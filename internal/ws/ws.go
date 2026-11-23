package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxChunkSize = 32768
)

// Conn implements net.Conn over an RFC 6455 WebSocket connection.
type Conn struct {
	raw      net.Conn
	r        *bufio.Reader
	isClient bool

	readM   sync.Mutex
	pending []byte

	writeM sync.Mutex
	closed bool
}

// UpgradeServer performs the server-side RFC 6455 WebSocket handshake.
func UpgradeServer(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return nil, errors.New("not a websocket upgrade request")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("missing websocket key")
	}

	h := sha1.New()
	_, _ = h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, errors.New("hijacker unavailable")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &Conn{
		raw:      conn,
		r:        rw.Reader,
		isClient: false,
	}, nil
}

// DialClient connects via TCP/TLS and upgrades to an RFC 6455 WebSocket with Bearer auth and optional headers.
func DialClient(ctx context.Context, baseURL, pathWithQuery, token string, extraHeaders map[string]string) (*Conn, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}

	scheme := strings.ToLower(u.Scheme)
	host := u.Host
	if !strings.Contains(host, ":") {
		if scheme == "https" || scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if scheme == "https" || scheme == "wss" {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: u.Hostname()},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", host)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	wsKey := base64.StdEncoding.EncodeToString(keyRaw)

	h := sha1.New()
	_, _ = h.Write([]byte(wsKey + wsGUID))
	wantAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	basePath := strings.TrimRight(u.Path, "/")
	reqTarget := basePath + pathWithQuery

	var headerBuf strings.Builder
	for k, v := range extraHeaders {
		if strings.TrimSpace(v) != "" {
			headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	reqStr := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer %s\r\n%s\r\n",
		reqTarget,
		u.Host,
		wsKey,
		token,
		headerBuf.String(),
	)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %s", strings.TrimSpace(statusLine))
	}

	gotAccept := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			if k == "sec-websocket-accept" {
				gotAccept = strings.TrimSpace(line[idx+1:])
			}
		}
	}
	if gotAccept != "" && gotAccept != wantAccept {
		_ = conn.Close()
		return nil, errors.New("websocket Sec-WebSocket-Accept mismatch")
	}

	return &Conn{
		raw:      conn,
		r:        br,
		isClient: true,
	}, nil
}

func (c *Conn) ReadMessage() (byte, []byte, error) {
	c.readM.Lock()
	defer c.readM.Unlock()
	return c.readMessageLocked()
}

func (c *Conn) readMessageLocked() (byte, []byte, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
			return 0, nil, err
		}
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		if payloadLen == 126 {
			var ext [2]byte
			if _, err := io.ReadFull(c.r, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
		} else if payloadLen == 127 {
			var ext [8]byte
			if _, err := io.ReadFull(c.r, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = binary.BigEndian.Uint64(ext[:])
		}

		if payloadLen > 8*1024*1024 {
			return 0, nil, errors.New("websocket frame too large")
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.r, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(c.r, payload); err != nil {
				return 0, nil, err
			}
			if masked {
				for i := range payload {
					payload[i] ^= maskKey[i%4]
				}
			}
		}

		switch opcode {
		case 0x8: // Close
			_ = c.writeFrame(0x8, nil)
			return opcode, payload, io.EOF
		case 0x9: // Ping
			_ = c.writeFrame(0xA, payload)
			continue
		case 0xA: // Pong
			continue
		default:
			return opcode, payload, nil
		}
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readM.Lock()
	defer c.readM.Unlock()

	for len(c.pending) == 0 {
		op, payload, err := c.readMessageLocked()
		if err != nil {
			return 0, err
		}
		if op == 0x1 || op == 0x2 || op == 0x0 {
			c.pending = payload
		}
	}

	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunkSize {
			chunk = p[:maxChunkSize]
		}
		if err := c.WriteBinary(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Conn) WriteText(s string) error {
	return c.writeFrame(0x1, []byte(s))
}

func (c *Conn) WriteBinary(b []byte) error {
	return c.writeFrame(0x2, b)
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if c.closed {
		return net.ErrClosed
	}

	n := len(payload)
	var maskBit byte
	if c.isClient {
		maskBit = 0x80
	}

	var header []byte
	if n < 126 {
		header = []byte{0x80 | opcode, maskBit | byte(n)}
	} else if n <= 65535 {
		header = make([]byte, 4)
		header[0] = 0x80 | opcode
		header[1] = maskBit | 126
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	} else {
		header = make([]byte, 10)
		header[0] = 0x80 | opcode
		header[1] = maskBit | 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}

	if c.isClient {
		var maskKey [4]byte
		_, _ = rand.Read(maskKey[:])
		header = append(header, maskKey[:]...)
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		if _, err := c.raw.Write(header); err != nil {
			return err
		}
		if n > 0 {
			if _, err := c.raw.Write(masked); err != nil {
				return err
			}
		}
		return nil
	}

	if _, err := c.raw.Write(header); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.raw.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) Close() error {
	c.writeM.Lock()
	if !c.closed {
		c.closed = true
	}
	c.writeM.Unlock()
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
