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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxChunkSize    = 32768
	maxMessageBytes = 8 * 1024 * 1024
)

// UpgradeOptions configures server-side WebSocket handshake validation.
type UpgradeOptions struct {
	CheckOrigin func(r *http.Request) bool
}

// UpgradeError reports a non-101 HTTP response during a WebSocket client handshake.
type UpgradeError struct {
	StatusCode int
	StatusLine string
	Body       string
}

func (e *UpgradeError) Error() string {
	base := fmt.Sprintf("websocket upgrade failed: HTTP %d", e.StatusCode)
	if e.StatusLine != "" {
		base = fmt.Sprintf("websocket upgrade failed: %s", e.StatusLine)
	}
	if msg := strings.TrimSpace(e.Body); msg != "" {
		return base + ": " + msg
	}
	return base
}

// Conn implements net.Conn over an RFC 6455 WebSocket connection.
type Conn struct {
	raw      net.Conn
	r        *bufio.Reader
	isClient bool

	readM   sync.Mutex
	pending []byte

	writeM        sync.Mutex
	writeDeadline time.Time
	closed        bool
}

// UpgradeServer performs the server-side RFC 6455 WebSocket handshake.
func UpgradeServer(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	return UpgradeServerWithOptions(w, r, UpgradeOptions{})
}

// UpgradeServerWithOptions performs the server-side RFC 6455 WebSocket handshake with custom checks.
func UpgradeServerWithOptions(w http.ResponseWriter, r *http.Request, opts UpgradeOptions) (*Conn, error) {
	if opts.CheckOrigin != nil && !opts.CheckOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return nil, errors.New("forbidden websocket origin")
	}
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

func hasCRLFOrNul(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}

// DialClient connects via TCP/TLS and upgrades to an RFC 6455 WebSocket with Bearer auth and optional headers.
func DialClient(ctx context.Context, baseURL, pathWithQuery, token string, extraHeaders map[string]string) (*Conn, error) {
	if hasCRLFOrNul(pathWithQuery) || hasCRLFOrNul(token) {
		return nil, errors.New("websocket request contains invalid control characters")
	}

	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, errors.New("websocket URL host is required")
	}

	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		if scheme == "https" || scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	targetAddr := net.JoinHostPort(hostname, port)

	var headerBuf strings.Builder
	for k, v := range extraHeaders {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if hasCRLFOrNul(k) || hasCRLFOrNul(v) || strings.Contains(k, ":") {
			return nil, fmt.Errorf("invalid websocket header %q", k)
		}
		headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if scheme == "https" || scheme == "wss" {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", targetAddr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
	}
	if err != nil {
		return nil, err
	}

	handshakeDeadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	_ = conn.SetDeadline(handshakeDeadline)

	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()
	finishHandshakeWatch := func() {
		close(stopWatch)
		<-watchDone
	}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	wsKey := base64.StdEncoding.EncodeToString(keyRaw)

	h := sha1.New()
	_, _ = h.Write([]byte(wsKey + wsGUID))
	wantAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	basePath := strings.TrimRight(u.Path, "/")
	reqTarget := basePath + pathWithQuery
	if reqTarget == "" {
		reqTarget = "/"
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
		finishHandshakeWatch()
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		finishHandshakeWatch()
		_ = conn.Close()
		return nil, err
	}

	statusCode := 0
	if fields := strings.Fields(statusLine); len(fields) >= 2 && strings.HasPrefix(strings.ToUpper(fields[0]), "HTTP/") {
		statusCode, _ = strconv.Atoi(fields[1])
	}
	if statusCode != http.StatusSwitchingProtocols {
		var contentLen int
		for lineCount := 0; lineCount < 64; lineCount++ {
			line, hErr := br.ReadString('\n')
			if hErr != nil || line == "\r\n" || line == "\n" {
				break
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				k := strings.ToLower(strings.TrimSpace(line[:idx]))
				if k == "content-length" {
					contentLen, _ = strconv.Atoi(strings.TrimSpace(line[idx+1:]))
				}
			}
		}
		var body string
		if contentLen > 0 && contentLen <= 4096 {
			readN := contentLen
			if readN > 512 {
				readN = 512
			}
			buf := make([]byte, readN)
			if _, bErr := io.ReadFull(br, buf); bErr == nil {
				body = strings.Join(strings.Fields(string(buf)), " ")
			}
		}
		finishHandshakeWatch()
		_ = conn.Close()
		return nil, &UpgradeError{
			StatusCode: statusCode,
			StatusLine: strings.TrimSpace(statusLine),
			Body:       body,
		}
	}

	gotAccept := ""
	for lineCount := 0; lineCount < 256; lineCount++ {
		line, err := br.ReadString('\n')
		if err != nil {
			finishHandshakeWatch()
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
		if lineCount == 255 {
			finishHandshakeWatch()
			_ = conn.Close()
			return nil, errors.New("websocket upgrade response headers exceeded limit")
		}
	}
	if gotAccept == "" || gotAccept != wantAccept {
		finishHandshakeWatch()
		_ = conn.Close()
		return nil, errors.New("websocket Sec-WebSocket-Accept missing or mismatch")
	}

	finishHandshakeWatch()
	if ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})

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
	var fragOpcode byte
	var fragBuf []byte

	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
			return 0, nil, err
		}
		fin := (hdr[0] & 0x80) != 0
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

		if payloadLen > maxMessageBytes {
			return 0, nil, errors.New("websocket frame too large")
		}

		if !c.isClient && !masked {
			_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
			return 0, nil, errors.New("websocket client frame must be masked")
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

		if opcode >= 0x8 {
			if !fin || payloadLen > 125 {
				_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
				return 0, nil, errors.New("invalid websocket control frame")
			}
			switch opcode {
			case 0x8: // Close
				_ = c.writeControlFrame(0x8, nil)
				return opcode, payload, io.EOF
			case 0x9: // Ping
				_ = c.writeControlFrame(0xA, payload)
				continue
			case 0xA: // Pong
				continue
			default:
				_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
				return 0, nil, fmt.Errorf("unsupported websocket control opcode: 0x%x", opcode)
			}
		}

		if opcode == 0x0 {
			if fragOpcode == 0 {
				_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
				return 0, nil, errors.New("unexpected websocket continuation frame")
			}
			if uint64(len(fragBuf))+payloadLen > maxMessageBytes {
				return 0, nil, errors.New("websocket fragmented message too large")
			}
			fragBuf = append(fragBuf, payload...)
			if fin {
				return fragOpcode, fragBuf, nil
			}
			continue
		}

		if opcode != 0x1 && opcode != 0x2 {
			_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
			return 0, nil, fmt.Errorf("unsupported websocket opcode: 0x%x", opcode)
		}

		if fragOpcode != 0 {
			_ = c.writeControlFrame(0x8, []byte{0x03, 0xEA})
			return 0, nil, errors.New("unexpected non-continuation data frame during fragmented message")
		}

		if fin {
			return opcode, payload, nil
		}
		fragOpcode = opcode
		fragBuf = payload
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
	return c.writeFrameLocked(opcode, payload)
}

func (c *Conn) writeControlFrame(opcode byte, payload []byte) error {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	_ = c.raw.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err := c.writeFrameLocked(opcode, payload)
	_ = c.raw.SetWriteDeadline(c.writeDeadline)
	return err
}

func (c *Conn) writeFrameLocked(opcode byte, payload []byte) error {
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
		_ = c.raw.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_ = c.writeFrameLocked(0x8, nil)
		_ = c.raw.SetWriteDeadline(c.writeDeadline)
	}
	c.writeM.Unlock()
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr               { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr              { return c.raw.RemoteAddr() }
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetDeadline(t time.Time) error {
	c.writeM.Lock()
	c.writeDeadline = t
	c.writeM.Unlock()
	return c.raw.SetDeadline(t)
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeM.Lock()
	c.writeDeadline = t
	c.writeM.Unlock()
	return c.raw.SetWriteDeadline(t)
}
