package hub

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type WSConn struct {
	conn   net.Conn
	r      *bufio.Reader
	writeM sync.Mutex
	closed bool
}

func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
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

	return &WSConn{
		conn: conn,
		r:    rw.Reader,
	}, nil
}

func (ws *WSConn) ReadMessage() (byte, []byte, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(ws.r, hdr[:]); err != nil {
			return 0, nil, err
		}
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		if payloadLen == 126 {
			var ext [2]byte
			if _, err := io.ReadFull(ws.r, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
		} else if payloadLen == 127 {
			var ext [8]byte
			if _, err := io.ReadFull(ws.r, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = binary.BigEndian.Uint64(ext[:])
		}

		if payloadLen > 4*1024*1024 {
			return 0, nil, errors.New("websocket frame too large")
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(ws.r, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(ws.r, payload); err != nil {
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
			_ = ws.writeFrame(0x8, nil)
			return opcode, payload, io.EOF
		case 0x9: // Ping
			_ = ws.writeFrame(0xA, payload)
			continue
		case 0xA: // Pong
			continue
		default:
			return opcode, payload, nil
		}
	}
}

func (ws *WSConn) WriteText(s string) error {
	return ws.writeFrame(0x1, []byte(s))
}

func (ws *WSConn) WriteBinary(b []byte) error {
	return ws.writeFrame(0x2, b)
}

func (ws *WSConn) writeFrame(opcode byte, payload []byte) error {
	ws.writeM.Lock()
	defer ws.writeM.Unlock()
	if ws.closed {
		return errors.New("websocket closed")
	}

	n := len(payload)
	var header []byte
	if n < 126 {
		header = []byte{0x80 | opcode, byte(n)}
	} else if n <= 65535 {
		header = make([]byte, 4)
		header[0] = 0x80 | opcode
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	} else {
		header = make([]byte, 10)
		header[0] = 0x80 | opcode
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}

	if _, err := ws.conn.Write(header); err != nil {
		return err
	}
	if n > 0 {
		if _, err := ws.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (ws *WSConn) Close() error {
	ws.writeM.Lock()
	ws.closed = true
	ws.writeM.Unlock()
	return ws.conn.Close()
}
