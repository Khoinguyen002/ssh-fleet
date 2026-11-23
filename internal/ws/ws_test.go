package ws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func buildRawFrame(fin bool, opcode byte, masked bool, payload []byte) []byte {
	var b0 byte = opcode & 0x0F
	if fin {
		b0 |= 0x80
	}
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	n := len(payload)
	var out []byte
	if n < 126 {
		out = []byte{b0, maskBit | byte(n)}
	} else {
		out = []byte{b0, maskBit | 126, byte(n >> 8), byte(n)}
	}
	if masked {
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		out = append(out, mask[:]...)
		for i, v := range payload {
			out = append(out, v^mask[i%4])
		}
	} else {
		out = append(out, payload...)
	}
	return out
}

func TestReadMessageFragmentedWithInterleavedPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := UpgradeServer(w, r)
		if err != nil {
			t.Errorf("UpgradeServer: %v", err)
			return
		}
		defer conn.Close()

		// Read fragmented message sent by client.
		op, msg, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("ReadMessage: %v", err)
			return
		}
		if op != 0x1 || string(msg) != "hello fragmented world" {
			t.Errorf("got op=%d msg=%q", op, msg)
			return
		}

		// Send fragmented message from server back with interleaved Ping mid-stream.
		_, _ = conn.raw.Write(buildRawFrame(false, 0x1, false, []byte("part1-")))
		_, _ = conn.raw.Write(buildRawFrame(true, 0x9, false, []byte("ping1")))
		_, _ = conn.raw.Write(buildRawFrame(true, 0x0, false, []byte("part2")))

		// Server must receive client's auto-Pong.
		var hdr [2]byte
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn.r, hdr[:]); err != nil {
			t.Errorf("read pong hdr: %v", err)
			return
		}
		if hdr[0]&0x0F != 0xA {
			t.Errorf("expected pong opcode 0xA, got 0x%x", hdr[0]&0x0F)
			return
		}
		plen := int(hdr[1] & 0x7F)
		var mask [4]byte
		_, _ = io.ReadFull(conn.r, mask[:])
		pongBody := make([]byte, plen)
		_, _ = io.ReadFull(conn.r, pongBody)
		for i := range pongBody {
			pongBody[i] ^= mask[i%4]
		}
		if string(pongBody) != "ping1" {
			t.Errorf("expected pong body ping1, got %q", pongBody)
		}
	}))
	defer srv.Close()

	client, err := DialClient(context.Background(), srv.URL, "/", "tok", nil)
	if err != nil {
		t.Fatalf("DialClient: %v", err)
	}
	defer client.Close()

	// Send masked fragmented frames from client + interleaved Ping.
	_, _ = client.raw.Write(buildRawFrame(false, 0x1, true, []byte("hello ")))
	_, _ = client.raw.Write(buildRawFrame(true, 0x9, true, []byte("hb")))
	_, _ = client.raw.Write(buildRawFrame(false, 0x0, true, []byte("fragmented ")))
	_, _ = client.raw.Write(buildRawFrame(true, 0x0, true, []byte("world")))

	// Note: client receives server's Pong response to "hb" (ignored by ReadMessage),
	// then reassembled "part1-part2" while auto-ponging "ping1".
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	op, got, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("client ReadMessage: %v", err)
	}
	if op != 0x1 || string(got) != "part1-part2" {
		t.Fatalf("expected reassembled 'part1-part2', got op=%d msg=%q", op, got)
	}
}

func TestServerRejectsUnmaskedClientFrame(t *testing.T) {
	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := UpgradeServer(w, r)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_, _, rErr := conn.ReadMessage()
		errCh <- rErr
	}))
	defer srv.Close()

	client, err := DialClient(context.Background(), srv.URL, "/", "tok", nil)
	if err != nil {
		t.Fatalf("DialClient: %v", err)
	}
	defer client.Close()

	// Write unmasked frame directly to raw socket.
	_, _ = client.raw.Write(buildRawFrame(true, 0x1, false, []byte("unmasked")))

	select {
	case rErr := <-errCh:
		if rErr == nil || !strings.Contains(rErr.Error(), "masked") {
			t.Fatalf("expected masking error, got %v", rErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for server to reject unmasked frame")
	}
}

func TestDialClientSecurityAndEdgeCases(t *testing.T) {
	// 1. Reject CRLF injection in token, path, and extra headers.
	if _, err := DialClient(context.Background(), "http://127.0.0.1:1", "/ok", "bad\r\nX-Inject: 1", nil); err == nil {
		t.Fatalf("expected error for CRLF in token")
	}
	if _, err := DialClient(context.Background(), "http://127.0.0.1:1", "/bad\nHost: evil", "tok", nil); err == nil {
		t.Fatalf("expected error for LF in path")
	}
	if _, err := DialClient(context.Background(), "http://127.0.0.1:1", "/ok", "tok", map[string]string{"X-Test": "a\rb"}); err == nil {
		t.Fatalf("expected error for CR in header value")
	}
	if _, err := DialClient(context.Background(), "http://127.0.0.1:1", "/ok", "tok", map[string]string{"Bad:Key": "val"}); err == nil {
		t.Fatalf("expected error for colon in header key")
	}

	// 2. HTTP 401 returns *UpgradeError with StatusCode == 401 and HTTP 502 surfaces error body.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer authSrv.Close()

	_, err := DialClient(context.Background(), authSrv.URL, "/", "bad-tok", nil)
	var upErr *UpgradeError
	if !errors.As(err, &upErr) || upErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected *UpgradeError 401, got %T: %v", err, err)
	}

	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "local ssh port 22 unreachable", http.StatusBadGateway)
	}))
	defer gwSrv.Close()

	_, err = DialClient(context.Background(), gwSrv.URL, "/", "tok", nil)
	var gwErr *UpgradeError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected *UpgradeError 502, got %T: %v", err, err)
	}
	if !strings.Contains(gwErr.Body, "local ssh port 22 unreachable") {
		t.Fatalf("expected UpgradeError.Body to contain error reason, got %q", gwErr.Body)
	}
	if !strings.Contains(gwErr.Error(), "local ssh port 22 unreachable") {
		t.Fatalf("expected UpgradeError.Error() to contain error reason, got %q", gwErr.Error())
	}

	// 3. Reject missing or mismatched Sec-WebSocket-Accept.
	for _, mode := range []string{"missing", "mismatch"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func(m string) {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				line, rErr := br.ReadString('\n')
				if rErr != nil || line == "\r\n" {
					break
				}
			}
			resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
			if m == "mismatch" {
				h := sha1.Sum([]byte("wrong-accept"))
				resp += "Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(h[:]) + "\r\n"
			}
			resp += "\r\n"
			_, _ = c.Write([]byte(resp))
		}(mode)

		_, dErr := DialClient(context.Background(), "http://"+ln.Addr().String(), "/", "tok", nil)
		_ = ln.Close()
		if dErr == nil || !strings.Contains(dErr.Error(), "Sec-WebSocket-Accept") {
			t.Fatalf("mode %s: expected Sec-WebSocket-Accept error, got %v", mode, dErr)
		}
	}

	// 4. Handshake timeout when server stalls HTTP upgrade headers.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stall: %v", err)
	}
	defer stallLn.Close()
	stallDone := make(chan struct{})
	go func() {
		defer close(stallDone)
		c, aErr := stallLn.Accept()
		if aErr != nil {
			return
		}
		defer c.Close()
		time.Sleep(300 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = DialClient(ctx, "http://"+stallLn.Addr().String(), "/", "tok", nil)
	if err == nil {
		t.Fatalf("expected handshake timeout error")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("handshake timeout took too long: %v", time.Since(start))
	}
	<-stallDone

	// 5. IPv6 loopback host support if IPv6 loopback is available on host.
	if ln6, lErr := net.Listen("tcp6", "[::1]:0"); lErr == nil {
		srv6 := &httptest.Server{
			Listener: ln6,
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c, uErr := UpgradeServer(w, r)
					if uErr != nil {
						return
					}
					defer c.Close()
					_ = c.WriteText("v6-ok")
				}),
			},
		}
		srv6.Start()
		defer srv6.Close()

		c6, dErr := DialClient(context.Background(), srv6.URL, "/", "tok", nil)
		if dErr != nil {
			t.Fatalf("DialClient IPv6 %s failed: %v", srv6.URL, dErr)
		}
		op, payload, rErr := c6.ReadMessage()
		_ = c6.Close()
		if rErr != nil || op != 0x1 || string(payload) != "v6-ok" {
			t.Fatalf("unexpected IPv6 ReadMessage: op=%d payload=%q err=%v", op, payload, rErr)
		}
	}
}

func TestUpgradeServerCheckOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := UpgradeServerWithOptions(w, r, UpgradeOptions{
			CheckOrigin: func(req *http.Request) bool {
				origin := req.Header.Get("Origin")
				return origin == "" || origin == "https://allowed.example"
			},
		})
		if err != nil {
			return
		}
		_ = conn.WriteText("ok")
		_ = conn.Close()
	}))
	defer srv.Close()

	_, err := DialClient(context.Background(), srv.URL, "/", "tok", map[string]string{
		"Origin": "https://evil.example",
	})
	var upErr *UpgradeError
	if !errors.As(err, &upErr) || upErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden origin, got %T: %v", err, err)
	}

	var buf bytes.Buffer
	_ = buf
	conn, err := DialClient(context.Background(), srv.URL, "/", "tok", map[string]string{
		"Origin": "https://allowed.example",
	})
	if err != nil {
		t.Fatalf("expected allowed origin to succeed, got %v", err)
	}
	op, payload, rErr := conn.ReadMessage()
	_ = conn.Close()
	if rErr != nil || op != 0x1 || string(payload) != "ok" {
		t.Fatalf("unexpected msg: op=%d payload=%q err=%v", op, payload, rErr)
	}
}
