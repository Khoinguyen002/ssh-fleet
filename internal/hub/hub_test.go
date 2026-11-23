package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-fleet/internal/agent"
	"ssh-fleet/internal/power"
	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/wol"
)

type fakePowerExec struct {
	mu          sync.Mutex
	softSlept   bool
	woke        bool
	hardSlept   bool
	hardSleepCh chan struct{}
}

func (f *fakePowerExec) StartInhibitor() (*exec.Cmd, error) { return nil, nil }

func (f *fakePowerExec) SoftSleep() error {
	f.mu.Lock()
	f.softSlept = true
	f.mu.Unlock()
	return nil
}

func (f *fakePowerExec) WakeDisplay() error {
	f.mu.Lock()
	f.woke = true
	f.mu.Unlock()
	return nil
}

func (f *fakePowerExec) HardSleep() error {
	f.mu.Lock()
	f.hardSlept = true
	ch := f.hardSleepCh
	f.mu.Unlock()
	if ch != nil {
		close(ch)
	}
	return nil
}

func TestHubEndToEndProxyPowerWoLAndVaultSync(t *testing.T) {
	tmp := t.TempDir()
	const token = "test-hub-secret-token"

	srv, err := NewServer(token, tmp)
	if err != nil {
		t.Fatalf("NewServer error: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	var cancelLaptop, cancelRelay context.CancelFunc
	defer func() {
		if cancelRelay != nil {
			cancelRelay()
		}
		if cancelLaptop != nil {
			cancelLaptop()
		}
		_ = srv.Close()
		ts.Close()
		time.Sleep(80 * time.Millisecond)
	}()

	// 1. Start mock local SSHD echo server on ephemeral port.
	sshdLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock sshd: %v", err)
	}
	defer sshdLn.Close()
	sshdPort := sshdLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := sshdLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("SSH-2.0-MockSSHD\r\n"))
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Connect laptop-1 and home-pc-relay on the same simulated LAN subnet 192.168.10.0/24.
	laptopExec := &fakePowerExec{hardSleepCh: make(chan struct{})}
	laptopPower := power.NewManager(laptopExec)
	laptopAgent, err := agent.NewClient(agent.Options{
		HubURL:  ts.URL,
		Token:   token,
		NodeID:  "laptop-1",
		Name:    "laptop-1",
		SSHPort: sshdPort,
		SSHUser: "khoi",
		Power:   laptopPower,
		NetworkInfoFn: func() ([]wol.NetInterfaceInfo, error) {
			return []wol.NetInterfaceInfo{
				{
					Name:        "wlan0",
					MAC:         "aa:bb:cc:dd:ee:01",
					IPv4:        "192.168.10.21",
					SubnetCIDR:  "192.168.10.0/24",
					BroadcastIP: "192.168.10.255",
				},
			}, nil
		},
		PingInterval:   5 * time.Second,
		ReconnectDelay: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient laptopAgent: %v", err)
	}

	var laptopCtx context.Context
	laptopCtx, cancelLaptop = context.WithCancel(context.Background())
	go func() { _ = laptopAgent.Run(laptopCtx) }()

	var wolMu sync.Mutex
	var wolReceived []string
	relayAgent, err := agent.NewClient(agent.Options{
		HubURL:  ts.URL,
		Token:   token,
		NodeID:  "home-pc-relay",
		Name:    "home-pc-relay",
		SSHPort: 22,
		SSHUser: "relay",
		WoLHandler: func(mac, broadcastIP string) error {
			wolMu.Lock()
			wolReceived = append(wolReceived, fmt.Sprintf("%s@%s", mac, broadcastIP))
			wolMu.Unlock()
			return nil
		},
		NetworkInfoFn: func() ([]wol.NetInterfaceInfo, error) {
			return []wol.NetInterfaceInfo{
				{
					Name:        "eth0",
					MAC:         "aa:bb:cc:dd:ee:02",
					IPv4:        "192.168.10.10",
					SubnetCIDR:  "192.168.10.0/24",
					BroadcastIP: "192.168.10.255",
				},
			}, nil
		},
		PingInterval:   5 * time.Second,
		ReconnectDelay: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient relayAgent: %v", err)
	}
	var relayCtx context.Context
	relayCtx, cancelRelay = context.WithCancel(context.Background())
	go func() { _ = relayAgent.Run(relayCtx) }()

	// Wait for both agents to register on Hub.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		nodes := srv.ListNodes()
		onlineCount := 0
		for _, n := range nodes {
			if n.Online {
				onlineCount++
			}
		}
		if onlineCount == 2 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if len(srv.ListNodes()) != 2 {
		t.Fatalf("expected 2 registered nodes, got %d", len(srv.ListNodes()))
	}

	// 3. Test NAT-traversal proxy stream Client -> Hub -> laptop-1 -> MockSSHD.
	proxyConn, br, err := agent.DialUpgrade(context.Background(), ts.URL, "/tunnel/client-proxy?node_id=laptop-1", token, "ssh-fleet-proxy")
	if err != nil {
		t.Fatalf("DialUpgrade proxy error: %v", err)
	}
	banner, err := br.ReadString('\n')
	if err != nil || banner != "SSH-2.0-MockSSHD\r\n" {
		t.Fatalf("unexpected SSH banner via proxy: %q (err=%v)", banner, err)
	}
	if _, err := proxyConn.Write([]byte("hello-over-nat-tunnel\n")); err != nil {
		t.Fatalf("write to proxy: %v", err)
	}
	echo, err := br.ReadString('\n')
	if err != nil || echo != "hello-over-nat-tunnel\n" {
		t.Fatalf("unexpected echo via proxy: %q (err=%v)", echo, err)
	}
	_ = proxyConn.Close()

	// 4. Test Keep-Awake, Soft-Sleep, and Direct Soft-Wake.
	postPower := func(nodeID string, payload protocol.PowerRequest) protocol.PowerResponse {
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/"+nodeID+"/power", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("postPower error: %v", err)
		}
		defer resp.Body.Close()
		var out protocol.PowerResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	kaRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionKeepAwakeOn})
	if !kaRes.OK || kaRes.PowerState != protocol.PowerKeepAwake {
		t.Fatalf("keep-awake-on failed: %+v", kaRes)
	}

	ssRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionSoftSleep})
	if !ssRes.OK || ssRes.PowerState != protocol.PowerSoftSleep {
		t.Fatalf("soft-sleep failed: %+v", ssRes)
	}

	wakeRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionWake})
	if !wakeRes.OK || wakeRes.Method != "direct-soft-wake" {
		t.Fatalf("direct soft wake failed: %+v", wakeRes)
	}

	// 5. Simulate Hard-Sleep (suspend S3) and disconnect laptop-1, then wake via LAN Relay WoL.
	hsRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionHardSleep})
	if !hsRes.OK {
		t.Fatalf("hard-sleep failed: %+v", hsRes)
	}
	select {
	case <-laptopExec.hardSleepCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("laptop HardSleep executor was not invoked")
	}

	cancelLaptop()
	// Wait until Hub sees laptop-1 offline.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var laptopOnline = true
		for _, n := range srv.ListNodes() {
			if n.NodeID == "laptop-1" {
				laptopOnline = n.Online
			}
		}
		if !laptopOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	wolWakeRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionWake})
	if !wolWakeRes.OK || wolWakeRes.Method != "wol-lan-relay" {
		t.Fatalf("expected wol-lan-relay wake response, got %+v", wolWakeRes)
	}
	if len(wolWakeRes.Relays) != 1 || wolWakeRes.Relays[0] != "home-pc-relay" {
		t.Fatalf("expected home-pc-relay to dispatch WoL, got %+v", wolWakeRes.Relays)
	}
	wolMu.Lock()
	if len(wolReceived) != 1 || wolReceived[0] != "aa:bb:cc:dd:ee:01@192.168.10.255" {
		t.Fatalf("unexpected WoL packet dispatched on relay: %v", wolReceived)
	}
	wolMu.Unlock()

	// 6. Test encrypted Vault blob PUT and GET on Hub.
	vaultBlob := []byte(`{"magic":"SFV1","ciphertext":"opaque-e2ee-data"}`)
	putReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/vault", bytes.NewReader(vaultBlob))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil || putResp.StatusCode != http.StatusOK {
		t.Fatalf("vault PUT failed: err=%v resp=%v", err, putResp)
	}
	_ = putResp.Body.Close()

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/vault", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil || getResp.StatusCode != http.StatusOK {
		t.Fatalf("vault GET failed: err=%v resp=%v", err, getResp)
	}
	gotBlob, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if !bytes.Equal(gotBlob, vaultBlob) {
		t.Fatalf("vault blob mismatch: got %q, want %q", gotBlob, vaultBlob)
	}
}

func TestCloudflareAccessAuthAndWebSocketTerminal(t *testing.T) {
	tmp := t.TempDir()
	srv, err := NewServerWithOptions(Options{
		Token:         "hub-tok",
		DataDir:       tmp,
		TrustCFAccess: true,
		CFAccessEmail: "Khoi@example.com, admin@example.com",
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(80 * time.Millisecond)
	}()

	// 1. Unauthorized without CF Access email or Bearer token
	req0, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/status", nil)
	resp0, err := http.DefaultClient.Do(req0)
	if err != nil {
		t.Fatalf("auth status err: %v", err)
	}
	var st0 struct {
		Authenticated bool `json:"authenticated"`
	}
	_ = json.NewDecoder(resp0.Body).Decode(&st0)
	_ = resp0.Body.Close()
	if st0.Authenticated {
		t.Fatalf("expected unauthenticated without header")
	}

	// 2. Denied for unlisted CF Access email
	reqDeny, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/nodes", nil)
	reqDeny.Header.Set("Cf-Access-Authenticated-User-Email", "stranger@example.com")
	respDeny, err := http.DefaultClient.Do(reqDeny)
	if err != nil {
		t.Fatalf("reqDeny err: %v", err)
	}
	_ = respDeny.Body.Close()
	if respDeny.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unlisted email, got %d", respDeny.StatusCode)
	}

	// 3. Allowed for matching CF Access email (case-insensitive)
	reqAllow, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/status", nil)
	reqAllow.Header.Set("Cf-Access-Authenticated-User-Email", "khoi@example.com")
	respAllow, err := http.DefaultClient.Do(reqAllow)
	if err != nil {
		t.Fatalf("reqAllow err: %v", err)
	}
	var stAllow struct {
		Authenticated bool   `json:"authenticated"`
		CFEmail       string `json:"cf_email"`
	}
	_ = json.NewDecoder(respAllow.Body).Decode(&stAllow)
	_ = respAllow.Body.Close()
	if !stAllow.Authenticated || stAllow.CFEmail != "khoi@example.com" {
		t.Fatalf("expected CF Access authenticated as khoi@example.com, got %+v", stAllow)
	}

	// 4. Web UI index served at "/"
	webResp, err := http.Get(ts.URL + "/")
	if err != nil || webResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / failed: err=%v resp=%v", err, webResp)
	}
	webBytes, _ := io.ReadAll(webResp.Body)
	_ = webResp.Body.Close()
	if !strings.Contains(string(webBytes), "SSH Fleet") {
		t.Fatalf("unexpected Web UI HTML")
	}

	// 5. Connect an agent and test WebSocket interactive agent shell stream via CF Access header
	ag, err := agent.NewClient(agent.Options{
		HubURL:       ts.URL,
		Token:        "hub-tok",
		NodeID:       "ws-test-node",
		Name:         "ws-test-node",
		PingInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(60 * time.Millisecond)
	}()
	go func() { _ = ag.Run(ctx) }()

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		nodes := srv.ListNodes()
		if len(nodes) == 1 && nodes[0].Online {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	u, _ := url.Parse(ts.URL)
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatalf("dial ws tcp: %v", err)
	}
	defer conn.Close()

	wsReq := fmt.Sprintf(
		"GET /api/v1/ws/terminal?mode=agent&node_id=ws-test-node HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCf-Access-Authenticated-User-Email: khoi@example.com\r\n\r\n",
		u.Host,
	)
	if _, err := conn.Write([]byte(wsReq)); err != nil {
		t.Fatalf("write ws upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 websocket upgrade, got %q (err=%v)", statusLine, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read ws header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Send masked client text frame: "echo WS_OK\nexit\n"
	cmdBytes := []byte("echo WS_OK\nexit\n")
	frame := []byte{0x81, 0x80 | byte(len(cmdBytes)), 0x11, 0x22, 0x33, 0x44}
	for i, b := range cmdBytes {
		frame = append(frame, b^frame[2+(i%4)])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var collected strings.Builder
	for i := 0; i < 30; i++ {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			break
		}
		plen := int(hdr[1] & 0x7F)
		if plen == 126 {
			var ext [2]byte
			_, _ = io.ReadFull(br, ext[:])
			plen = int(binary.BigEndian.Uint16(ext[:]))
		}
		buf := make([]byte, plen)
		_, err := io.ReadFull(br, buf)
		if err != nil {
			break
		}
		collected.Write(buf)
		if strings.Contains(collected.String(), "WS_OK") {
			break
		}
	}
	if !strings.Contains(collected.String(), "WS_OK") {
		t.Fatalf("expected WS_OK in terminal output, got: %q", collected.String())
	}
}
