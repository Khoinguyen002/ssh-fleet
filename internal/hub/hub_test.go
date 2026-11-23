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
	"ssh-fleet/internal/ws"
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

	// Unbound offline laptop must refuse wake until manually bound to MAC + ESP32 Wake Relay.
	unboundRes := postPower("laptop-1", protocol.PowerRequest{Action: protocol.ActionWake})
	if unboundRes.OK {
		t.Fatalf("expected wake to fail when WoL is not bound, got %+v", unboundRes)
	}

	// Binding to a Peer PC instead of a registered ESP32 Wake Relay must be rejected (404).
	bindPeerPayload := []byte(`{"wol":{"mac":"aa:bb:cc:dd:ee:01","broadcast_ip":"192.168.10.255","port":9,"wake_relay_id":"home-pc-relay"}}`)
	bindPeerReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/nodes/laptop-1/wol", bytes.NewReader(bindPeerPayload))
	bindPeerReq.Header.Set("Authorization", "Bearer "+token)
	bindPeerResp, err := http.DefaultClient.Do(bindPeerReq)
	if err != nil {
		t.Fatalf("PATCH wol bind err: %v", err)
	}
	_ = bindPeerResp.Body.Close()
	if bindPeerResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 rejecting peer PC as wake relay, got %d", bindPeerResp.StatusCode)
	}

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

	// 3b. Verify /api/v1/hub-info rejects unauthenticated and returns redacted + full token when authenticated
	infoUnauth, err := http.Get(ts.URL + "/api/v1/hub-info")
	if err != nil || infoUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauth /api/v1/hub-info, got err=%v resp=%v", err, infoUnauth)
	}
	_ = infoUnauth.Body.Close()

	reqInfo, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/hub-info", nil)
	reqInfo.Header.Set("Cf-Access-Authenticated-User-Email", "khoi@example.com")
	respInfo, err := http.DefaultClient.Do(reqInfo)
	if err != nil || respInfo.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/hub-info failed: err=%v resp=%v", err, respInfo)
	}
	var hubInfo struct {
		OK               bool   `json:"ok"`
		HubToken         string `json:"hub_token"`
		HubTokenRedacted string `json:"hub_token_redacted"`
		JoinTokenTTLSec  int    `json:"join_token_ttl_sec"`
	}
	_ = json.NewDecoder(respInfo.Body).Decode(&hubInfo)
	_ = respInfo.Body.Close()
	if !hubInfo.OK || hubInfo.HubToken != "" || hubInfo.HubTokenRedacted == "" || hubInfo.JoinTokenTTLSec != 300 {
		t.Fatalf("unexpected /api/v1/hub-info payload (must not expose hub_token): %+v", hubInfo)
	}

	// 3c. Mint a 5-min one-time join token, exchange once -> succeeds, replay -> 401
	jtReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/join-tokens", nil)
	jtReq.Header.Set("Cf-Access-Authenticated-User-Email", "khoi@example.com")
	jtResp, err := http.DefaultClient.Do(jtReq)
	if err != nil || jtResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/join-tokens failed: err=%v resp=%v", err, jtResp)
	}
	var jtOut struct {
		OK        bool   `json:"ok"`
		JoinToken string `json:"join_token"`
		TTLSec    int    `json:"ttl_sec"`
	}
	_ = json.NewDecoder(jtResp.Body).Decode(&jtOut)
	_ = jtResp.Body.Close()
	if !jtOut.OK || !strings.HasPrefix(jtOut.JoinToken, "sfj_") || jtOut.TTLSec != 300 {
		t.Fatalf("unexpected join token: %+v", jtOut)
	}

	exPayload, _ := json.Marshal(map[string]string{"join_token": jtOut.JoinToken, "node_id": "enrolled-laptop"})
	exResp, err := http.Post(ts.URL+"/api/v1/join/exchange", "application/json", bytes.NewReader(exPayload))
	if err != nil || exResp.StatusCode != http.StatusOK {
		t.Fatalf("exchange join token failed: err=%v resp=%v", err, exResp)
	}
	var exOut struct {
		OK        bool   `json:"ok"`
		NodeToken string `json:"node_token"`
	}
	_ = json.NewDecoder(exResp.Body).Decode(&exOut)
	_ = exResp.Body.Close()
	if !exOut.OK || !strings.HasPrefix(exOut.NodeToken, "sfn_enrolled-laptop.") {
		t.Fatalf("unexpected node_token: %+v", exOut)
	}

	// Replay same one-time join token must fail with 401
	exResp2, _ := http.Post(ts.URL+"/api/v1/join/exchange", "application/json", bytes.NewReader(exPayload))
	_ = exResp2.Body.Close()
	if exResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on replayed join token, got %d", exResp2.StatusCode)
	}

	// Verify expired join token is rejected
	expTok, _ := srv.joinTokens.Create(1 * time.Millisecond)
	time.Sleep(15 * time.Millisecond)
	if srv.joinTokens.Consume(expTok) {
		t.Fatalf("expected expired join token to be rejected")
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

func TestVPSSleepProtectionAndESP32WakeRelay(t *testing.T) {
	tmp := t.TempDir()
	const token = "vps-esp32-token"

	srv, err := NewServer(token, tmp)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(60 * time.Millisecond)
	}()

	// 1. Register a VPS node (IsVPS=true) and verify soft-sleep and hard-sleep are blocked.
	isVPS := true
	vpsAgent, err := agent.NewClient(agent.Options{
		HubURL:       ts.URL,
		Token:        token,
		NodeID:       "prod-vps-1",
		Name:         "prod-vps-1",
		IsVPS:        &isVPS,
		PingInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient vpsAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(40 * time.Millisecond)
	}()
	go func() { _ = vpsAgent.Run(ctx) }()

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.ListNodes()) == 1 && srv.ListNodes()[0].Online {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	for _, act := range []protocol.PowerAction{protocol.ActionSoftSleep, protocol.ActionHardSleep} {
		b, _ := json.Marshal(protocol.PowerRequest{Action: act})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/prod-vps-1/power", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post %s err: %v", act, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 refusing %s on VPS, got %d", act, resp.StatusCode)
		}
	}

	// 2. Register an ESP32 wake relay via POST /api/v1/wake-relays and verify status tracking.
	createRelayReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/wake-relays", bytes.NewReader([]byte(`{"name":"Home ESP32"}`)))
	createRelayReq.Header.Set("Authorization", "Bearer "+token)
	createRelayResp, err := http.DefaultClient.Do(createRelayReq)
	if err != nil || createRelayResp.StatusCode != http.StatusCreated {
		t.Fatalf("create wake relay failed: err=%v resp=%v", err, createRelayResp)
	}
	var createdRelay struct {
		OK    bool                        `json:"ok"`
		Relay protocol.WakeRelaySummary `json:"relay"`
		Token string                      `json:"token"`
	}
	_ = json.NewDecoder(createRelayResp.Body).Decode(&createdRelay)
	_ = createRelayResp.Body.Close()
	if !createdRelay.OK || createdRelay.Relay.ID != "home-esp32" || createdRelay.Relay.Online || !strings.HasPrefix(createdRelay.Token, "home-esp32.") {
		t.Fatalf("unexpected created relay: %+v", createdRelay)
	}

	// Connect ESP32 using its dedicated <id>.<secret> token.
	espConn, err := ws.DialClient(context.Background(), ts.URL, "/hub/ws/wake", createdRelay.Token, nil)
	if err != nil {
		t.Fatalf("DialClient /hub/ws/wake: %v", err)
	}
	defer espConn.Close()

	_ = espConn.WriteText(`{"t":"hello","firmwareVersion":"1.0.0"}`)
	_, ackRaw, err := espConn.ReadMessage()
	if err != nil || !strings.Contains(string(ackRaw), `"home-esp32"`) {
		t.Fatalf("expected hello-ack with home-esp32 from /hub/ws/wake, got %q (err=%v)", ackRaw, err)
	}

	// Check GET /api/v1/wake-relays shows online=true and firmware_version=1.0.0.
	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/wake-relays", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil || listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/wake-relays failed: err=%v resp=%v", err, listResp)
	}
	var listOut struct {
		WakeRelays []protocol.WakeRelaySummary `json:"wake_relays"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&listOut)
	_ = listResp.Body.Close()
	if len(listOut.WakeRelays) != 1 || !listOut.WakeRelays[0].Online || listOut.WakeRelays[0].FirmwareVersion != "1.0.0" {
		t.Fatalf("expected home-esp32 online with fw 1.0.0, got %+v", listOut.WakeRelays)
	}

	espWakeReceived := make(chan string, 1)
	go func() {
		for {
			_, raw, err := espConn.ReadMessage()
			if err != nil {
				return
			}
			var msg struct {
				T         string `json:"t"`
				RequestID string `json:"requestId"`
				MAC       string `json:"mac"`
			}
			if json.Unmarshal(raw, &msg) == nil && msg.T == "wake" {
				espWakeReceived <- msg.MAC
				resp, _ := json.Marshal(map[string]any{
					"t":         "wake-ack",
					"requestId": msg.RequestID,
					"ok":        true,
				})
				_ = espConn.WriteText(string(resp))
			}
		}
	}()

	// Register a non-VPS home-pc, disconnect it, and test manual WoL binding requirement.
	notVPS := false
	pcAgent, _ := agent.NewClient(agent.Options{
		HubURL:       ts.URL,
		Token:        token,
		NodeID:       "home-pc",
		Name:         "home-pc",
		IsVPS:        &notVPS,
		PingInterval: 5 * time.Second,
	})
	pcCtx, pcCancel := context.WithCancel(context.Background())
	go func() { _ = pcAgent.Run(pcCtx) }()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		foundOnline := false
		for _, n := range srv.ListNodes() {
			if n.NodeID == "home-pc" && n.Online {
				foundOnline = true
			}
		}
		if foundOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	pcCancel()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		stillOnline := true
		for _, n := range srv.ListNodes() {
			if n.NodeID == "home-pc" {
				stillOnline = n.Online
			}
		}
		if !stillOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Unbound -> 400 Bad Request
	wakeBody, _ := json.Marshal(protocol.PowerRequest{Action: protocol.ActionWake})
	wakeReq0, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/home-pc/power", bytes.NewReader(wakeBody))
	wakeReq0.Header.Set("Authorization", "Bearer "+token)
	wakeResp0, _ := http.DefaultClient.Do(wakeReq0)
	_ = wakeResp0.Body.Close()
	if wakeResp0.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unbound home-pc wake, got %d", wakeResp0.StatusCode)
	}

	// Bind home-pc to home-esp32 manually
	bindReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/nodes/home-pc/wol", bytes.NewReader([]byte(`{"wol":{"mac":"9c:6b:00:13:9e:b3","broadcast_ip":"192.168.1.255","port":9,"wake_relay_id":"home-esp32"}}`)))
	bindReq.Header.Set("Authorization", "Bearer "+token)
	bindResp, err := http.DefaultClient.Do(bindReq)
	if err != nil || bindResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH home-pc wol failed: err=%v resp=%v", err, bindResp)
	}
	_ = bindResp.Body.Close()

	// Wake succeeds via bound home-esp32
	wakeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/home-pc/power", bytes.NewReader(wakeBody))
	wakeReq.Header.Set("Authorization", "Bearer "+token)
	wakeResp, err := http.DefaultClient.Do(wakeReq)
	if err != nil {
		t.Fatalf("wake home-pc err: %v", err)
	}
	var wakeOut protocol.PowerResponse
	_ = json.NewDecoder(wakeResp.Body).Decode(&wakeOut)
	_ = wakeResp.Body.Close()

	if !wakeOut.OK || wakeOut.Method != "wol-esp32-relay" || len(wakeOut.Relays) != 1 || wakeOut.Relays[0] != "home-esp32" {
		t.Fatalf("expected home-esp32 wake relay success, got %+v", wakeOut)
	}
	select {
	case mac := <-espWakeReceived:
		if mac != "9c:6b:00:13:9e:b3" {
			t.Fatalf("unexpected MAC on ESP32 wake frame: %s", mac)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ESP32 did not receive wake command")
	}

	// Disconnect ESP32 -> Wake returns 503 Service Unavailable
	_ = espConn.Close()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		relays := srv.ListWakeRelays()
		if len(relays) == 1 && !relays[0].Online {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	wakeReqOff, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/home-pc/power", bytes.NewReader(wakeBody))
	wakeReqOff.Header.Set("Authorization", "Bearer "+token)
	wakeRespOff, _ := http.DefaultClient.Do(wakeReqOff)
	_ = wakeRespOff.Body.Close()
	if wakeRespOff.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when bound ESP32 relay is offline, got %d", wakeRespOff.StatusCode)
	}
}
