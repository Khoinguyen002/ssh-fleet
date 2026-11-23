package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ssh-fleet/internal/agent"
	"ssh-fleet/internal/keyring"
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
	powerOff    bool
	powerOffCh  chan struct{}
	powerOffErr error
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

func (f *fakePowerExec) CheckPowerOff() error {
	f.mu.Lock()
	err := f.powerOffErr
	f.mu.Unlock()
	return err
}

func (f *fakePowerExec) PowerOff() error {
	f.mu.Lock()
	if f.powerOffErr != nil {
		err := f.powerOffErr
		f.mu.Unlock()
		return err
	}
	f.powerOff = true
	ch := f.powerOffCh
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
	defer func() {
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

	laptopCtx, cancelLaptop := context.WithCancel(context.Background())
	defer cancelLaptop()
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
	relayCtx, cancelRelay := context.WithCancel(context.Background())
	defer cancelRelay()
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

	for _, act := range []protocol.PowerAction{protocol.ActionSoftSleep, protocol.ActionHardSleep, protocol.ActionPowerOff} {
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

type fakeKeyringHandler struct {
	mu          sync.Mutex
	locked      bool
	expectedPw  string
	unlockCalls atomic.Int32
	lastPw      string
}

func (f *fakeKeyringHandler) setLocked(v bool) {
	f.mu.Lock()
	f.locked = v
	f.mu.Unlock()
}

func (f *fakeKeyringHandler) IsLocked(context.Context) *bool {
	f.mu.Lock()
	v := f.locked
	f.mu.Unlock()
	return &v
}

func (f *fakeKeyringHandler) Unlock(_ context.Context, password string) keyring.Result {
	f.unlockCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastPw = password
	if password == "" {
		return keyring.Result{OK: false, KeyringLocked: f.locked, Error: "Keyring password cannot be empty."}
	}
	if password != f.expectedPw {
		return keyring.Result{OK: false, KeyringLocked: true, Error: "Incorrect keyring password."}
	}
	f.locked = false
	return keyring.Result{OK: true, KeyringLocked: false}
}

func connectMockESP32Relay(t *testing.T, tsURL, adminToken, name string) (string, *ws.Conn, <-chan string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"name": name})
	req, _ := http.NewRequest(http.MethodPost, tsURL+"/api/v1/wake-relays", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create wake relay %s failed: err=%v resp=%v", name, err, resp)
	}
	var out struct {
		Relay protocol.WakeRelaySummary `json:"relay"`
		Token string                      `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()

	conn, err := ws.DialClient(context.Background(), tsURL, "/hub/ws/wake", out.Token, nil)
	if err != nil {
		t.Fatalf("DialClient /hub/ws/wake: %v", err)
	}
	_ = conn.WriteText(`{"t":"hello","firmwareVersion":"1.0.0"}`)
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read hello-ack: %v", err)
	}

	wakeCh := make(chan string, 4)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg struct {
				T         string `json:"t"`
				RequestID string `json:"requestId"`
				MAC       string `json:"mac"`
			}
			if json.Unmarshal(raw, &msg) == nil && msg.T == "wake" {
				wakeCh <- msg.MAC
				ack, _ := json.Marshal(map[string]any{
					"t":         "wake-ack",
					"requestId": msg.RequestID,
					"ok":        true,
				})
				_ = conn.WriteText(string(ack))
			}
		}
	}()
	return out.Relay.ID, conn, wakeCh
}

func bindNodeWoL(t *testing.T, tsURL, adminToken, nodeID, mac, relayID string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"wol": map[string]any{
			"mac":           mac,
			"broadcast_ip":  "192.168.1.255",
			"port":          9,
			"wake_relay_id": relayID,
		},
	})
	req, _ := http.NewRequest(http.MethodPatch, tsURL+"/api/v1/nodes/"+nodeID+"/wol", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bind WoL failed: err=%v resp=%v", err, resp)
	}
	_ = resp.Body.Close()
}

func waitForNodeOnline(t *testing.T, srv *Server, nodeID string, wantOnline bool, timeout time.Duration) protocol.NodeInfo {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range srv.ListNodes() {
			if n.NodeID == nodeID && n.Online == wantOnline {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for node %s online=%v (nodes=%+v)", nodeID, wantOnline, srv.ListNodes())
	return protocol.NodeInfo{}
}

func TestHardSleepEvictsAgentAndWakesViaESP32(t *testing.T) {
	const token = "hard-sleep-token"
	srv, err := NewServer(token, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	relayID, espConn, espWakeCh := connectMockESP32Relay(t, ts.URL, token, "Lab ESP32")
	defer espConn.Close()

	notVPS := false
	execImpl := &fakePowerExec{hardSleepCh: make(chan struct{})}
	ag, err := agent.NewClient(agent.Options{
		HubURL:         ts.URL,
		Token:          token,
		NodeID:         "workstation",
		Name:           "workstation",
		IsVPS:          &notVPS,
		Power:          power.NewManager(execImpl),
		PingInterval:   5 * time.Second,
		ReconnectDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ag.Run(ctx) }()

	waitForNodeOnline(t, srv, "workstation", true, 3*time.Second)
	bindNodeWoL(t, ts.URL, token, "workstation", "9c:6b:00:13:9e:b3", relayID)

	// HardSleep must evict the agent immediately so Hub marks it offline/sleeping.
	hsBody, _ := json.Marshal(protocol.PowerRequest{Action: protocol.ActionHardSleep})
	hsReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/workstation/power", bytes.NewReader(hsBody))
	hsReq.Header.Set("Authorization", "Bearer "+token)
	hsResp, err := http.DefaultClient.Do(hsReq)
	if err != nil {
		t.Fatalf("hard-sleep request err: %v", err)
	}
	var hsOut protocol.PowerResponse
	_ = json.NewDecoder(hsResp.Body).Decode(&hsOut)
	_ = hsResp.Body.Close()
	if hsResp.StatusCode != http.StatusOK || !hsOut.OK {
		t.Fatalf("hard-sleep failed: status=%d out=%+v", hsResp.StatusCode, hsOut)
	}

	var gotNode *protocol.NodeInfo
	for _, n := range srv.ListNodes() {
		if n.NodeID == "workstation" {
			cp := n
			gotNode = &cp
		}
	}
	if gotNode == nil || gotNode.Online || gotNode.PowerState != protocol.PowerSleeping {
		t.Fatalf("expected immediate eviction to offline/sleeping after HardSleep, got %+v", gotNode)
	}

	select {
	case <-execImpl.hardSleepCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not invoke HardSleep executor")
	}

	// Wake immediately routes via ESP32 WoL instead of hitting a stale tunnel and returning 502.
	wakeBody, _ := json.Marshal(protocol.PowerRequest{Action: protocol.ActionWake})
	wakeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/workstation/power", bytes.NewReader(wakeBody))
	wakeReq.Header.Set("Authorization", "Bearer "+token)
	wakeResp, err := http.DefaultClient.Do(wakeReq)
	if err != nil {
		t.Fatalf("wake request err: %v", err)
	}
	var wakeOut protocol.PowerResponse
	_ = json.NewDecoder(wakeResp.Body).Decode(&wakeOut)
	_ = wakeResp.Body.Close()
	if wakeResp.StatusCode != http.StatusOK || !wakeOut.OK || wakeOut.Method != "wol-esp32-relay" {
		t.Fatalf("expected ESP32 WoL wake success, got status=%d out=%+v", wakeResp.StatusCode, wakeOut)
	}
	select {
	case mac := <-espWakeCh:
		if mac != "9c:6b:00:13:9e:b3" {
			t.Fatalf("unexpected MAC sent to ESP32: %s", mac)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ESP32 did not receive wake command")
	}
}

func TestWakeFallsBackToESP32WhenSocketIsZombie(t *testing.T) {
	const token = "zombie-fallback-token"
	srv, err := NewServerWithOptions(Options{
		Token:           token,
		DataDir:         t.TempDir(),
		SoftWakeTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	relayID, espConn, espWakeCh := connectMockESP32Relay(t, ts.URL, token, "LivingRoom ESP32")
	defer espConn.Close()

	// Helper to register a silent (zombie) raw WebSocket control connection.
	connectZombie := func(nodeID string) *ws.Conn {
		c, err := ws.DialClient(context.Background(), ts.URL, "/tunnel/control", token, nil)
		if err != nil {
			t.Fatalf("DialClient /tunnel/control: %v", err)
		}
		regFrame, _ := json.Marshal(protocol.ControlFrame{
			Type: "register",
			Node: &protocol.NodeInfo{
				NodeID:     nodeID,
				Name:       nodeID,
				OS:         "linux",
				Arch:       "amd64",
				PowerState: protocol.PowerActive,
			},
		})
		if err := c.WriteBinary(append(regFrame, '\n')); err != nil {
			t.Fatalf("write register: %v", err)
		}
		waitForNodeOnline(t, srv, nodeID, true, 2*time.Second)
		return c
	}

	// 1. Bound zombie socket -> soft-wake times out, evicts socket, and falls back to ESP32 WoL.
	z1 := connectZombie("zombie-bound")
	defer z1.Close()
	bindNodeWoL(t, ts.URL, token, "zombie-bound", "aa:bb:cc:dd:ee:11", relayID)

	wakeBody, _ := json.Marshal(protocol.PowerRequest{Action: protocol.ActionWake})
	req1, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/zombie-bound/power", bytes.NewReader(wakeBody))
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("wake zombie-bound err: %v", err)
	}
	var out1 protocol.PowerResponse
	_ = json.NewDecoder(resp1.Body).Decode(&out1)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || !out1.OK || out1.Method != "wol-esp32-relay" {
		t.Fatalf("expected fallback to wol-esp32-relay, got status=%d out=%+v", resp1.StatusCode, out1)
	}
	select {
	case mac := <-espWakeCh:
		if mac != "aa:bb:cc:dd:ee:11" {
			t.Fatalf("unexpected fallback MAC: %s", mac)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ESP32 did not receive fallback wake")
	}
	waitForNodeOnline(t, srv, "zombie-bound", false, 1*time.Second)

	// 2. Unbound zombie socket -> evicts socket and returns 503 (never 502) JSON error.
	z2 := connectZombie("zombie-unbound")
	defer z2.Close()
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/zombie-unbound/power", bytes.NewReader(wakeBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("wake zombie-unbound err: %v", err)
	}
	var out2 protocol.PowerResponse
	_ = json.NewDecoder(resp2.Body).Decode(&out2)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable || out2.OK {
		t.Fatalf("expected 503 JSON error for unbound zombie, got status=%d out=%+v", resp2.StatusCode, out2)
	}
	waitForNodeOnline(t, srv, "zombie-unbound", false, 1*time.Second)
}

func TestReadDeadlineEvictsDeadAgentAndESP32(t *testing.T) {
	const token = "deadline-evict-token"
	srv, err := NewServerWithOptions(Options{
		Token:            token,
		DataDir:          t.TempDir(),
		AgentReadTimeout: 250 * time.Millisecond,
		ESP32ReadTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	// Silent raw agent socket (never sends pings after register).
	deadConn, err := ws.DialClient(context.Background(), ts.URL, "/tunnel/control", token, nil)
	if err != nil {
		t.Fatalf("DialClient dead-pc: %v", err)
	}
	defer deadConn.Close()
	reg, _ := json.Marshal(protocol.ControlFrame{
		Type: "register",
		Node: &protocol.NodeInfo{NodeID: "dead-pc", Name: "dead-pc", OS: "linux", Arch: "amd64"},
	})
	_ = deadConn.WriteBinary(append(reg, '\n'))
	waitForNodeOnline(t, srv, "dead-pc", true, 2*time.Second)

	// Live agent sending pings every 70ms stays online past deadline.
	liveAgent, err := agent.NewClient(agent.Options{
		HubURL:       ts.URL,
		Token:        token,
		NodeID:       "live-pc",
		Name:         "live-pc",
		PingInterval: 70 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient live-pc: %v", err)
	}
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()
	go func() { _ = liveAgent.Run(liveCtx) }()
	waitForNodeOnline(t, srv, "live-pc", true, 2*time.Second)

	// Silent ESP32 relay vs live pinging ESP32 relay.
	deadRelayID, deadESP, _ := connectMockESP32Relay(t, ts.URL, token, "Dead ESP32")
	defer deadESP.Close()
	liveRelayID, liveESP, _ := connectMockESP32Relay(t, ts.URL, token, "Live ESP32")
	defer liveESP.Close()

	liveESPStop := make(chan struct{})
	defer close(liveESPStop)
	go func() {
		ticker := time.NewTicker(70 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-liveESPStop:
				return
			case <-ticker.C:
				_ = liveESP.WriteText(`{"t":"ping"}`)
			}
		}
	}()

	time.Sleep(450 * time.Millisecond)

	nodes := map[string]protocol.NodeInfo{}
	for _, n := range srv.ListNodes() {
		nodes[n.NodeID] = n
	}
	if nodes["dead-pc"].Online || nodes["dead-pc"].PowerState != protocol.PowerOffline {
		t.Fatalf("expected dead-pc evicted to offline, got %+v", nodes["dead-pc"])
	}
	if !nodes["live-pc"].Online {
		t.Fatalf("expected live-pc to remain online, got %+v", nodes["live-pc"])
	}

	relays := map[string]protocol.WakeRelaySummary{}
	for _, r := range srv.ListWakeRelays() {
		relays[r.ID] = r
	}
	if relays[deadRelayID].Online {
		t.Fatalf("expected silent ESP32 relay %s evicted, got online=true", deadRelayID)
	}
	if !relays[liveRelayID].Online {
		t.Fatalf("expected pinging ESP32 relay %s to remain online", liveRelayID)
	}
}

func TestAuthPrivilegeSeparationAndNodeSpoofingBlocked(t *testing.T) {
	const adminTok = "admin-master-token"
	srv, err := NewServer(adminTok, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	// Mint one-time join token as admin and exchange it for node-a's per-node token.
	jtReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/join-tokens", nil)
	jtReq.Header.Set("Authorization", "Bearer "+adminTok)
	jtResp, err := http.DefaultClient.Do(jtReq)
	if err != nil || jtResp.StatusCode != http.StatusCreated {
		t.Fatalf("mint join token failed: err=%v resp=%v", err, jtResp)
	}
	var jtOut struct {
		JoinToken string `json:"join_token"`
	}
	_ = json.NewDecoder(jtResp.Body).Decode(&jtOut)
	_ = jtResp.Body.Close()

	exBody, _ := json.Marshal(map[string]string{"join_token": jtOut.JoinToken, "node_id": "node-a"})
	exResp, err := http.Post(ts.URL+"/api/v1/join/exchange", "application/json", bytes.NewReader(exBody))
	if err != nil || exResp.StatusCode != http.StatusOK {
		t.Fatalf("join exchange failed: err=%v resp=%v", err, exResp)
	}
	var exOut struct {
		NodeToken string `json:"node_token"`
	}
	_ = json.NewDecoder(exResp.Body).Decode(&exOut)
	_ = exResp.Body.Close()
	nodeTok := exOut.NodeToken

	// node-a token must get 403 Forbidden on admin endpoints and authenticated=false on auth/status.
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/hub-info", ""},
		{http.MethodPost, "/api/v1/join-tokens", ""},
		{http.MethodGet, "/api/v1/wake-relays", ""},
		{http.MethodGet, "/api/v1/ws/terminal?mode=agent&node_id=node-a", ""},
		{http.MethodPatch, "/api/v1/nodes/node-a/wol", `{"wol":null}`},
		{http.MethodPost, "/api/v1/nodes/node-a/unlock-keyring", `{"password":"pw"}`},
		{http.MethodPost, "/api/v1/nodes/node-a/power", `{"action":"wake","keyring_password":"pw"}`},
	} {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+nodeTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s err: %v", tc.method, tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for node token on %s %s, got %d", tc.method, tc.path, resp.StatusCode)
		}
	}

	stReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/status", nil)
	stReq.Header.Set("Authorization", "Bearer "+nodeTok)
	stResp, _ := http.DefaultClient.Do(stReq)
	var st struct {
		Authenticated bool `json:"authenticated"`
	}
	_ = json.NewDecoder(stResp.Body).Decode(&st)
	_ = stResp.Body.Close()
	if st.Authenticated {
		t.Fatalf("node token must not report authenticated=true on /api/v1/auth/status")
	}

	// node token CAN read GET /api/v1/nodes.
	nodesReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/nodes", nil)
	nodesReq.Header.Set("Authorization", "Bearer "+nodeTok)
	nodesResp, _ := http.DefaultClient.Do(nodesReq)
	_ = nodesResp.Body.Close()
	if nodesResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for node token on GET /api/v1/nodes, got %d", nodesResp.StatusCode)
	}

	// Anti-spoofing: node-a's credential must NOT be allowed to register as node-b.
	spoofConn, err := ws.DialClient(context.Background(), ts.URL, "/tunnel/control", nodeTok, nil)
	if err != nil {
		t.Fatalf("DialClient spoof: %v", err)
	}
	defer spoofConn.Close()
	spoofReg, _ := json.Marshal(protocol.ControlFrame{
		Type: "register",
		Node: &protocol.NodeInfo{NodeID: "node-b", Name: "node-b", OS: "linux", Arch: "amd64"},
	})
	_ = spoofConn.WriteBinary(append(spoofReg, '\n'))

	_ = spoofConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 64)
	if _, rErr := spoofConn.Read(buf); rErr == nil {
		t.Fatalf("expected Hub to close spoofed tunnel connection")
	}
	for _, n := range srv.ListNodes() {
		if n.NodeID == "node-b" {
			t.Fatalf("spoofed node-b must not be registered: %+v", n)
		}
	}

	// Registering with matching node_id ("node-a") succeeds.
	legitConn, err := ws.DialClient(context.Background(), ts.URL, "/tunnel/control", nodeTok, nil)
	if err != nil {
		t.Fatalf("DialClient legit node-a: %v", err)
	}
	defer legitConn.Close()
	legitReg, _ := json.Marshal(protocol.ControlFrame{
		Type: "register",
		Node: &protocol.NodeInfo{NodeID: "node-a", Name: "node-a", OS: "linux", Arch: "amd64"},
	})
	_ = legitConn.WriteBinary(append(legitReg, '\n'))
	waitForNodeOnline(t, srv, "node-a", true, 2*time.Second)
}

func TestWakeQueuedKeyringUnlockAndManualUnlock(t *testing.T) {
	const token = "keyring-unlock-token"
	const secretPw = "super-secret-keyring-pass"
	dataDir := t.TempDir()

	srv, err := NewServerWithOptions(Options{
		Token:            token,
		DataDir:          dataDir,
		KeyringUnlockTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	relayID, espConn, espWakeCh := connectMockESP32Relay(t, ts.URL, token, "Ubuntu ESP32")

	notVPS := false
	kr := &fakeKeyringHandler{locked: true, expectedPw: secretPw}
	execImpl := &fakePowerExec{hardSleepCh: make(chan struct{})}
	startUbuntuAgent := func() context.CancelFunc {
		ag, err := agent.NewClient(agent.Options{
			HubURL:         ts.URL,
			Token:          token,
			NodeID:         "ubuntu-box",
			Name:           "ubuntu-box",
			IsVPS:          &notVPS,
			Power:          power.NewManager(execImpl),
			Keyring:        kr,
			PingInterval:   100 * time.Millisecond,
			ReconnectDelay: 100 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewClient ubuntu-box: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = ag.Run(ctx) }()
		return cancel
	}

	cancel1 := startUbuntuAgent()
	n0 := waitForNodeOnline(t, srv, "ubuntu-box", true, 3*time.Second)
	if n0.KeyringLocked == nil || !*n0.KeyringLocked {
		t.Fatalf("expected keyring_locked=true on register, got %+v", n0.KeyringLocked)
	}
	bindNodeWoL(t, ts.URL, token, "ubuntu-box", "11:22:33:44:55:66", relayID)

	// 1. Manual unlock validation: empty -> 400, wrong -> 401, right -> 200.
	callUnlock := func(pw string) (int, protocol.UnlockKeyringResponse) {
		b, _ := json.Marshal(protocol.UnlockKeyringRequest{Password: pw})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/ubuntu-box/unlock-keyring", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("unlock-keyring request err: %v", err)
		}
		defer resp.Body.Close()
		var out protocol.UnlockKeyringResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	if code, _ := callUnlock(""); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty keyring password, got %d", code)
	}
	if code, out := callUnlock("wrong-pw"); code != http.StatusUnauthorized || out.OK || out.KeyringLocked == nil || !*out.KeyringLocked {
		t.Fatalf("expected 401 + locked=true on wrong password, got code=%d out=%+v", code, out)
	}
	if code, out := callUnlock(secretPw); code != http.StatusOK || !out.OK || out.KeyringLocked == nil || *out.KeyringLocked {
		t.Fatalf("expected 200 + locked=false on right password, got code=%d out=%+v", code, out)
	}

	// 2. HardSleep and take ESP32 offline -> Wake with keyring_password must fail 503 and NOT leave unlock queued.
	kr.setLocked(true)
	hsBody, _ := json.Marshal(protocol.PowerRequest{Action: protocol.ActionHardSleep})
	hsReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/ubuntu-box/power", bytes.NewReader(hsBody))
	hsReq.Header.Set("Authorization", "Bearer "+token)
	hsResp, _ := http.DefaultClient.Do(hsReq)
	_ = hsResp.Body.Close()
	cancel1()
	waitForNodeOnline(t, srv, "ubuntu-box", false, 2*time.Second)

	_ = espConn.Close()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		relays := srv.ListWakeRelays()
		if len(relays) == 1 && !relays[0].Online {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	wakePayload, _ := json.Marshal(protocol.PowerRequest{
		Action:          protocol.ActionWake,
		KeyringPassword: secretPw,
	})
	failReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/ubuntu-box/power", bytes.NewReader(wakePayload))
	failReq.Header.Set("Authorization", "Bearer "+token)
	failResp, _ := http.DefaultClient.Do(failReq)
	_ = failResp.Body.Close()
	if failResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when ESP32 relay offline, got %d", failResp.StatusCode)
	}

	// 3. Reconnect ESP32 relay, wake with keyring_password -> queued in RAM only (never persisted to hub-nodes.json).
	relayID2, espConn2, espWakeCh2 := connectMockESP32Relay(t, ts.URL, token, "Ubuntu ESP32 2")
	defer espConn2.Close()
	bindNodeWoL(t, ts.URL, token, "ubuntu-box", "11:22:33:44:55:66", relayID2)
	_ = espWakeCh

	wakeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/ubuntu-box/power", bytes.NewReader(wakePayload))
	wakeReq.Header.Set("Authorization", "Bearer "+token)
	wakeResp, err := http.DefaultClient.Do(wakeReq)
	if err != nil {
		t.Fatalf("wake with keyring err: %v", err)
	}
	var wakeOut protocol.PowerResponse
	_ = json.NewDecoder(wakeResp.Body).Decode(&wakeOut)
	_ = wakeResp.Body.Close()
	if wakeResp.StatusCode != http.StatusOK || !wakeOut.OK || !wakeOut.UnlockQueued {
		t.Fatalf("expected 200 + unlock_queued=true, got status=%d out=%+v", wakeResp.StatusCode, wakeOut)
	}
	select {
	case <-espWakeCh2:
	case <-time.After(2 * time.Second):
		t.Fatalf("ESP32 did not receive wake command")
	}

	diskBytes, err := os.ReadFile(filepath.Join(dataDir, "hub-nodes.json"))
	if err != nil {
		t.Fatalf("read hub-nodes.json: %v", err)
	}
	if bytes.Contains(diskBytes, []byte(secretPw)) {
		t.Fatalf("keyring password must NEVER be written to hub-nodes.json")
	}

	// 4. Agent reconnects after wake -> Hub auto-dispatches queued unlock-keyring (single-use).
	prevCalls := kr.unlockCalls.Load()
	cancel2 := startUbuntuAgent()
	defer cancel2()
	waitForNodeOnline(t, srv, "ubuntu-box", true, 3*time.Second)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var unlocked bool
		for _, n := range srv.ListNodes() {
			if n.NodeID == "ubuntu-box" && n.KeyringLocked != nil && !*n.KeyringLocked && !n.KeyringUnlockPending {
				unlocked = true
			}
		}
		if unlocked && kr.unlockCalls.Load() == prevCalls+1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if kr.unlockCalls.Load() != prevCalls+1 {
		t.Fatalf("expected auto-unlock once on reconnect, calls=%d (want %d)", kr.unlockCalls.Load(), prevCalls+1)
	}

	// Single-use: disconnect & reconnect with locked=true -> must NOT re-run queued unlock.
	cancel2()
	waitForNodeOnline(t, srv, "ubuntu-box", false, 2*time.Second)
	kr.setLocked(true)
	cancel3 := startUbuntuAgent()
	defer cancel3()
	waitForNodeOnline(t, srv, "ubuntu-box", true, 3*time.Second)
	time.Sleep(150 * time.Millisecond)
	if kr.unlockCalls.Load() != prevCalls+1 {
		t.Fatalf("queued unlock must be single-use, got calls=%d", kr.unlockCalls.Load())
	}
	cancel3()

	// 5. TTL expiry: queued password must expire and not fire on late reconnect.
	ttlSrv, err := NewServerWithOptions(Options{
		Token:            token,
		DataDir:          t.TempDir(),
		KeyringUnlockTTL: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions TTL: %v", err)
	}
	ttlTS := httptest.NewServer(ttlSrv.Handler())
	defer func() {
		_ = ttlSrv.Close()
		ttlTS.Close()
		time.Sleep(40 * time.Millisecond)
	}()

	ttlRelayID, ttlESP, ttlWakeCh := connectMockESP32Relay(t, ttlTS.URL, token, "TTL ESP32")
	defer ttlESP.Close()
	ttlKR := &fakeKeyringHandler{locked: true, expectedPw: secretPw}
	startTTLAgent := func() context.CancelFunc {
		ag, _ := agent.NewClient(agent.Options{
			HubURL:  ttlTS.URL,
			Token:   token,
			NodeID:  "ttl-box",
			Name:    "ttl-box",
			IsVPS:   &notVPS,
			Keyring: ttlKR,
		})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = ag.Run(ctx) }()
		return cancel
	}
	cTTL1 := startTTLAgent()
	waitForNodeOnline(t, ttlSrv, "ttl-box", true, 2*time.Second)
	bindNodeWoL(t, ttlTS.URL, token, "ttl-box", "22:33:44:55:66:77", ttlRelayID)
	cTTL1()
	waitForNodeOnline(t, ttlSrv, "ttl-box", false, 2*time.Second)

	wReq, _ := http.NewRequest(http.MethodPost, ttlTS.URL+"/api/v1/nodes/ttl-box/power", bytes.NewReader(wakePayload))
	wReq.Header.Set("Authorization", "Bearer "+token)
	wResp, _ := http.DefaultClient.Do(wReq)
	_ = wResp.Body.Close()
	<-ttlWakeCh

	time.Sleep(220 * time.Millisecond)
	cTTL2 := startTTLAgent()
	defer cTTL2()
	waitForNodeOnline(t, ttlSrv, "ttl-box", true, 2*time.Second)
	time.Sleep(150 * time.Millisecond)
	if ttlKR.unlockCalls.Load() != 0 {
		t.Fatalf("expected expired queued unlock not to run, got %d calls", ttlKR.unlockCalls.Load())
	}
}

func TestPowerOffEvictsAgentAndWakesViaESP32(t *testing.T) {
	const token = "poweroff-token"
	srv, err := NewServer(token, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	relayID, espConn, espWakeCh := connectMockESP32Relay(t, ts.URL, token, "Office ESP32")
	defer espConn.Close()

	notVPS := false
	execImpl := &fakePowerExec{
		powerOffCh:  make(chan struct{}),
		powerOffErr: errors.New("shutdown permission denied (polkit or passwordless sudo required)"),
	}
	ag, err := agent.NewClient(agent.Options{
		HubURL:         ts.URL,
		Token:          token,
		NodeID:         "desktop-pc",
		Name:           "desktop-pc",
		IsVPS:          &notVPS,
		Power:          power.NewManager(execImpl),
		PingInterval:   5 * time.Second,
		ReconnectDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ag.Run(ctx) }()

	waitForNodeOnline(t, srv, "desktop-pc", true, 3*time.Second)
	bindNodeWoL(t, ts.URL, token, "desktop-pc", "9c:6b:00:13:9e:b4", relayID)

	sendPowerReq := func(payload protocol.PowerRequest) (int, protocol.PowerResponse) {
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/nodes/desktop-pc/power", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("power request err: %v", err)
		}
		defer resp.Body.Close()
		var out protocol.PowerResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// 1. Permission error must fail 503 BEFORE ACKing or evicting the agent.
	codeFail, outFail := sendPowerReq(protocol.PowerRequest{Action: protocol.ActionPowerOff})
	if codeFail != http.StatusServiceUnavailable || outFail.OK || !strings.Contains(outFail.Error, "permission denied") {
		t.Fatalf("expected 503 permission error without eviction, got code=%d out=%+v", codeFail, outFail)
	}
	waitForNodeOnline(t, srv, "desktop-pc", true, 1*time.Second)

	// 2. Grant permission -> PowerOff succeeds 200, evicts agent immediately to offline, and runs PowerOff().
	execImpl.mu.Lock()
	execImpl.powerOffErr = nil
	execImpl.mu.Unlock()

	codeOK, outOK := sendPowerReq(protocol.PowerRequest{Action: protocol.ActionPowerOff})
	if codeOK != http.StatusOK || !outOK.OK || outOK.Method != "direct-agent" {
		t.Fatalf("expected 200 poweroff success, got code=%d out=%+v", codeOK, outOK)
	}

	var gotNode *protocol.NodeInfo
	for _, n := range srv.ListNodes() {
		if n.NodeID == "desktop-pc" {
			cp := n
			gotNode = &cp
		}
	}
	if gotNode == nil || gotNode.Online || gotNode.PowerState != protocol.PowerOffline {
		t.Fatalf("expected immediate eviction to offline after PowerOff, got %+v", gotNode)
	}

	select {
	case <-execImpl.powerOffCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not invoke PowerOff executor")
	}

	// 3. Immediately wake via ESP32 S5 WoL + queued keyring password.
	wakeCode, wakeOut := sendPowerReq(protocol.PowerRequest{
		Action:          protocol.ActionWake,
		KeyringPassword: "desktop-keyring-pw",
	})
	if wakeCode != http.StatusOK || !wakeOut.OK || wakeOut.Method != "wol-esp32-relay" || !wakeOut.UnlockQueued {
		t.Fatalf("expected ESP32 WoL + unlock_queued after PowerOff, got code=%d out=%+v", wakeCode, wakeOut)
	}
	select {
	case mac := <-espWakeCh:
		if mac != "9c:6b:00:13:9e:b4" {
			t.Fatalf("unexpected MAC sent to ESP32: %s", mac)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ESP32 did not receive wake command after PowerOff")
	}
}

func TestRenameAndDeleteNodeAndRevokeCred(t *testing.T) {
	const adminTok = "rename-delete-admin-tok"
	dataDir := t.TempDir()
	srv, err := NewServer(adminTok, dataDir)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		_ = srv.Close()
		ts.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	// 1. Mint one-time join token and exchange for temp-pc's per-node credential.
	jtReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/join-tokens", nil)
	jtReq.Header.Set("Authorization", "Bearer "+adminTok)
	jtResp, err := http.DefaultClient.Do(jtReq)
	if err != nil || jtResp.StatusCode != http.StatusCreated {
		t.Fatalf("mint join token failed: err=%v resp=%v", err, jtResp)
	}
	var jtOut struct {
		JoinToken string `json:"join_token"`
	}
	_ = json.NewDecoder(jtResp.Body).Decode(&jtOut)
	_ = jtResp.Body.Close()

	exBody, _ := json.Marshal(map[string]string{"join_token": jtOut.JoinToken, "node_id": "temp-pc"})
	exResp, err := http.Post(ts.URL+"/api/v1/join/exchange", "application/json", bytes.NewReader(exBody))
	if err != nil || exResp.StatusCode != http.StatusOK {
		t.Fatalf("join exchange failed: err=%v resp=%v", err, exResp)
	}
	var exOut struct {
		NodeToken string `json:"node_token"`
	}
	_ = json.NewDecoder(exResp.Body).Decode(&exOut)
	_ = exResp.Body.Close()
	nodeTok := exOut.NodeToken

	connectTempAgent := func() context.CancelFunc {
		ag, err := agent.NewClient(agent.Options{
			HubURL:         ts.URL,
			Token:          nodeTok,
			NodeID:         "temp-pc",
			Name:           "temp-pc",
			PingInterval:   5 * time.Second,
			ReconnectDelay: 100 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewClient temp-pc: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = ag.Run(ctx) }()
		return cancel
	}

	cancel1 := connectTempAgent()
	waitForNodeOnline(t, srv, "temp-pc", true, 3*time.Second)

	// 2. Node token must get 403 Forbidden on PATCH and DELETE /api/v1/nodes/temp-pc.
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/nodes/temp-pc", strings.NewReader(`{"name":"Hacked"}`))
		req.Header.Set("Authorization", "Bearer "+nodeTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("nodeTok %s err: %v", method, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for node token on %s /api/v1/nodes/temp-pc, got %d", method, resp.StatusCode)
		}
	}

	// 3. Admin PATCH empty name -> 400; valid name -> 200.
	emptyReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/nodes/temp-pc", strings.NewReader(`{"name":"   "}`))
	emptyReq.Header.Set("Authorization", "Bearer "+adminTok)
	emptyResp, _ := http.DefaultClient.Do(emptyReq)
	_ = emptyResp.Body.Close()
	if emptyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty rename, got %d", emptyResp.StatusCode)
	}

	renReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/nodes/temp-pc", strings.NewReader(`{"name":"Home Ubuntu PC"}`))
	renReq.Header.Set("Authorization", "Bearer "+adminTok)
	renResp, err := http.DefaultClient.Do(renReq)
	if err != nil || renResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH rename failed: err=%v resp=%v", err, renResp)
	}
	var renOut struct {
		OK   bool              `json:"ok"`
		Node protocol.NodeInfo `json:"node"`
	}
	_ = json.NewDecoder(renResp.Body).Decode(&renOut)
	_ = renResp.Body.Close()
	if !renOut.OK || renOut.Node.Name != "Home Ubuntu PC" || !renOut.Node.CustomName {
		t.Fatalf("unexpected rename response: %+v", renOut)
	}

	// 4. Disconnect and reconnect sending old Name="temp-pc" -> Hub must preserve "Home Ubuntu PC".
	cancel1()
	waitForNodeOnline(t, srv, "temp-pc", false, 2*time.Second)

	cancel2 := connectTempAgent()
	defer cancel2()
	n2 := waitForNodeOnline(t, srv, "temp-pc", true, 3*time.Second)
	if n2.Name != "Home Ubuntu PC" {
		t.Fatalf("expected Hub to preserve custom name 'Home Ubuntu PC' across reconnect, got %q", n2.Name)
	}

	// 5. Admin DELETE removes node from memory + disk, closes tunnel, and revokes sfn_temp-pc.*.
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/nodes/temp-pc", nil)
	delReq.Header.Set("Authorization", "Bearer "+adminTok)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil || delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE node failed: err=%v resp=%v", err, delResp)
	}
	_ = delResp.Body.Close()
	cancel2()

	for _, n := range srv.ListNodes() {
		if n.NodeID == "temp-pc" {
			t.Fatalf("expected temp-pc removed from ListNodes(), got %+v", n)
		}
	}
	diskBytes, err := os.ReadFile(filepath.Join(dataDir, "hub-nodes.json"))
	if err == nil && bytes.Contains(diskBytes, []byte("temp-pc")) {
		t.Fatalf("expected temp-pc removed from hub-nodes.json, got %s", diskBytes)
	}

	// Revoked node token must now get 401 Unauthorized on GET /api/v1/nodes.
	revReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/nodes", nil)
	revReq.Header.Set("Authorization", "Bearer "+nodeTok)
	revResp, err := http.DefaultClient.Do(revReq)
	if err != nil {
		t.Fatalf("revoked token GET /api/v1/nodes err: %v", err)
	}
	_ = revResp.Body.Close()
	if revResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked node token, got %d", revResp.StatusCode)
	}
}
