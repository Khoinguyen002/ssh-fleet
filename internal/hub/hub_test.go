package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
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
	defer ts.Close()
	defer srv.Close()

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
