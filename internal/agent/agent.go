package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"ssh-fleet/internal/power"
	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/wol"
)

type Options struct {
	HubURL         string
	Token          string
	NodeID         string
	Name           string
	SSHPort        int
	SSHUser        string
	Power          *power.Manager
	WoLHandler     func(mac, broadcastIP string) error
	NetworkInfoFn  func() ([]wol.NetInterfaceInfo, error)
	PingInterval   time.Duration
	ReconnectDelay time.Duration
}

type Client struct {
	opts  Options
	power *power.Manager
}

func NewClient(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.HubURL) == "" {
		return nil, errors.New("hub url is required")
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("hub token is required")
	}
	if strings.TrimSpace(opts.NodeID) == "" {
		h, _ := os.Hostname()
		opts.NodeID = strings.ToLower(strings.TrimSpace(h))
		if opts.NodeID == "" {
			opts.NodeID = "device"
		}
	}
	if strings.TrimSpace(opts.Name) == "" {
		h, _ := os.Hostname()
		if h != "" {
			opts.Name = h
		} else {
			opts.Name = opts.NodeID
		}
	}
	if opts.SSHPort <= 0 {
		opts.SSHPort = 22
	}
	if strings.TrimSpace(opts.SSHUser) == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			// Strip Windows DOMAIN\user prefix if present.
			if idx := strings.LastIndex(u.Username, `\`); idx >= 0 {
				opts.SSHUser = u.Username[idx+1:]
			} else {
				opts.SSHUser = u.Username
			}
		}
	}
	if opts.Power == nil {
		opts.Power = power.NewManager(nil)
	}
	if opts.WoLHandler == nil {
		opts.WoLHandler = func(mac, broadcastIP string) error {
			return wol.SendMagicPacket(mac, broadcastIP, 9, 7)
		}
	}
	if opts.NetworkInfoFn == nil {
		opts.NetworkInfoFn = wol.DetectNetworkInterfaces
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = 15 * time.Second
	}
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = 3 * time.Second
	}
	return &Client{opts: opts, power: opts.Power}, nil
}

func (c *Client) Run(ctx context.Context) error {
	for {
		err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			c.power.Close()
			return ctx.Err()
		}
		if err != nil {
			// Keep reconnecting reliably across Wi-Fi / sleep transitions.
			select {
			case <-ctx.Done():
				c.power.Close()
				return ctx.Err()
			case <-time.After(c.opts.ReconnectDelay):
			}
		}
	}
}

func (c *Client) buildNodeInfo() protocol.NodeInfo {
	host, _ := os.Hostname()
	ifaces, _ := c.opts.NetworkInfoFn()
	var ips, subnets, macs []string
	var bcast string
	seenSubnet := map[string]bool{}
	seenMAC := map[string]bool{}
	for _, info := range ifaces {
		if info.IPv4 != "" {
			ips = append(ips, info.IPv4)
		}
		if info.SubnetCIDR != "" && !seenSubnet[info.SubnetCIDR] {
			seenSubnet[info.SubnetCIDR] = true
			subnets = append(subnets, info.SubnetCIDR)
		}
		if info.MAC != "" && !seenMAC[info.MAC] {
			seenMAC[info.MAC] = true
			macs = append(macs, info.MAC)
		}
		if bcast == "" && info.BroadcastIP != "" {
			bcast = info.BroadcastIP
		}
	}

	return protocol.NodeInfo{
		NodeID:      c.opts.NodeID,
		Name:        c.opts.Name,
		Hostname:    host,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		SSHUser:     c.opts.SSHUser,
		SSHPort:     c.opts.SSHPort,
		LocalIPs:    ips,
		SubnetCIDRs: subnets,
		MACAddrs:    macs,
		BroadcastIP: bcast,
		PowerState:  c.power.State(),
		Online:      true,
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	conn, br, err := DialUpgrade(ctx, c.opts.HubURL, "/tunnel/control", c.opts.Token, "ssh-fleet-control")
	if err != nil {
		return err
	}
	defer conn.Close()

	var writeM sync.Mutex
	sendFrame := func(f protocol.ControlFrame) error {
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		writeM.Lock()
		defer writeM.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Write(b)
		_ = conn.SetWriteDeadline(time.Time{})
		return err
	}

	nodeInfo := c.buildNodeInfo()
	if err := sendFrame(protocol.ControlFrame{
		Type: "register",
		Node: &nodeInfo,
	}); err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	go func() {
		ticker := time.NewTicker(c.opts.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := sendFrame(protocol.ControlFrame{
					Type:       "ping",
					PowerState: c.power.State(),
				}); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var frame protocol.ControlFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			continue
		}

		switch frame.Type {
		case "open-ssh-stream":
			go c.handleOpenStream(ctx, frame.StreamID)
		case "power-cmd":
			go c.handlePowerCmd(sendFrame, frame)
		case "wol-cmd":
			go c.handleWolCmd(sendFrame, frame)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

func (c *Client) handleOpenStream(ctx context.Context, streamID string) {
	if streamID == "" {
		return
	}
	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", c.opts.SSHPort), 5*time.Second)
	if err != nil {
		return
	}

	remoteConn, br, err := DialUpgrade(ctx, c.opts.HubURL, "/tunnel/agent-stream?stream_id="+url.QueryEscape(streamID), c.opts.Token, "ssh-fleet-stream")
	if err != nil {
		_ = localConn.Close()
		return
	}

	spliceBuffered(localConn, remoteConn, br)
}

func (c *Client) handlePowerCmd(sendFrame func(protocol.ControlFrame) error, frame protocol.ControlFrame) {
	switch protocol.PowerAction(frame.Action) {
	case protocol.ActionKeepAwakeOn:
		st, err := c.power.SetKeepAwake(true)
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         err == nil,
			PowerState: st,
			Error:      errString(err),
		})
	case protocol.ActionKeepAwakeOff:
		st, err := c.power.SetKeepAwake(false)
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         err == nil,
			PowerState: st,
			Error:      errString(err),
		})
	case protocol.ActionSoftSleep:
		st, err := c.power.SoftSleep()
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         err == nil,
			PowerState: st,
			Error:      errString(err),
		})
	case protocol.ActionWake:
		st, err := c.power.Wake()
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         err == nil,
			PowerState: st,
			Error:      errString(err),
		})
	case protocol.ActionHardSleep:
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         true,
			PowerState: protocol.PowerSleeping,
		})
		_ = c.power.PrepareHardSleep(250 * time.Millisecond)
	default:
		_ = sendFrame(protocol.ControlFrame{
			Type:  "power-ack",
			ReqID: frame.ReqID,
			OK:    false,
			Error: fmt.Sprintf("unknown power action: %s", frame.Action),
		})
	}
}

func (c *Client) handleWolCmd(sendFrame func(protocol.ControlFrame) error, frame protocol.ControlFrame) {
	err := c.opts.WoLHandler(frame.MAC, frame.BroadcastIP)
	_ = sendFrame(protocol.ControlFrame{
		Type:  "wol-ack",
		ReqID: frame.ReqID,
		OK:    err == nil,
		Error: errString(err),
	})
}

// DialUpgrade opens a raw TCP/TLS HTTP/1.1 Upgrade connection to the Hub.
func DialUpgrade(ctx context.Context, baseURL, pathWithQuery, token, proto string) (net.Conn, *bufio.Reader, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	basePath := strings.TrimRight(u.Path, "/")
	reqTarget := basePath + pathWithQuery

	reqStr := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nAuthorization: Bearer %s\r\n\r\n",
		reqTarget,
		u.Host,
		proto,
		token,
	)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("hub upgrade failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br, nil
}

// PipeStdioToProxy opens a proxied SSH stream for a target node and pipes it over stdin/stdout (OpenSSH ProxyCommand).
func PipeStdioToProxy(ctx context.Context, hubURL, token, nodeID string) error {
	conn, br, err := DialUpgrade(ctx, hubURL, "/tunnel/client-proxy?node_id="+url.QueryEscape(nodeID), token, "ssh-fleet-proxy")
	if err != nil {
		return err
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	go func() {
		defer wg.Done()
		_, e := io.Copy(os.Stdout, br)
		errCh <- e
	}()
	go func() {
		defer wg.Done()
		_, e := io.Copy(conn, os.Stdin)
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		errCh <- e
	}()

	err = <-errCh
	_ = conn.Close()
	return err
}

// GenerateServiceFile returns OS-native background service unit contents and target file path.
func GenerateServiceFile(goos, binPath, hubURL, token, nodeID, nodeName string, sshPort int) (targetPath string, content string, hint string, err error) {
	home, _ := os.UserHomeDir()
	switch goos {
	case "linux":
		targetPath = filepath.Join(home, ".config", "systemd", "user", "ssh-fleet-agent.service")
		content = fmt.Sprintf(`[Unit]
Description=ssh-fleet device agent (%s)
After=network-online.target

[Service]
Type=simple
ExecStart="%s" agent --hub "%s" --token "%s" --node-id "%s" --name "%s" --ssh-port %d
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, nodeName, binPath, hubURL, token, nodeID, nodeName, sshPort)
		hint = "systemctl --user daemon-reload && systemctl --user enable --now ssh-fleet-agent"
		return targetPath, content, hint, nil
	case "darwin":
		targetPath = filepath.Join(home, "Library", "LaunchAgents", "com.sshfleet.agent.plist")
		content = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.sshfleet.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>agent</string>
    <string>--hub</string><string>%s</string>
    <string>--token</string><string>%s</string>
    <string>--node-id</string><string>%s</string>
    <string>--name</string><string>%s</string>
    <string>--ssh-port</string><string>%d</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, binPath, hubURL, token, nodeID, nodeName, sshPort)
		hint = "launchctl load -w " + targetPath
		return targetPath, content, hint, nil
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		targetPath = filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "ssh-fleet-agent.vbs")
		cmdLine := fmt.Sprintf(`\"%s\" agent --hub \"%s\" --token \"%s\" --node-id \"%s\" --name \"%s\" --ssh-port %d`, binPath, hubURL, token, nodeID, nodeName, sshPort)
		content = fmt.Sprintf("Set WshShell = CreateObject(\"WScript.Shell\")\r\nWshShell.Run \"%s\", 0, False\r\n", cmdLine)
		hint = "Double-click or reboot to start automatically via Windows Startup folder"
		return targetPath, content, hint, nil
	default:
		return "", "", "", fmt.Errorf("unsupported OS %s", goos)
	}
}

func spliceBuffered(local net.Conn, remote net.Conn, remoteReader *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, remoteReader)
		if tc, ok := local.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
		if tc, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	_ = local.Close()
	_ = remote.Close()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
