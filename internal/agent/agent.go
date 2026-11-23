package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"ssh-fleet/internal/keyring"
	"ssh-fleet/internal/power"
	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/updater"
	"ssh-fleet/internal/version"
	"ssh-fleet/internal/wol"
	"ssh-fleet/internal/ws"
)

type Options struct {
	HubURL            string
	Token             string
	CFClientID        string
	CFClientSecret    string
	NodeID            string
	Name              string
	SSHPort           int
	SSHUser           string
	IsVPS             *bool
	Power             *power.Manager
	Keyring           keyring.Handler
	WoLHandler        func(mac, broadcastIP string) error
	NetworkInfoFn     func() ([]wol.NetInterfaceInfo, error)
	UpdateFn          func(context.Context) (updater.Result, error)
	OnUpdated         func(string)
	PingInterval      time.Duration
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	AuthBackoffDelay  time.Duration
}

type Client struct {
	opts               Options
	power              *power.Manager
	keyring            keyring.Handler
	isVPS              bool
	suspendMu          sync.Mutex
	reconnectHoldUntil time.Time
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
	if opts.Keyring == nil {
		opts.Keyring = keyring.NewOSHandler()
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
	if opts.MaxReconnectDelay <= 0 {
		opts.MaxReconnectDelay = 60 * time.Second
	}
	if opts.MaxReconnectDelay < opts.ReconnectDelay {
		opts.MaxReconnectDelay = opts.ReconnectDelay
	}
	if opts.AuthBackoffDelay <= 0 {
		opts.AuthBackoffDelay = 30 * time.Second
	}
	isVPS := DetectIsVPS()
	if opts.IsVPS != nil {
		isVPS = *opts.IsVPS
	}
	return &Client{opts: opts, power: opts.Power, keyring: opts.Keyring, isVPS: isVPS}, nil
}

// DetectIsVPS reports whether the host is running inside a cloud VM / hypervisor / container.
func DetectIsVPS() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, p := range []string{
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_vendor",
		"/sys/hypervisor/type",
	} {
		if b, err := os.ReadFile(p); err == nil {
			val := strings.ToLower(string(b))
			for _, sig := range []string{
				"qemu", "kvm", "vmware", "virtualbox", "xen", "bochs",
				"parallels", "amazon ec2", "google", "digitalocean", "hetzner",
				"openstack", "linode", "vultr", "microsoft corporation", "virtuozzo",
			} {
				if strings.Contains(val, sig) {
					return true
				}
			}
		}
	}
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		v := strings.ToLower(strings.TrimSpace(string(out)))
		if v != "" && v != "none" {
			return true
		}
	}
	return false
}

func (c *Client) setReconnectHold(d time.Duration) {
	until := time.Now().Add(d)
	c.suspendMu.Lock()
	if until.After(c.reconnectHoldUntil) {
		c.reconnectHoldUntil = until
	}
	c.suspendMu.Unlock()
}

func (c *Client) waitReconnectHold(ctx context.Context) error {
	c.suspendMu.Lock()
	until := c.reconnectHoldUntil
	c.suspendMu.Unlock()
	if wait := time.Until(until); wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	attempt := 0
	for {
		if err := c.waitReconnectHold(ctx); err != nil {
			c.power.Close()
			return err
		}
		registered, err := c.connectOnce(ctx)
		if registered {
			attempt = 0
		}
		if ctx.Err() != nil {
			c.power.Close()
			return ctx.Err()
		}
		if err != nil {
			var delay time.Duration
			var uerr *ws.UpgradeError
			if errors.As(err, &uerr) && (uerr.StatusCode == http.StatusUnauthorized || uerr.StatusCode == http.StatusForbidden) {
				delay = c.opts.AuthBackoffDelay
			} else {
				shift := attempt
				if shift > 6 {
					shift = 6
				}
				delay = c.opts.ReconnectDelay << shift
				if delay <= 0 || delay > c.opts.MaxReconnectDelay {
					delay = c.opts.MaxReconnectDelay
				}
				attempt++
			}
			delay = jitterDuration(delay)
			// Keep reconnecting reliably across Wi-Fi / sleep transitions.
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				c.power.Close()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

func jitterDuration(d time.Duration) time.Duration {
	if d < 20*time.Millisecond {
		return d
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d
	}
	delta := (int64(b[0])*2 - 255) * int64(d) / (255 * 5)
	out := d + time.Duration(delta)
	if out <= 0 {
		return d
	}
	return out
}

func (c *Client) probeKeyringLocked(ctx context.Context) *bool {
	if c.keyring == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.keyring.IsLocked(probeCtx)
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
		NodeID:        c.opts.NodeID,
		Name:          c.opts.Name,
		Version:       version.Version,
		Hostname:      host,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		SSHUser:       c.opts.SSHUser,
		SSHPort:       c.opts.SSHPort,
		LocalIPs:      ips,
		SubnetCIDRs:   subnets,
		MACAddrs:      macs,
		BroadcastIP:   bcast,
		PowerState:    c.power.State(),
		Online:        true,
		IsVPS:         c.isVPS,
		KeyringLocked: c.probeKeyringLocked(context.Background()),
	}
}

func (c *Client) connectOnce(ctx context.Context) (bool, error) {
	conn, br, err := DialUpgradeWithHeaders(ctx, c.opts.HubURL, "/tunnel/control", c.opts.Token, "ssh-fleet-control", c.cfHeaders())
	if err != nil {
		return false, err
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
		return false, err
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
					Type:          "ping",
					PowerState:    c.power.State(),
					KeyringLocked: c.probeKeyringLocked(ctx),
				}); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	readTimeout := 3 * c.opts.PingInterval
	if readTimeout <= 0 {
		readTimeout = 45 * time.Second
	}

	registered := false
	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		if !scanner.Scan() {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var frame protocol.ControlFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			continue
		}

		switch frame.Type {
		case "pong", "register-ack":
			registered = true
		case "replaced":
			c.setReconnectHold(20 * time.Second)
			_ = conn.Close()
			return registered, errors.New("connection replaced by another agent with same node_id")
		case "open-ssh-stream":
			go c.handleOpenStream(ctx, sendFrame, frame.StreamID)
		case "open-shell-stream":
			go c.handleOpenShellStream(ctx, sendFrame, frame.StreamID, frame.Cols, frame.Rows)
		case "open-exec-stream":
			go c.handleOpenExecStream(ctx, sendFrame, frame.StreamID)
		case "power-cmd":
			go c.handlePowerCmd(sendFrame, func() { _ = conn.Close() }, frame)
		case "wol-cmd":
			go c.handleWolCmd(sendFrame, frame)
		case "unlock-keyring":
			go c.handleUnlockKeyring(ctx, sendFrame, frame)
		case "self-update":
			go c.handleSelfUpdate(ctx, sendFrame, func() { _ = conn.Close() }, frame)
		}
	}

	if err := scanner.Err(); err != nil {
		return registered, err
	}
	return registered, io.EOF
}

func (c *Client) cfHeaders() map[string]string {
	h := map[string]string{}
	if strings.TrimSpace(c.opts.CFClientID) != "" {
		h["CF-Access-Client-Id"] = c.opts.CFClientID
	}
	if strings.TrimSpace(c.opts.CFClientSecret) != "" {
		h["CF-Access-Client-Secret"] = c.opts.CFClientSecret
	}
	return h
}

func (c *Client) handleOpenStream(ctx context.Context, sendFrame func(protocol.ControlFrame) error, streamID string) {
	if streamID == "" {
		return
	}
	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", c.opts.SSHPort), 5*time.Second)
	if err != nil {
		_ = sendFrame(protocol.ControlFrame{
			Type:     "stream-error",
			StreamID: streamID,
			Error:    fmt.Sprintf("local ssh port %d unreachable: %v", c.opts.SSHPort, err),
		})
		return
	}

	remoteConn, br, err := DialUpgradeWithHeaders(ctx, c.opts.HubURL, "/tunnel/agent-stream?stream_id="+url.QueryEscape(streamID), c.opts.Token, "ssh-fleet-stream", c.cfHeaders())
	if err != nil {
		_ = localConn.Close()
		_ = sendFrame(protocol.ControlFrame{
			Type:     "stream-error",
			StreamID: streamID,
			Error:    err.Error(),
		})
		return
	}

	spliceBuffered(localConn, remoteConn, br)
}

func (c *Client) handleOpenShellStream(ctx context.Context, sendFrame func(protocol.ControlFrame) error, streamID string, cols, rows int) {
	if streamID == "" {
		return
	}
	remoteConn, br, err := DialUpgradeWithHeaders(ctx, c.opts.HubURL, "/tunnel/agent-stream?stream_id="+url.QueryEscape(streamID), c.opts.Token, "ssh-fleet-stream", c.cfHeaders())
	if err != nil {
		_ = sendFrame(protocol.ControlFrame{
			Type:     "stream-error",
			StreamID: streamID,
			Error:    err.Error(),
		})
		return
	}
	defer remoteConn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = remoteConn.Close()
		case <-done:
		}
	}()

	cmd := buildInteractiveShellCmd(cols, rows)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(remoteConn, "failed to start shell: %v\r\n", err)
		return
	}

	var writeM sync.Mutex
	safeWrite := func(p []byte) error {
		writeM.Lock()
		defer writeM.Unlock()
		_, wErr := remoteConn.Write(p)
		return wErr
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rErr := stdout.Read(buf)
			if n > 0 {
				if err := safeWrite(buf[:n]); err != nil {
					_ = remoteConn.Close()
					break
				}
			}
			if rErr != nil {
				break
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rErr := stderr.Read(buf)
			if n > 0 {
				if err := safeWrite(buf[:n]); err != nil {
					_ = remoteConn.Close()
					break
				}
			}
			if rErr != nil {
				break
			}
		}
	}()

	pipesDone := make(chan struct{})
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		_, _ = io.Copy(stdin, br)
		_ = stdin.Close()
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-pipesDone:
			return
		case <-timer.C:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = remoteConn.Close()
		}
	}()

	wg.Wait()
	close(pipesDone)
	_ = remoteConn.Close()
	<-stdinDone
	_ = cmd.Wait()
}

func isSafeShellPath(sh string) bool {
	if sh == "" {
		return false
	}
	return !strings.ContainsAny(sh, " \t\r\n;&|$`'\"<>()\\")
}

func setEnvEntry(base []string, key, val string, overwrite bool) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	seen := false
	for _, entry := range base {
		if strings.HasPrefix(entry, prefix) {
			if !seen {
				existing := strings.TrimSpace(strings.TrimPrefix(entry, prefix))
				if !overwrite && existing != "" {
					out = append(out, entry)
				} else {
					out = append(out, prefix+val)
				}
				seen = true
			}
			continue
		}
		out = append(out, entry)
	}
	if !seen {
		out = append(out, prefix+val)
	}
	return out
}

func shellEnv(base []string) []string {
	env := setEnvEntry(base, "TERM", "xterm-256color", true)
	env = setEnvEntry(env, "COLORTERM", "truecolor", true)
	env = setEnvEntry(env, "LANG", "en_US.UTF-8", false)
	return env
}

func clampTermSize(cols, rows int) (int, int) {
	if cols <= 0 || rows <= 0 {
		return 0, 0
	}
	if cols < 20 {
		cols = 20
	} else if cols > 500 {
		cols = 500
	}
	if rows < 5 {
		rows = 5
	} else if rows > 200 {
		rows = 200
	}
	return cols, rows
}

func buildInteractiveShellCmd(cols, rows int) *exec.Cmd {
	cols, rows = clampTermSize(cols, rows)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell.exe", "-NoLogo")
	case "darwin":
		sh := strings.TrimSpace(os.Getenv("SHELL"))
		if !isSafeShellPath(sh) {
			sh = "/bin/zsh"
		}
		if _, err := exec.LookPath("script"); err == nil {
			if cols > 0 && rows > 0 {
				cmd = exec.Command("script", "-q", "/dev/null", sh, "-c", fmt.Sprintf("stty cols %d rows %d 2>/dev/null; exec %s -i", cols, rows, sh))
			} else {
				cmd = exec.Command("script", "-q", "/dev/null", sh, "-i")
			}
		} else {
			cmd = exec.Command(sh, "-i")
		}
	default:
		sh := strings.TrimSpace(os.Getenv("SHELL"))
		if !isSafeShellPath(sh) {
			if _, err := exec.LookPath("bash"); err == nil {
				sh = "/bin/bash"
			} else {
				sh = "/bin/sh"
			}
		}
		if _, err := exec.LookPath("script"); err == nil {
			if cols > 0 && rows > 0 {
				cmd = exec.Command("script", "-q", "-c", fmt.Sprintf("stty cols %d rows %d 2>/dev/null; exec %s -i", cols, rows, sh), "/dev/null")
			} else {
				cmd = exec.Command("script", "-q", "-c", sh+" -i", "/dev/null")
			}
		} else {
			cmd = exec.Command(sh, "-i")
		}
	}
	cmd.Env = shellEnv(os.Environ())
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cmd.Dir = home
	}
	return cmd
}

func resolveExecDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return ""
	}
	if dir == "~" || strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if dir == "~" {
				return home
			}
			return filepath.Join(home, dir[2:])
		}
	}
	return dir
}

func buildExecCmd(command string) *exec.Cmd {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	} else if bash, err := exec.LookPath("bash"); err == nil {
		cmd = exec.Command(bash, "-c", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	cmd.Env = os.Environ()
	return cmd
}

func (c *Client) handleOpenExecStream(ctx context.Context, sendFrame func(protocol.ControlFrame) error, streamID string) {
	if streamID == "" {
		return
	}
	remoteConn, br, err := DialUpgradeWithHeaders(ctx, c.opts.HubURL, "/tunnel/agent-stream?stream_id="+url.QueryEscape(streamID), c.opts.Token, "ssh-fleet-stream", c.cfHeaders())
	if err != nil {
		_ = sendFrame(protocol.ControlFrame{
			Type:     "stream-error",
			StreamID: streamID,
			Error:    err.Error(),
		})
		return
	}
	defer remoteConn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = remoteConn.Close()
		case <-done:
		}
	}()

	var writeM sync.Mutex
	writeFrame := func(frameType byte, payload []byte) error {
		writeM.Lock()
		defer writeM.Unlock()
		return protocol.WriteExecFrame(remoteConn, frameType, payload)
	}
	sendExit := func(code int, errMsg string) {
		b, _ := json.Marshal(protocol.ExecExitPayload{Code: code, Error: errMsg})
		_ = writeFrame(protocol.ExecFrameExit, b)
	}

	_ = remoteConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	firstType, firstPayload, fErr := protocol.ReadExecFrame(br)
	_ = remoteConn.SetReadDeadline(time.Time{})
	if fErr != nil {
		sendExit(2, fmt.Sprintf("failed to read exec request: %v", fErr))
		return
	}
	if firstType != protocol.ExecFrameStart {
		sendExit(2, fmt.Sprintf("expected start frame, got 0x%02x", firstType))
		return
	}
	var req protocol.ExecStartRequest
	if err := json.Unmarshal(firstPayload, &req); err != nil {
		sendExit(2, fmt.Sprintf("invalid exec request: %v", err))
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		sendExit(2, "empty command")
		return
	}

	cmd := buildExecCmd(req.Command)
	if dir := resolveExecDir(req.Dir); dir != "" {
		cmd.Dir = dir
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		sendExit(126, err.Error())
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendExit(126, err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sendExit(126, err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		sendExit(126, err.Error())
		return
	}

	pipeStream := func(r io.Reader, frameType byte, wg *sync.WaitGroup) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rErr := r.Read(buf)
			if n > 0 {
				if wErr := writeFrame(frameType, buf[:n]); wErr != nil {
					_ = remoteConn.Close()
					return
				}
			}
			if rErr != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pipeStream(stdout, protocol.ExecFrameStdout, &wg)
	go pipeStream(stderr, protocol.ExecFrameStderr, &wg)

	pipesDone := make(chan struct{})
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		for {
			ft, payload, rErr := protocol.ReadExecFrame(br)
			if rErr != nil {
				_ = stdin.Close()
				timer := time.NewTimer(250 * time.Millisecond)
				select {
				case <-pipesDone:
					timer.Stop()
				case <-timer.C:
					if cmd.Process != nil {
						_ = cmd.Process.Kill()
					}
					_ = remoteConn.Close()
				}
				return
			}
			switch ft {
			case protocol.ExecFrameStdin:
				if len(payload) > 0 {
					_, _ = stdin.Write(payload)
				}
			case protocol.ExecFrameEOF:
				_ = stdin.Close()
			case protocol.ExecFrameCancel:
				_ = stdin.Close()
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
			}
		}
	}()

	wg.Wait()
	close(pipesDone)
	waitErr := cmd.Wait()
	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	sendExit(exitCode, "")
	_ = remoteConn.Close()
	<-stdinDone
}

func (c *Client) handlePowerCmd(sendFrame func(protocol.ControlFrame) error, closeConn func(), frame protocol.ControlFrame) {
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
		if c.isVPS {
			_ = sendFrame(protocol.ControlFrame{
				Type:       "power-ack",
				ReqID:      frame.ReqID,
				OK:         false,
				PowerState: c.power.State(),
				Error:      "refusing to sleep a VPS / virtual machine",
			})
			return
		}
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
		if c.isVPS {
			_ = sendFrame(protocol.ControlFrame{
				Type:       "power-ack",
				ReqID:      frame.ReqID,
				OK:         false,
				PowerState: c.power.State(),
				Error:      "refusing to hard-sleep a VPS / virtual machine",
			})
			return
		}
		c.setReconnectHold(1750 * time.Millisecond)
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         true,
			PowerState: protocol.PowerSleeping,
		})
		_ = c.power.PrepareHardSleep(250*time.Millisecond, closeConn)
	case protocol.ActionPowerOff:
		if c.isVPS {
			_ = sendFrame(protocol.ControlFrame{
				Type:       "power-ack",
				ReqID:      frame.ReqID,
				OK:         false,
				PowerState: c.power.State(),
				Error:      "refusing to power off a VPS / virtual machine",
			})
			return
		}
		if err := c.power.CheckPowerOff(); err != nil {
			_ = sendFrame(protocol.ControlFrame{
				Type:       "power-ack",
				ReqID:      frame.ReqID,
				OK:         false,
				PowerState: c.power.State(),
				Error:      err.Error(),
			})
			return
		}
		c.setReconnectHold(15 * time.Second)
		_ = sendFrame(protocol.ControlFrame{
			Type:       "power-ack",
			ReqID:      frame.ReqID,
			OK:         true,
			PowerState: protocol.PowerOffline,
		})
		_ = c.power.PreparePowerOff(250*time.Millisecond, closeConn)
	default:
		_ = sendFrame(protocol.ControlFrame{
			Type:  "power-ack",
			ReqID: frame.ReqID,
			OK:    false,
			Error: fmt.Sprintf("unknown power action: %s", frame.Action),
		})
	}
}

func (c *Client) handleUnlockKeyring(ctx context.Context, sendFrame func(protocol.ControlFrame) error, frame protocol.ControlFrame) {
	unlockCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	var res keyring.Result
	if c.keyring == nil {
		res = keyring.Result{OK: false, KeyringLocked: true, Error: "keyring handler unavailable"}
	} else {
		res = c.keyring.Unlock(unlockCtx, frame.Password)
	}
	locked := res.KeyringLocked
	_ = sendFrame(protocol.ControlFrame{
		Type:          "unlock-keyring-ack",
		ReqID:         frame.ReqID,
		OK:            res.OK,
		KeyringLocked: &locked,
		Error:         res.Error,
	})
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

func (c *Client) handleSelfUpdate(ctx context.Context, sendFrame func(protocol.ControlFrame) error, closeConn func(), frame protocol.ControlFrame) {
	updCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var res updater.Result
	var err error
	if c.opts.UpdateFn != nil {
		res, err = c.opts.UpdateFn(updCtx)
	} else {
		res, err = updater.CheckAndApply(updCtx, updater.Options{
			CurrentVersion:  version.Version,
			RequireChecksum: true,
		})
	}
	_ = sendFrame(protocol.ControlFrame{
		Type:    "self-update-ack",
		ReqID:   frame.ReqID,
		OK:      err == nil,
		Updated: res.Updated,
		Version: res.LatestVersion,
		Error:   errString(err),
	})
	if err == nil && res.Updated {
		time.AfterFunc(250*time.Millisecond, func() {
			if c.opts.OnUpdated != nil {
				c.opts.OnUpdated(res.BinaryPath)
				return
			}
			if closeConn != nil {
				closeConn()
			}
			c.power.Close()
			_ = updater.ReExec(res.BinaryPath)
		})
	}
}

// DialUpgrade opens a raw TCP/TLS HTTP/1.1 Upgrade connection to the Hub.
func DialUpgrade(ctx context.Context, baseURL, pathWithQuery, token, proto string) (net.Conn, *bufio.Reader, error) {
	return DialUpgradeWithHeaders(ctx, baseURL, pathWithQuery, token, proto, nil)
}

// DialUpgradeWithHeaders opens an RFC 6455 WebSocket tunnel to the Hub with Bearer auth and optional headers (e.g. Cloudflare Access Service Token).
func DialUpgradeWithHeaders(ctx context.Context, baseURL, pathWithQuery, token, _ string, extraHeaders map[string]string) (net.Conn, *bufio.Reader, error) {
	conn, err := ws.DialClient(ctx, baseURL, pathWithQuery, token, extraHeaders)
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

// PipeStdioToProxy opens a proxied SSH stream for a target node and pipes it over stdin/stdout (OpenSSH ProxyCommand).
func PipeStdioToProxy(ctx context.Context, hubURL, token, nodeID string, cfHeaders ...map[string]string) error {
	var extra map[string]string
	if len(cfHeaders) > 0 {
		extra = cfHeaders[0]
	}
	conn, br, err := DialUpgradeWithHeaders(ctx, hubURL, "/tunnel/client-proxy?node_id="+url.QueryEscape(nodeID), token, "ssh-fleet-proxy", extra)
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

// RunInteractiveShell opens a direct interactive shell stream on a target node without requiring sshd.
func RunInteractiveShell(ctx context.Context, hubURL, token, nodeID string, cols, rows int, stdin io.Reader, stdout io.Writer, cfHeaders ...map[string]string) error {
	var extra map[string]string
	if len(cfHeaders) > 0 {
		extra = cfHeaders[0]
	}
	if stdout == nil {
		stdout = io.Discard
	}
	path := "/tunnel/client-shell?node_id=" + url.QueryEscape(nodeID)
	if cols > 0 && rows > 0 {
		path += fmt.Sprintf("&cols=%d&rows=%d", cols, rows)
	}
	conn, br, err := DialUpgradeWithHeaders(ctx, hubURL, path, token, "ssh-fleet-shell", extra)
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if stdin != nil {
		go func() {
			_, _ = io.Copy(conn, stdin)
		}()
	}

	_, copyErr := io.Copy(stdout, br)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return copyErr
}

// RunRemoteExec executes a non-interactive command on a target node over the agent tunnel,
// streaming stdout/stderr separately and returning the remote exit code.
func RunRemoteExec(ctx context.Context, hubURL, token, nodeID string, req protocol.ExecStartRequest, stdin io.Reader, stdout, stderr io.Writer, cfHeaders ...map[string]string) (int, error) {
	var extra map[string]string
	if len(cfHeaders) > 0 {
		extra = cfHeaders[0]
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	path := "/tunnel/client-exec?node_id=" + url.QueryEscape(nodeID)
	conn, br, err := DialUpgradeWithHeaders(ctx, hubURL, path, token, "ssh-fleet-exec", extra)
	if err != nil {
		return 1, err
	}
	defer conn.Close()

	var writeM sync.Mutex
	writeFrame := func(frameType byte, payload []byte) error {
		writeM.Lock()
		defer writeM.Unlock()
		return protocol.WriteExecFrame(conn, frameType, payload)
	}

	startPayload, err := json.Marshal(req)
	if err != nil {
		return 2, err
	}
	if err := writeFrame(protocol.ExecFrameStart, startPayload); err != nil {
		return 1, err
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = writeFrame(protocol.ExecFrameCancel, nil)
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		case <-done:
		}
	}()

	if stdin != nil {
		go func() {
			buf := make([]byte, 32*1024)
			for {
				select {
				case <-done:
					return
				default:
				}
				n, rErr := stdin.Read(buf)
				if n > 0 {
					if wErr := writeFrame(protocol.ExecFrameStdin, buf[:n]); wErr != nil {
						return
					}
				}
				if rErr != nil {
					_ = writeFrame(protocol.ExecFrameEOF, nil)
					return
				}
			}
		}()
	} else {
		if err := writeFrame(protocol.ExecFrameEOF, nil); err != nil {
			return 1, err
		}
	}

	for {
		ft, payload, rErr := protocol.ReadExecFrame(br)
		if rErr != nil {
			if ctx.Err() != nil {
				return 130, ctx.Err()
			}
			return 1, rErr
		}
		switch ft {
		case protocol.ExecFrameStdout:
			if len(payload) > 0 {
				if _, wErr := stdout.Write(payload); wErr != nil {
					return 1, wErr
				}
			}
		case protocol.ExecFrameStderr:
			if len(payload) > 0 {
				if _, wErr := stderr.Write(payload); wErr != nil {
					return 1, wErr
				}
			}
		case protocol.ExecFrameExit:
			var exitPayload protocol.ExecExitPayload
			if err := json.Unmarshal(payload, &exitPayload); err != nil {
				return 1, fmt.Errorf("invalid exit payload: %w", err)
			}
			if exitPayload.Error != "" {
				return exitPayload.Code, errors.New(exitPayload.Error)
			}
			return exitPayload.Code, nil
		}
	}
}

// GenerateServiceFile returns OS-native background service unit contents and target file path.
// It delegates runtime configuration to `config.json` (`0600`) so tokens and CF secrets never appear in `ps aux`.
func GenerateServiceFile(goos, binPath, hubURL, token, nodeID, nodeName string, sshPort int) (targetPath string, content string, hint string, err error) {
	home, _ := os.UserHomeDir()
	_, _, _, _ = hubURL, token, nodeID, sshPort
	switch goos {
	case "linux":
		targetPath = filepath.Join(home, ".config", "systemd", "user", "ssh-fleet-agent.service")
		content = fmt.Sprintf(`[Unit]
Description=ssh-fleet device agent (%s)
After=network-online.target

[Service]
Type=simple
ExecStart="%s" agent
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, nodeName, binPath)
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
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, binPath)
		hint = "launchctl load -w " + targetPath
		return targetPath, content, hint, nil
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		targetPath = filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "ssh-fleet-agent.vbs")
		cmdLine := fmt.Sprintf(`\"%s\" agent`, binPath)
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
		} else {
			_ = local.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
		if tc, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = remote.Close()
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
