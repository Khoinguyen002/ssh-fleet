package power

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssh-fleet/internal/protocol"
)

// Executor abstracts OS power command execution so unit/integration tests can run cleanly without suspending the host.
type Executor interface {
	StartInhibitor() (*exec.Cmd, error)
	SoftSleep() error
	WakeDisplay() error
	HardSleep() error
}

type Manager struct {
	mu          sync.Mutex
	exec        Executor
	inhibitCmd  *exec.Cmd
	keepAwake   bool
	softSleep   bool
	stateChange func(protocol.PowerState)
}

func NewManager(execImpl Executor) *Manager {
	if execImpl == nil {
		execImpl = osExecutor{}
	}
	return &Manager{exec: execImpl}
}

func (m *Manager) OnStateChange(fn func(protocol.PowerState)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateChange = fn
}

func (m *Manager) State() protocol.PowerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentStateLocked()
}

func (m *Manager) currentStateLocked() protocol.PowerState {
	if m.softSleep {
		return protocol.PowerSoftSleep
	}
	if m.keepAwake {
		return protocol.PowerKeepAwake
	}
	return protocol.PowerActive
}

func (m *Manager) notifyLocked() {
	if m.stateChange != nil {
		st := m.currentStateLocked()
		go m.stateChange(st)
	}
}

func (m *Manager) SetKeepAwake(enable bool) (protocol.PowerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if enable {
		if m.inhibitCmd == nil {
			cmd, err := m.exec.StartInhibitor()
			if err == nil && cmd != nil {
				m.inhibitCmd = cmd
			}
		}
		m.keepAwake = true
		m.softSleep = false
		m.notifyLocked()
		return m.currentStateLocked(), nil
	}

	m.stopInhibitorLocked()
	m.keepAwake = false
	m.notifyLocked()
	return m.currentStateLocked(), nil
}

func (m *Manager) SoftSleep() (protocol.PowerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure keep-awake inhibitor is held so the OS keeps Wi-Fi/TCP alive for instant remote wake.
	if m.inhibitCmd == nil {
		cmd, err := m.exec.StartInhibitor()
		if err == nil && cmd != nil {
			m.inhibitCmd = cmd
		}
	}
	m.keepAwake = true
	m.softSleep = true
	err := m.exec.SoftSleep()
	m.notifyLocked()
	return m.currentStateLocked(), err
}

func (m *Manager) Wake() (protocol.PowerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.softSleep = false
	err := m.exec.WakeDisplay()
	m.notifyLocked()
	return m.currentStateLocked(), err
}

// PrepareHardSleep stops inhibitors and schedules OS suspend after a short delay so the ACK frame flushes first.
func (m *Manager) PrepareHardSleep(delay time.Duration) error {
	m.mu.Lock()
	m.stopInhibitorLocked()
	m.keepAwake = false
	m.softSleep = false
	m.mu.Unlock()

	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	time.AfterFunc(delay, func() {
		_ = m.exec.HardSleep()
	})
	return nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopInhibitorLocked()
}

func (m *Manager) stopInhibitorLocked() {
	if m.inhibitCmd != nil && m.inhibitCmd.Process != nil {
		_ = m.inhibitCmd.Process.Kill()
		_ = m.inhibitCmd.Wait()
	}
	m.inhibitCmd = nil
}

type osExecutor struct{}

func (osExecutor) StartInhibitor() (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("systemd-inhibit"); err == nil {
			cmd := exec.Command(
				"systemd-inhibit",
				"--what=idle:sleep:handle-lid-switch",
				"--who=ssh-fleet",
				"--why=KeepAwake",
				"sleep",
				"2147483647",
			)
			if err := cmd.Start(); err == nil {
				return cmd, nil
			}
		}
		return nil, nil
	case "darwin":
		if _, err := exec.LookPath("caffeinate"); err == nil {
			cmd := exec.Command("caffeinate", "-dimsu")
			if err := cmd.Start(); err == nil {
				return cmd, nil
			}
		}
		return nil, nil
	case "windows":
		psScript := `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Power{[DllImport("kernel32.dll")]public static extern uint SetThreadExecutionState(uint esFlags);}'; while($true){[Power]::SetThreadExecutionState(2147483651) | Out-Null; Start-Sleep -Seconds 30}`
		cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
		if err := cmd.Start(); err == nil {
			return cmd, nil
		}
		return nil, nil
	default:
		return nil, nil
	}
}

func (osExecutor) SoftSleep() error {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("loginctl"); err == nil {
			_ = exec.Command("loginctl", "lock-session").Run()
		}
		if _, err := exec.LookPath("xset"); err == nil {
			_ = exec.Command("xset", "dpms", "force", "off").Run()
		}
		return nil
	case "darwin":
		if _, err := exec.LookPath("pmset"); err == nil {
			return exec.Command("pmset", "displaysleepnow").Run()
		}
		return nil
	case "windows":
		psScript := `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{[DllImport("user32.dll")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);}'; [Win]::SendMessage(0xffff,0x0112,0xF170,2) | Out-Null`
		_ = exec.Command("powershell", "-NoProfile", "-Command", psScript).Run()
		return nil
	default:
		return nil
	}
}

func (osExecutor) WakeDisplay() error {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("xset"); err == nil {
			_ = exec.Command("xset", "dpms", "force", "on").Run()
		}
		return nil
	case "darwin":
		if _, err := exec.LookPath("caffeinate"); err == nil {
			return exec.Command("caffeinate", "-u", "-t", "2").Run()
		}
		return nil
	case "windows":
		psScript := `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{[DllImport("user32.dll")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);}'; [Win]::SendMessage(0xffff,0x0112,0xF170,-1) | Out-Null`
		_ = exec.Command("powershell", "-NoProfile", "-Command", psScript).Run()
		return nil
	default:
		return nil
	}
}

func (osExecutor) HardSleep() error {
	switch runtime.GOOS {
	case "linux":
		pid := strconv.Itoa(execPID())
		if _, err := exec.LookPath("pkcheck"); err == nil {
			if err := exec.Command("pkcheck", "--action-id", "org.freedesktop.login1.suspend", "--process", pid).Run(); err == nil {
				if err := exec.Command("pkcheck", "--action-id", "org.freedesktop.login1.inhibit-block-sleep", "--process", pid).Run(); err == nil {
					return exec.Command("systemctl", "suspend", "-i").Run()
				}
				return exec.Command("systemctl", "suspend").Run()
			}
		}
		if err := exec.Command("sudo", "-n", "systemctl", "suspend", "-i").Run(); err == nil {
			return nil
		}
		return exec.Command("systemctl", "suspend").Run()
	case "darwin":
		return exec.Command("pmset", "sleepnow").Run()
	case "windows":
		return exec.Command("rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0").Run()
	default:
		return fmt.Errorf("hard sleep not supported on %s", strings.TrimSpace(runtime.GOOS))
	}
}
