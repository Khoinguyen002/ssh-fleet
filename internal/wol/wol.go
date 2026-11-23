package wol

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type NetInterfaceInfo struct {
	Name        string `json:"name"`
	MAC         string `json:"mac"`
	IPv4        string `json:"ipv4"`
	SubnetCIDR  string `json:"subnet_cidr"`
	BroadcastIP string `json:"broadcast_ip"`
}

// ParseMAC parses a MAC address in colon, hyphen, or plain hex notation into 6 bytes.
func ParseMAC(macAddr string) ([6]byte, error) {
	var out [6]byte
	cleaned := strings.TrimSpace(macAddr)
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")
	if len(cleaned) != 12 {
		return out, fmt.Errorf("invalid MAC address %q", macAddr)
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil || len(b) != 6 {
		return out, fmt.Errorf("invalid MAC address %q: %v", macAddr, err)
	}
	copy(out[:], b)
	return out, nil
}

// BuildMagicPacket constructs a standard 102-byte Wake-on-LAN magic packet.
func BuildMagicPacket(macAddr string) ([102]byte, error) {
	var pkt [102]byte
	mac, err := ParseMAC(macAddr)
	if err != nil {
		return pkt, err
	}
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	for i := 1; i <= 16; i++ {
		copy(pkt[i*6:(i+1)*6], mac[:])
	}
	return pkt, nil
}

// SendMagicPacket broadcasts a 102-byte WoL magic packet via UDP to the given broadcast IP and ports.
func SendMagicPacket(macAddr, broadcastIP string, ports ...int) error {
	pkt, err := BuildMagicPacket(macAddr)
	if err != nil {
		return err
	}
	if strings.TrimSpace(broadcastIP) == "" {
		broadcastIP = "255.255.255.255"
	}
	if len(ports) == 0 {
		ports = []int{9, 7}
	}

	var firstErr error
	sentAny := false
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", broadcastIP, port)
		udpAddr, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		conn, err := net.DialUDP("udp4", nil, udpAddr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// Send magic packet 3 times with 40ms spacing to guard against UDP drops.
		for attempt := 0; attempt < 3; attempt++ {
			if _, wErr := conn.Write(pkt[:]); wErr != nil {
				if firstErr == nil {
					firstErr = wErr
				}
			} else {
				sentAny = true
			}
			if attempt < 2 {
				time.Sleep(40 * time.Millisecond)
			}
		}
		_ = conn.Close()
	}

	if !sentAny && firstErr != nil {
		return firstErr
	}
	return nil
}

// IsVirtualInterfaceName reports whether an interface name belongs to a Docker/VPN/virtual bridge rather than physical NIC.
func IsVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, p := range []string{
		"lo", "docker", "br-", "veth", "virbr", "tun", "tap",
		"wg", "tailscale", "cloudflare", "vmnet", "vboxnet", "zt", "utun", "awdl",
	} {
		if lower == p || strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func interfacePriority(name string) int {
	lower := strings.ToLower(name)
	for _, p := range []string{"enp", "eth", "eno", "ens", "em"} {
		if strings.HasPrefix(lower, p) {
			return 0
		}
	}
	if strings.HasPrefix(lower, "wl") {
		return 1
	}
	return 2
}

func isPhysicalSysfsNIC(name string) bool {
	if runtime.GOOS != "linux" {
		return !IsVirtualInterfaceName(name)
	}
	_, err := os.Stat(filepath.Join("/sys/class/net", name, "device"))
	return err == nil
}

// DetectNetworkInterfaces returns active, non-virtual IPv4 interfaces prioritized by physical Ethernet NIC first.
func DetectNetworkInterfaces() ([]NetInterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var physical []NetInterfaceInfo
	var fallback []NetInterfaceInfo

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsVirtualInterfaceName(iface.Name) {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		isPhys := isPhysicalSysfsNIC(iface.Name)
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || len(ipNet.Mask) != 4 {
				continue
			}

			networkIP := ip4.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			bcast := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				bcast[i] = networkIP[i] | ^ipNet.Mask[i]
			}

			item := NetInterfaceInfo{
				Name:        iface.Name,
				MAC:         iface.HardwareAddr.String(),
				IPv4:        ip4.String(),
				SubnetCIDR:  fmt.Sprintf("%s/%d", networkIP.String(), ones),
				BroadcastIP: bcast.String(),
			}
			if isPhys {
				physical = append(physical, item)
			} else {
				fallback = append(fallback, item)
			}
		}
	}

	out := physical
	if len(out) == 0 {
		out = fallback
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := interfacePriority(out[i].Name), interfacePriority(out[j].Name)
		if pi != pj {
			return pi < pj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
