package wol

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
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
		_, wErr := conn.Write(pkt[:])
		_ = conn.Close()
		if wErr != nil {
			if firstErr == nil {
				firstErr = wErr
			}
			continue
		}
		sentAny = true
	}

	if !sentAny && firstErr != nil {
		return firstErr
	}
	return nil
}

// DetectNetworkInterfaces returns active, non-loopback IPv4 interfaces with MAC, subnet CIDR, and broadcast IP.
func DetectNetworkInterfaces() ([]NetInterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []NetInterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
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

			out = append(out, NetInterfaceInfo{
				Name:        iface.Name,
				MAC:         iface.HardwareAddr.String(),
				IPv4:        ip4.String(),
				SubnetCIDR:  fmt.Sprintf("%s/%d", networkIP.String(), ones),
				BroadcastIP: bcast.String(),
			})
		}
	}
	return out, nil
}
