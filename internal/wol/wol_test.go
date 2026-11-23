package wol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestBuildMagicPacket(t *testing.T) {
	pkt, err := BuildMagicPacket("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("BuildMagicPacket failed: %v", err)
	}
	if len(pkt) != 102 {
		t.Fatalf("expected 102 bytes, got %d", len(pkt))
	}

	for i := 0; i < 6; i++ {
		if pkt[i] != 0xFF {
			t.Fatalf("header byte %d = %x, want 0xFF", i, pkt[i])
		}
	}

	wantMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for i := 1; i <= 16; i++ {
		chunk := pkt[i*6 : (i+1)*6]
		if !bytes.Equal(chunk, wantMAC) {
			t.Fatalf("repetition %d = %x, want %x", i, chunk, wantMAC)
		}
	}

	if _, err := BuildMagicPacket("invalid-mac"); err == nil {
		t.Fatalf("expected error for invalid MAC")
	}
}

func TestSendMagicPacketLoopbackUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error: %v", err)
	}
	defer pc.Close()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	if err := SendMagicPacket("11-22-33-44-55-66", "127.0.0.1", port); err != nil {
		t.Fatalf("SendMagicPacket error: %v", err)
	}

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != 102 {
		t.Fatalf("received %d bytes, want 102", n)
	}

	want, _ := BuildMagicPacket("11:22:33:44:55:66")
	if !bytes.Equal(buf[:n], want[:]) {
		t.Fatalf("received packet mismatch")
	}
}

func TestIsVirtualInterfaceName(t *testing.T) {
	for _, virt := range []string{"docker0", "br-4159b85017e1", "vethaa72bc9", "CloudflareWARP", "tun0", "wg0", "lo"} {
		if !IsVirtualInterfaceName(virt) {
			t.Fatalf("expected %q to be classified as virtual interface", virt)
		}
	}
	for _, phys := range []string{"enp3s0", "eth0", "wlan0", "en0"} {
		if IsVirtualInterfaceName(phys) {
			t.Fatalf("expected %q not to be classified as virtual interface", phys)
		}
	}
}
