package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssh-fleet/internal/protocol"
)

func TestVaultSaveLoadMaterializeAndSSHConfig(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.enc")
	keysDir := filepath.Join(tmp, "keys")
	sshConfigPath := filepath.Join(tmp, "ssh_config")

	v := NewEmptyVault()
	v.UpsertKey(SSHKeyEntry{
		Name:          "main-ed25519",
		PrivateKeyPEM: "-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEYDATA\n-----END OPENSSH PRIVATE KEY-----",
		PublicKey:     "ssh-ed25519 AAAATEST user@host",
	})
	v.UpsertHost(HostEntry{
		Name:    "prod-vps",
		Host:    "203.0.113.10",
		User:    "ubuntu",
		Port:    2222,
		KeyName: "main-ed25519",
		Tags:    []string{"prod", "vps"},
	})
	v.UpsertHost(HostEntry{
		Name:   "my-laptop",
		User:   "khoi",
		ViaHub: true,
		NodeID: "laptop-123",
		MAC:    "aa:bb:cc:dd:ee:ff",
		Tags:   []string{"personal", "laptop"},
	})

	if err := SaveVaultWithIter(vaultPath, "pass123", v, 1000); err != nil {
		t.Fatalf("SaveVaultWithIter error: %v", err)
	}

	loaded, err := LoadVault(vaultPath, "pass123")
	if err != nil {
		t.Fatalf("LoadVault error: %v", err)
	}
	if len(loaded.Hosts) != 2 || len(loaded.Keys) != 1 {
		t.Fatalf("unexpected loaded counts: hosts=%d keys=%d", len(loaded.Hosts), len(loaded.Keys))
	}

	paths, err := MaterializeKeys(loaded, keysDir)
	if err != nil {
		t.Fatalf("MaterializeKeys error: %v", err)
	}
	keyPath := paths["main-ed25519"]
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key error: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	liveNodes := []protocol.NodeInfo{
		{NodeID: "office-pc-999", Name: "office-pc", SSHUser: "khoi", Online: true},
	}
	block := GenerateSSHConfigBlock(loaded, liveNodes, keysDir, "/usr/local/bin/sf")
	if !strings.Contains(block, "Host prod-vps") || !strings.Contains(block, "HostName 203.0.113.10") || !strings.Contains(block, "Port 2222") {
		t.Fatalf("missing static VPS config in block:\n%s", block)
	}
	if !strings.Contains(block, `ProxyCommand "/usr/local/bin/sf" proxy laptop-123`) {
		t.Fatalf("missing proxy command for hub host:\n%s", block)
	}
	if !strings.Contains(block, `ProxyCommand "/usr/local/bin/sf" proxy office-pc-999`) {
		t.Fatalf("missing live node config:\n%s", block)
	}

	// Write twice to verify idempotent replacement without duplicating blocks.
	_ = os.WriteFile(sshConfigPath, []byte("Host existing\n  HostName 1.2.3.4\n"), 0600)
	if err := SyncSSHConfig(sshConfigPath, block); err != nil {
		t.Fatalf("SyncSSHConfig first error: %v", err)
	}
	if err := SyncSSHConfig(sshConfigPath, block); err != nil {
		t.Fatalf("SyncSSHConfig second error: %v", err)
	}

	finalCfgBytes, _ := os.ReadFile(sshConfigPath)
	finalCfg := string(finalCfgBytes)
	if strings.Count(finalCfg, SSHConfigBeginMarker) != 1 {
		t.Fatalf("expected exactly 1 begin marker, got:\n%s", finalCfg)
	}
	if !strings.Contains(finalCfg, "Host existing") {
		t.Fatalf("existing host config was lost:\n%s", finalCfg)
	}
}
