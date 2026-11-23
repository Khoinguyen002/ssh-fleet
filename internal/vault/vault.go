package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sfcrypto "ssh-fleet/internal/crypto"
	"ssh-fleet/internal/protocol"
)

const (
	SSHConfigBeginMarker = "# --- BEGIN SSH-FLEET ---"
	SSHConfigEndMarker   = "# --- END SSH-FLEET ---"
)

type LocalConfig struct {
	HubURL         string `json:"hub_url"`
	HubToken       string `json:"hub_token"`
	CFClientID     string `json:"cf_client_id,omitempty"`
	CFClientSecret string `json:"cf_client_secret,omitempty"`
	VaultPath      string `json:"vault_path"`
	KeysDir        string `json:"keys_dir"`
	NodeID         string `json:"node_id"`
	AgentName      string `json:"agent_name"`
	SSHPort        int    `json:"ssh_port"`
}

type HostEntry struct {
	Name        string   `json:"name"`
	Host        string   `json:"host,omitempty"`
	User        string   `json:"user,omitempty"`
	Port        int      `json:"port,omitempty"`
	KeyName     string   `json:"key_name,omitempty"`
	ViaHub      bool     `json:"via_hub,omitempty"`
	NodeID      string   `json:"node_id,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	BroadcastIP string   `json:"broadcast_ip,omitempty"`
	RelayNodeID string   `json:"relay_node_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

type SSHKeyEntry struct {
	Name          string    `json:"name"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	PublicKey     string    `json:"public_key,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type VaultData struct {
	Version   int           `json:"version"`
	UpdatedAt time.Time     `json:"updated_at"`
	Hosts     []HostEntry   `json:"hosts"`
	Keys      []SSHKeyEntry `json:"keys"`
}

func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ssh-fleet"), nil
}

func DefaultConfig() (LocalConfig, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return LocalConfig{}, err
	}
	hostName, _ := os.Hostname()
	if hostName == "" {
		hostName = "device"
	}
	return LocalConfig{
		VaultPath: filepath.Join(dir, "vault.enc"),
		KeysDir:   filepath.Join(dir, "keys"),
		NodeID:    sanitizeID(hostName) + "-" + randomHex(3),
		AgentName: hostName,
		SSHPort:   22,
	}, nil
}

func LoadOrInitConfig(path string) (LocalConfig, error) {
	if path == "" {
		dir, err := DefaultConfigDir()
		if err != nil {
			return LocalConfig{}, err
		}
		path = filepath.Join(dir, "config.json")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg, dErr := DefaultConfig()
			if dErr != nil {
				return LocalConfig{}, dErr
			}
			_ = SaveConfig(path, cfg)
			return cfg, nil
		}
		return LocalConfig{}, err
	}

	var cfg LocalConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return LocalConfig{}, err
	}
	def, _ := DefaultConfig()
	if cfg.VaultPath == "" {
		cfg.VaultPath = def.VaultPath
	}
	if cfg.KeysDir == "" {
		cfg.KeysDir = def.KeysDir
	}
	if cfg.NodeID == "" {
		cfg.NodeID = def.NodeID
	}
	if cfg.AgentName == "" {
		cfg.AgentName = def.AgentName
	}
	if cfg.SSHPort <= 0 {
		cfg.SSHPort = 22
	}
	return cfg, nil
}

func SaveConfig(path string, cfg LocalConfig) error {
	if path == "" {
		dir, err := DefaultConfigDir()
		if err != nil {
			return err
		}
		path = filepath.Join(dir, "config.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func NewEmptyVault() *VaultData {
	return &VaultData{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Hosts:     []HostEntry{},
		Keys:      []SSHKeyEntry{},
	}
}

func LoadVault(path, password string) (*VaultData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecryptVaultBytes(raw, password)
}

func DecryptVaultBytes(raw []byte, password string) (*VaultData, error) {
	plain, err := sfcrypto.DecryptBlob(raw, password)
	if err != nil {
		return nil, err
	}
	var data VaultData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, fmt.Errorf("decode vault json: %w", err)
	}
	if data.Version == 0 {
		data.Version = 1
	}
	return &data, nil
}

func EncryptVaultBytes(data *VaultData, password string) ([]byte, error) {
	return EncryptVaultBytesWithIter(data, password, sfcrypto.DefaultIterations)
}

func EncryptVaultBytesWithIter(data *VaultData, password string, iter int) ([]byte, error) {
	if data == nil {
		data = NewEmptyVault()
	}
	if data.Version == 0 {
		data.Version = 1
	}
	data.UpdatedAt = time.Now().UTC()
	plain, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}
	return sfcrypto.EncryptBlobWithIterations(plain, password, iter)
}

func SaveVault(path, password string, data *VaultData) error {
	return SaveVaultWithIter(path, password, data, sfcrypto.DefaultIterations)
}

func SaveVaultWithIter(path, password string, data *VaultData, iter int) error {
	enc, err := EncryptVaultBytesWithIter(data, password, iter)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, enc, 0600)
}

func (v *VaultData) UpsertHost(h HostEntry) {
	if h.Port <= 0 {
		h.Port = 22
	}
	for i := range v.Hosts {
		if strings.EqualFold(v.Hosts[i].Name, h.Name) {
			v.Hosts[i] = h
			return
		}
	}
	v.Hosts = append(v.Hosts, h)
}

func (v *VaultData) RemoveHost(name string) bool {
	for i := range v.Hosts {
		if strings.EqualFold(v.Hosts[i].Name, name) {
			v.Hosts = append(v.Hosts[:i], v.Hosts[i+1:]...)
			return true
		}
	}
	return false
}

func (v *VaultData) FindHost(query string) (*HostEntry, bool) {
	for i := range v.Hosts {
		if strings.EqualFold(v.Hosts[i].Name, query) || (v.Hosts[i].NodeID != "" && strings.EqualFold(v.Hosts[i].NodeID, query)) {
			h := v.Hosts[i]
			return &h, true
		}
	}
	return nil, false
}

func (v *VaultData) UpsertKey(k SSHKeyEntry) {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	for i := range v.Keys {
		if strings.EqualFold(v.Keys[i].Name, k.Name) {
			v.Keys[i] = k
			return
		}
	}
	v.Keys = append(v.Keys, k)
}

func (v *VaultData) RemoveKey(name string) bool {
	for i := range v.Keys {
		if strings.EqualFold(v.Keys[i].Name, name) {
			v.Keys = append(v.Keys[:i], v.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// MaterializeKeys writes all decrypted private keys to keysDir with strict 0600 permissions.
func MaterializeKeys(data *VaultData, keysDir string) (map[string]string, error) {
	paths := make(map[string]string)
	if data == nil || len(data.Keys) == 0 {
		return paths, nil
	}
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, err
	}
	for _, k := range data.Keys {
		safeName := sanitizeID(k.Name)
		if safeName == "" {
			continue
		}
		privPath := filepath.Join(keysDir, safeName)
		content := k.PrivateKeyPEM
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(privPath, []byte(content), 0600); err != nil {
			return nil, fmt.Errorf("write key %s: %w", safeName, err)
		}
		_ = os.Chmod(privPath, 0600)
		if strings.TrimSpace(k.PublicKey) != "" {
			pubContent := strings.TrimSpace(k.PublicKey) + "\n"
			_ = os.WriteFile(privPath+".pub", []byte(pubContent), 0644)
		}
		paths[k.Name] = privPath
	}
	return paths, nil
}

// GenerateSSHConfigBlock produces an OpenSSH config section for all static VPS and live Hub nodes.
func GenerateSSHConfigBlock(data *VaultData, liveNodes []protocol.NodeInfo, keysDir, selfBinPath string) string {
	if strings.TrimSpace(selfBinPath) == "" {
		selfBinPath = "sf"
	}

	var sb strings.Builder
	sb.WriteString(SSHConfigBeginMarker + "\n")
	sb.WriteString("# Managed by ssh-fleet (sf). Manual edits inside this block will be overwritten.\n\n")

	seenAliases := map[string]bool{}

	if data != nil {
		hosts := make([]HostEntry, len(data.Hosts))
		copy(hosts, data.Hosts)
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

		for _, h := range hosts {
			alias := sanitizeSSHHostAlias(h.Name)
			if alias == "" {
				continue
			}
			seenAliases[alias] = true
			if h.NodeID != "" {
				seenAliases[sanitizeSSHHostAlias(h.NodeID)] = true
			}

			sb.WriteString(fmt.Sprintf("Host %s\n", alias))
			if h.ViaHub && h.NodeID != "" {
				sb.WriteString(fmt.Sprintf("  HostName %s\n", h.NodeID))
				sb.WriteString(fmt.Sprintf("  ProxyCommand \"%s\" proxy %s\n", selfBinPath, h.NodeID))
			} else if h.Host != "" {
				sb.WriteString(fmt.Sprintf("  HostName %s\n", h.Host))
			}
			if h.User != "" {
				sb.WriteString(fmt.Sprintf("  User %s\n", h.User))
			}
			if h.Port > 0 && h.Port != 22 && !h.ViaHub {
				sb.WriteString(fmt.Sprintf("  Port %d\n", h.Port))
			}
			if h.KeyName != "" && keysDir != "" {
				sb.WriteString(fmt.Sprintf("  IdentityFile \"%s\"\n", filepath.Join(keysDir, sanitizeID(h.KeyName))))
				sb.WriteString("  IdentitiesOnly yes\n")
			}
			sb.WriteString("  ServerAliveInterval 30\n")
			sb.WriteString("  ServerAliveCountMax 3\n\n")
		}
	}

	nodes := make([]protocol.NodeInfo, len(liveNodes))
	copy(nodes, liveNodes)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	for _, n := range nodes {
		alias := sanitizeSSHHostAlias(n.Name)
		if alias == "" {
			alias = sanitizeSSHHostAlias(n.NodeID)
		}
		if alias == "" || seenAliases[alias] || seenAliases[sanitizeSSHHostAlias(n.NodeID)] {
			continue
		}
		seenAliases[alias] = true

		sb.WriteString(fmt.Sprintf("Host %s\n", alias))
		sb.WriteString(fmt.Sprintf("  HostName %s\n", n.NodeID))
		if n.SSHUser != "" {
			sb.WriteString(fmt.Sprintf("  User %s\n", n.SSHUser))
		}
		sb.WriteString(fmt.Sprintf("  ProxyCommand \"%s\" proxy %s\n", selfBinPath, n.NodeID))
		sb.WriteString("  ServerAliveInterval 30\n")
		sb.WriteString("  ServerAliveCountMax 3\n\n")
	}

	sb.WriteString(SSHConfigEndMarker + "\n")
	return sb.String()
}

// SyncSSHConfig idempotently inserts or replaces the managed SSH-FLEET block in sshConfigPath.
func SyncSSHConfig(sshConfigPath, block string) error {
	if err := os.MkdirAll(filepath.Dir(sshConfigPath), 0700); err != nil {
		return err
	}
	existingBytes, err := os.ReadFile(sshConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	existing := string(existingBytes)

	startIdx := strings.Index(existing, SSHConfigBeginMarker)
	endIdx := strings.Index(existing, SSHConfigEndMarker)

	var updated string
	if startIdx >= 0 && endIdx > startIdx {
		afterEnd := endIdx + len(SSHConfigEndMarker)
		if afterEnd < len(existing) && existing[afterEnd] == '\n' {
			afterEnd++
		}
		prefix := strings.TrimRight(existing[:startIdx], "\n")
		suffix := strings.TrimLeft(existing[afterEnd:], "\n")
		parts := []string{}
		if prefix != "" {
			parts = append(parts, prefix)
		}
		parts = append(parts, strings.TrimRight(block, "\n"))
		if suffix != "" {
			parts = append(parts, suffix)
		}
		updated = strings.Join(parts, "\n\n") + "\n"
	} else {
		trimmed := strings.TrimRight(existing, "\n")
		if trimmed == "" {
			updated = block
		} else {
			updated = trimmed + "\n\n" + block
		}
	}

	return os.WriteFile(sshConfigPath, []byte(updated), 0600)
}

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' || r == '.' {
			b.WriteRune('-')
		}
	}
	res := strings.Trim(b.String(), "-_")
	if res == "" {
		return "node"
	}
	return res
}

func sanitizeSSHHostAlias(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
