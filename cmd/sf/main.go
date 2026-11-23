package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ssh-fleet/internal/agent"
	"ssh-fleet/internal/hub"
	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/ui"
	"ssh-fleet/internal/vault"
	"ssh-fleet/internal/wol"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return cmdFind(nil)
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "find":
		return cmdFind(args[1:])
	case "list", "ls":
		return cmdList(args[1:])
	case "ssh":
		return cmdSSH(args[1:])
	case "wake":
		return cmdWake(args[1:])
	case "sleep":
		return cmdSleep(args[1:])
	case "keep-awake":
		return cmdKeepAwake(args[1:])
	case "host":
		return cmdHost(args[1:])
	case "key":
		return cmdKey(args[1:])
	case "vault":
		return cmdVault(args[1:])
	case "ssh-config":
		return cmdSSHConfig(args[1:])
	case "hub":
		return cmdHub(args[1:])
	case "agent":
		return cmdAgent(args[1:])
	case "proxy":
		return cmdProxy(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "join":
		return cmdJoin(args[1:])
	default:
		// Allow `sf <target>` shortcut if it doesn't start with '-'
		if !strings.HasPrefix(args[0], "-") {
			return cmdFind(args)
		}
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Println(`ssh-fleet (sf) - Cross-Platform SSH, NAT-Traversal Hub, E2EE Vault & Wake/Sleep Manager

USAGE:
  sf [find [query]]                 Interactive fuzzy search across VPS & Hub devices
  sf list                           List all VPS and live/offline Hub devices
  sf ssh <target> [--wake]          Connect via native SSH (or Hub Proxy tunnel)
  sf wake <target> [--mac ...]      Wake device (Soft-Wake or LAN Relay Wake-on-LAN)
  sf sleep <target> [--hard|--soft] Soft-Sleep (keep Wi-Fi/SSH alive) or Hard-Sleep (S3)
  sf keep-awake <target> <on|off>   Toggle AGY-Studio-style keep-awake inhibitor

VAULT & INVENTORY (E2EE):
  sf config set --hub URL --token T Configure Hub URL & Bearer token locally
  sf vault init                     Create encrypted E2EE vault (vault.enc)
  sf vault push                     Upload encrypted vault blob to Hub
  sf vault pull                     Download encrypted vault blob from Hub
  sf vault status                   Show local config & vault status
  sf host add|rm|list               Manage VPS / Device aliases in E2EE vault
  sf key add|import|rm|list         Manage SSH private keys in E2EE vault
  sf ssh-config [--write]           Generate or update ~/.ssh/config block

RELAY HUB & DEVICE AGENT:
  sf hub [--listen :8090] [--token T] [--install-service]
  sf join <hub-url> <token> [--name NAME] [--no-agent]
  sf agent [--hub URL] [--token T] [--name NAME] [--ssh-port 22] [--install-service]
  sf proxy <node-id>                Internal OpenSSH ProxyCommand over Hub tunnel`)
}

func configPath() string {
	if p := os.Getenv("SF_CONFIG"); p != "" {
		return p
	}
	dir, _ := vault.DefaultConfigDir()
	return filepath.Join(dir, "config.json")
}

func getVaultPassword(confirm bool) (string, error) {
	if env := os.Getenv("SF_VAULT_PASSWORD"); env != "" {
		return env, nil
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Vault Master Password: ")
	p1, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	p1 = strings.TrimRight(p1, "\r\n")
	if p1 == "" {
		return "", errors.New("master password cannot be empty")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm Master Password: ")
		p2, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		p2 = strings.TrimRight(p2, "\r\n")
		if p1 != p2 {
			return "", errors.New("passwords do not match")
		}
	}
	return p1, nil
}

func tryLoadVault(cfg vault.LocalConfig, required bool) (*vault.VaultData, string, error) {
	if _, err := os.Stat(cfg.VaultPath); errors.Is(err, os.ErrNotExist) {
		if !required {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("vault not found at %s (run `sf vault init` or `sf vault pull`)", cfg.VaultPath)
	}
	pw, err := getVaultPassword(false)
	if err != nil {
		return nil, "", err
	}
	v, err := vault.LoadVault(cfg.VaultPath, pw)
	if err != nil {
		return nil, "", err
	}
	return v, pw, nil
}

func addCFHeaders(req *http.Request, cfg vault.LocalConfig) {
	if strings.TrimSpace(cfg.CFClientID) != "" {
		req.Header.Set("CF-Access-Client-Id", cfg.CFClientID)
	}
	if strings.TrimSpace(cfg.CFClientSecret) != "" {
		req.Header.Set("CF-Access-Client-Secret", cfg.CFClientSecret)
	}
}

func cfHeaderMap(cfg vault.LocalConfig) map[string]string {
	h := map[string]string{}
	if strings.TrimSpace(cfg.CFClientID) != "" {
		h["CF-Access-Client-Id"] = cfg.CFClientID
	}
	if strings.TrimSpace(cfg.CFClientSecret) != "" {
		h["CF-Access-Client-Secret"] = cfg.CFClientSecret
	}
	return h
}

func fetchHubNodes(cfg vault.LocalConfig) ([]protocol.NodeInfo, error) {
	if strings.TrimSpace(cfg.HubURL) == "" || strings.TrimSpace(cfg.HubToken) == "" {
		return nil, nil
	}
	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.HubURL, "/")+"/api/v1/nodes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.HubToken)
	addCFHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub returned %s", resp.Status)
	}
	var payload struct {
		OK    bool                `json:"ok"`
		Nodes []protocol.NodeInfo `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Nodes, nil
}

func resolveTarget(cfg vault.LocalConfig, v *vault.VaultData, query string) (ui.FleetTarget, error) {
	nodes, _ := fetchHubNodes(cfg)
	fleet := ui.MergeFleet(v, nodes)
	for _, t := range fleet {
		if strings.EqualFold(t.Name, query) || (t.NodeID != "" && strings.EqualFold(t.NodeID, query)) {
			return t, nil
		}
	}
	ranked := ui.FilterTargets(fleet, query)
	if len(ranked) == 0 {
		return ui.FleetTarget{}, fmt.Errorf("no host or hub device matching %q", query)
	}
	return ranked[0], nil
}

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg, err := vault.LoadOrInitConfig(configPath())
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if args[0] == "set" {
		fs := flag.NewFlagSet("config set", flag.ContinueOnError)
		hubURL := fs.String("hub", "", "Hub base URL (e.g. https://hub.example.com)")
		token := fs.String("token", "", "Hub bearer token")
		cfID := fs.String("cf-client-id", "", "Cloudflare Access Service Token Client ID")
		cfSecret := fs.String("cf-client-secret", "", "Cloudflare Access Service Token Client Secret")
		nodeID := fs.String("node-id", "", "Override local node ID")
		name := fs.String("name", "", "Override local device name")
		sshPort := fs.Int("ssh-port", 0, "Local SSH daemon port")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := vault.LoadOrInitConfig(configPath())
		if err != nil {
			return err
		}
		if *hubURL != "" {
			cfg.HubURL = strings.TrimRight(*hubURL, "/")
		}
		if *token != "" {
			cfg.HubToken = *token
		}
		if *cfID != "" {
			cfg.CFClientID = *cfID
		}
		if *cfSecret != "" {
			cfg.CFClientSecret = *cfSecret
		}
		if *nodeID != "" {
			cfg.NodeID = *nodeID
		}
		if *name != "" {
			cfg.AgentName = *name
		}
		if *sshPort > 0 {
			cfg.SSHPort = *sshPort
		}
		if err := vault.SaveConfig(configPath(), cfg); err != nil {
			return err
		}
		fmt.Printf("Saved configuration to %s\n", configPath())
		return nil
	}
	return fmt.Errorf("usage: sf config [show | set --hub URL --token TOKEN]")
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	noVault := fs.Bool("no-vault", false, "Skip unlocking encrypted vault and only show Hub devices")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	var v *vault.VaultData
	if !*noVault {
		if _, err := os.Stat(cfg.VaultPath); err == nil {
			if os.Getenv("SF_VAULT_PASSWORD") != "" {
				v, _, _ = tryLoadVault(cfg, false)
			} else {
				v, _, err = tryLoadVault(cfg, false)
				if err != nil {
					return err
				}
			}
		}
	}
	nodes, hubErr := fetchHubNodes(cfg)
	if hubErr != nil && cfg.HubURL != "" {
		fmt.Fprintf(os.Stderr, "warning: could not query Hub (%s): %v\n", cfg.HubURL, hubErr)
	}
	fleet := ui.MergeFleet(v, nodes)
	ui.PrintFleetTable(fleet)
	return nil
}

func cmdFind(args []string) error {
	query := strings.Join(args, " ")
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	var v *vault.VaultData
	if _, err := os.Stat(cfg.VaultPath); err == nil {
		v, _, err = tryLoadVault(cfg, false)
		if err != nil {
			return err
		}
	}
	nodes, hubErr := fetchHubNodes(cfg)
	if hubErr != nil && cfg.HubURL != "" {
		fmt.Fprintf(os.Stderr, "warning: Hub query failed: %v\n", hubErr)
	}
	fleet := ui.MergeFleet(v, nodes)
	choice, err := ui.RunInteractiveSelector(fleet, query)
	if err != nil || choice == nil {
		return err
	}

	switch choice.Action {
	case "ssh":
		return launchSSH(cfg, v, choice.Target, false, nil)
	case "wake":
		return executePower(cfg, choice.Target, protocol.PowerRequest{
			Action:      protocol.ActionWake,
			MAC:         choice.Target.MAC,
			BroadcastIP: choice.Target.BroadcastIP,
			RelayNodeID: choice.Target.RelayNodeID,
		})
	case "soft-sleep":
		return executePower(cfg, choice.Target, protocol.PowerRequest{Action: protocol.ActionSoftSleep})
	case "hard-sleep":
		return executePower(cfg, choice.Target, protocol.PowerRequest{Action: protocol.ActionHardSleep})
	case "keep-awake-on":
		return executePower(cfg, choice.Target, protocol.PowerRequest{Action: protocol.ActionKeepAwakeOn})
	case "keep-awake-off":
		return executePower(cfg, choice.Target, protocol.PowerRequest{Action: protocol.ActionKeepAwakeOff})
	default:
		return nil
	}
}

func cmdSSH(args []string) error {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	wakeFirst := fs.Bool("wake", false, "Wake device first and wait until online before opening SSH")
	waitSec := fs.Int("wait", 45, "Max seconds to wait for waking node to come online")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: sf ssh <target> [--wake] [-- extra-ssh-args]")
	}
	targetQuery := rest[0]
	extraSSHArgs := rest[1:]

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	v, _, err := tryLoadVault(cfg, false)
	if err != nil {
		return err
	}
	target, err := resolveTarget(cfg, v, targetQuery)
	if err != nil {
		return err
	}

	if *wakeFirst && target.ViaHub && !target.Online {
		if err := executePower(cfg, target, protocol.PowerRequest{
			Action:      protocol.ActionWake,
			MAC:         target.MAC,
			BroadcastIP: target.BroadcastIP,
			RelayNodeID: target.RelayNodeID,
		}); err != nil {
			return err
		}
		fmt.Printf("Waiting up to %ds for %s to come online...\n", *waitSec, target.Name)
		deadline := time.Now().Add(time.Duration(*waitSec) * time.Second)
		for time.Now().Before(deadline) {
			nodes, _ := fetchHubNodes(cfg)
			for _, n := range nodes {
				if n.NodeID == target.NodeID && n.Online {
					target.Online = true
					goto Ready
				}
			}
			time.Sleep(1500 * time.Millisecond)
		}
		return fmt.Errorf("timed out waiting for %s to come online", target.Name)
	}

Ready:
	return launchSSH(cfg, v, target, false, extraSSHArgs)
}

func launchSSH(cfg vault.LocalConfig, v *vault.VaultData, target ui.FleetTarget, _ bool, extraArgs []string) error {
	var keyPaths map[string]string
	if v != nil {
		var err error
		keyPaths, err = vault.MaterializeKeys(v, cfg.KeysDir)
		if err != nil {
			return err
		}
	}

	sshArgs := []string{}
	if target.KeyName != "" {
		if p, ok := keyPaths[target.KeyName]; ok {
			sshArgs = append(sshArgs, "-i", p, "-o", "IdentitiesOnly=yes")
		}
	}

	if target.ViaHub && target.NodeID != "" {
		selfBin, err := os.Executable()
		if err != nil {
			selfBin = "sf"
		}
		proxyCmd := fmt.Sprintf("\"%s\" proxy %s", selfBin, target.NodeID)
		sshArgs = append(sshArgs, "-o", "ProxyCommand="+proxyCmd)
		dest := target.NodeID
		if target.User != "" {
			dest = target.User + "@" + dest
		}
		sshArgs = append(sshArgs, dest)
	} else {
		if target.Host == "" {
			return fmt.Errorf("target %q has no host address", target.Name)
		}
		if target.Port > 0 && target.Port != 22 {
			sshArgs = append(sshArgs, "-p", strconv.Itoa(target.Port))
		}
		dest := target.Host
		if target.User != "" {
			dest = target.User + "@" + dest
		}
		sshArgs = append(sshArgs, dest)
	}

	sshArgs = append(sshArgs, extraArgs...)
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdWake(args []string) error {
	fs := flag.NewFlagSet("wake", flag.ContinueOnError)
	mac := fs.String("mac", "", "Override MAC address for Wake-on-LAN")
	bcast := fs.String("broadcast", "", "Override broadcast IP (default 255.255.255.255)")
	relay := fs.String("relay", "", "Preferred online LAN relay node ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 && *mac == "" {
		return errors.New("usage: sf wake <target> [--mac AA:BB:CC:DD:EE:FF] [--broadcast IP] [--relay NODE_ID]")
	}

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	if fs.NArg() == 0 && *mac != "" {
		if err := wol.SendMagicPacket(*mac, *bcast, 9, 7); err != nil {
			return err
		}
		fmt.Printf("Sent local Wake-on-LAN magic packet to %s\n", *mac)
		return nil
	}

	v, _, err := tryLoadVault(cfg, false)
	if err != nil {
		return err
	}
	target, err := resolveTarget(cfg, v, fs.Arg(0))
	if err != nil {
		return err
	}
	useMAC := *mac
	if useMAC == "" {
		useMAC = target.MAC
	}
	useBcast := *bcast
	if useBcast == "" {
		useBcast = target.BroadcastIP
	}
	useRelay := *relay
	if useRelay == "" {
		useRelay = target.RelayNodeID
	}

	// Best-effort local WoL packet in case we are currently on the same LAN.
	if useMAC != "" && !target.Online {
		_ = wol.SendMagicPacket(useMAC, useBcast, 9, 7)
	}

	if target.NodeID != "" && cfg.HubURL != "" {
		return executePower(cfg, target, protocol.PowerRequest{
			Action:      protocol.ActionWake,
			MAC:         useMAC,
			BroadcastIP: useBcast,
			RelayNodeID: useRelay,
		})
	}
	if useMAC != "" {
		if err := wol.SendMagicPacket(useMAC, useBcast, 9, 7); err != nil {
			return err
		}
		fmt.Printf("Sent Wake-on-LAN magic packet to %s (%s)\n", target.Name, useMAC)
		return nil
	}
	return errors.New("cannot wake target: neither Hub node nor MAC address configured")
}

func cmdSleep(args []string) error {
	fs := flag.NewFlagSet("sleep", flag.ContinueOnError)
	hard := fs.Bool("hard", false, "Use OS Hard Sleep (Suspend-to-RAM; requires WoL to wake)")
	soft := fs.Bool("soft", true, "Use Soft Sleep (screen off + lock, keep Wi-Fi & SSH alive for instant wake)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: sf sleep <target> [--soft | --hard]")
	}
	_ = soft
	action := protocol.ActionSoftSleep
	if *hard {
		action = protocol.ActionHardSleep
	}

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	v, _, err := tryLoadVault(cfg, false)
	if err != nil {
		return err
	}
	target, err := resolveTarget(cfg, v, fs.Arg(0))
	if err != nil {
		return err
	}
	return executePower(cfg, target, protocol.PowerRequest{Action: action})
}

func cmdKeepAwake(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: sf keep-awake <target> <on|off>")
	}
	var action protocol.PowerAction
	switch strings.ToLower(args[1]) {
	case "on", "true", "1", "enable":
		action = protocol.ActionKeepAwakeOn
	case "off", "false", "0", "disable":
		action = protocol.ActionKeepAwakeOff
	default:
		return fmt.Errorf("invalid keep-awake mode %q (expected on|off)", args[1])
	}

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	v, _, err := tryLoadVault(cfg, false)
	if err != nil {
		return err
	}
	target, err := resolveTarget(cfg, v, args[0])
	if err != nil {
		return err
	}
	return executePower(cfg, target, protocol.PowerRequest{Action: action})
}

func executePower(cfg vault.LocalConfig, target ui.FleetTarget, reqBody protocol.PowerRequest) error {
	if cfg.HubURL == "" || cfg.HubToken == "" {
		return errors.New("hub_url and hub_token must be configured via `sf config set`")
	}
	nodeID := target.NodeID
	if nodeID == "" {
		nodeID = target.Name
	}

	b, _ := json.Marshal(reqBody)
	endpoint := fmt.Sprintf("%s/api/v1/nodes/%s/power", strings.TrimRight(cfg.HubURL, "/"), nodeID)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.HubToken)
	req.Header.Set("Content-Type", "application/json")
	addCFHeaders(req, cfg)

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out protocol.PowerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("power action %s failed on %s: %s", reqBody.Action, nodeID, out.Error)
	}
	fmt.Printf("OK [%s] -> node=%s method=%s state=%s", reqBody.Action, out.NodeID, out.Method, out.PowerState)
	if len(out.Relays) > 0 {
		fmt.Printf(" relays=%v", out.Relays)
	}
	fmt.Println()
	return nil
}

func cmdVault(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sf vault <init|push|pull|status>")
	}
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	switch args[0] {
	case "init":
		if _, err := os.Stat(cfg.VaultPath); err == nil {
			return fmt.Errorf("vault already exists at %s", cfg.VaultPath)
		}
		pw, err := getVaultPassword(true)
		if err != nil {
			return err
		}
		v := vault.NewEmptyVault()
		if err := vault.SaveVault(cfg.VaultPath, pw, v); err != nil {
			return err
		}
		fmt.Printf("Initialized encrypted E2EE vault at %s\n", cfg.VaultPath)
		return nil

	case "status":
		_, err := os.Stat(cfg.VaultPath)
		fmt.Printf("Config:     %s\n", configPath())
		fmt.Printf("Vault Path: %s (exists=%v)\n", cfg.VaultPath, err == nil)
		fmt.Printf("Hub URL:    %s\n", cfg.HubURL)
		fmt.Printf("Node ID:    %s\n", cfg.NodeID)
		return nil

	case "push":
		if cfg.HubURL == "" || cfg.HubToken == "" {
			return errors.New("hub_url and hub_token must be configured via `sf config set`")
		}
		raw, err := os.ReadFile(cfg.VaultPath)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPut, strings.TrimRight(cfg.HubURL, "/")+"/api/v1/vault", bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.HubToken)
		req.Header.Set("Content-Type", "application/json")
		addCFHeaders(req, cfg)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("hub push failed (%s): %s", resp.Status, string(b))
		}
		fmt.Println("Pushed encrypted vault blob to Hub.")
		return nil

	case "pull":
		if cfg.HubURL == "" || cfg.HubToken == "" {
			return errors.New("hub_url and hub_token must be configured via `sf config set`")
		}
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.HubURL, "/")+"/api/v1/vault", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.HubToken)
		addCFHeaders(req, cfg)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("hub pull failed (%s): %s", resp.Status, string(b))
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		pw, err := getVaultPassword(false)
		if err != nil {
			return err
		}
		v, err := vault.DecryptVaultBytes(raw, pw)
		if err != nil {
			return fmt.Errorf("pulled vault verification failed: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(cfg.VaultPath), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(cfg.VaultPath, raw, 0600); err != nil {
			return err
		}
		if _, err := vault.MaterializeKeys(v, cfg.KeysDir); err != nil {
			return err
		}
		fmt.Printf("Pulled and verified vault (%d hosts, %d keys) to %s\n", len(v.Hosts), len(v.Keys), cfg.VaultPath)
		return nil

	default:
		return errors.New("usage: sf vault <init|push|pull|status>")
	}
}

func cmdHost(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sf host <add|rm|list>")
	}
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("host add", flag.ContinueOnError)
		name := fs.String("name", "", "Alias name")
		host := fs.String("host", "", "IP or hostname (for static VPS)")
		user := fs.String("user", "", "SSH username")
		port := fs.Int("port", 22, "SSH port")
		key := fs.String("key", "", "Vault key name")
		viaHub := fs.Bool("via-hub", false, "Connect through Hub NAT-traversal tunnel")
		nodeID := fs.String("node-id", "", "Hub node ID (when --via-hub)")
		mac := fs.String("mac", "", "MAC address for Wake-on-LAN")
		bcast := fs.String("broadcast", "", "Broadcast IP for WoL")
		relay := fs.String("relay", "", "Preferred LAN relay node ID")
		tagsStr := fs.String("tags", "", "Comma-separated tags")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("--name is required")
		}
		v, pw, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		var tags []string
		for _, t := range strings.Split(*tagsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
		v.UpsertHost(vault.HostEntry{
			Name:        *name,
			Host:        *host,
			User:        *user,
			Port:        *port,
			KeyName:     *key,
			ViaHub:      *viaHub,
			NodeID:      *nodeID,
			MAC:         *mac,
			BroadcastIP: *bcast,
			RelayNodeID: *relay,
			Tags:        tags,
		})
		if err := vault.SaveVault(cfg.VaultPath, pw, v); err != nil {
			return err
		}
		fmt.Printf("Saved host %q to encrypted vault.\n", *name)
		return nil

	case "rm":
		if len(args) < 2 {
			return errors.New("usage: sf host rm <name>")
		}
		v, pw, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		if !v.RemoveHost(args[1]) {
			return fmt.Errorf("host %q not found", args[1])
		}
		if err := vault.SaveVault(cfg.VaultPath, pw, v); err != nil {
			return err
		}
		fmt.Printf("Removed host %q.\n", args[1])
		return nil

	case "list":
		v, _, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		ui.PrintFleetTable(ui.MergeFleet(v, nil))
		return nil

	default:
		return errors.New("usage: sf host <add|rm|list>")
	}
}

func cmdKey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sf key <import|rm|list>")
	}
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	switch args[0] {
	case "import", "add":
		fs := flag.NewFlagSet("key import", flag.ContinueOnError)
		name := fs.String("name", "", "Key name inside vault")
		privFile := fs.String("file", "", "Path to SSH private key file")
		pubFile := fs.String("pub", "", "Optional path to SSH public key file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || *privFile == "" {
			return errors.New("usage: sf key import --name NAME --file ~/.ssh/id_ed25519 [--pub ~/.ssh/id_ed25519.pub]")
		}
		privBytes, err := os.ReadFile(*privFile)
		if err != nil {
			return err
		}
		var pubStr string
		if *pubFile != "" {
			if pb, err := os.ReadFile(*pubFile); err == nil {
				pubStr = string(pb)
			}
		} else if pb, err := os.ReadFile(*privFile + ".pub"); err == nil {
			pubStr = string(pb)
		}

		v, pw, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		v.UpsertKey(vault.SSHKeyEntry{
			Name:          *name,
			PrivateKeyPEM: string(privBytes),
			PublicKey:     pubStr,
		})
		if err := vault.SaveVault(cfg.VaultPath, pw, v); err != nil {
			return err
		}
		if _, err := vault.MaterializeKeys(v, cfg.KeysDir); err != nil {
			return err
		}
		fmt.Printf("Imported key %q into E2EE vault and materialized in %s.\n", *name, cfg.KeysDir)
		return nil

	case "rm":
		if len(args) < 2 {
			return errors.New("usage: sf key rm <name>")
		}
		v, pw, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		if !v.RemoveKey(args[1]) {
			return fmt.Errorf("key %q not found", args[1])
		}
		return vault.SaveVault(cfg.VaultPath, pw, v)

	case "list":
		v, _, err := tryLoadVault(cfg, true)
		if err != nil {
			return err
		}
		for _, k := range v.Keys {
			fmt.Printf("%-20s created=%s pub=%v\n", k.Name, k.CreatedAt.Format(time.RFC3339), k.PublicKey != "")
		}
		return nil

	default:
		return errors.New("usage: sf key <import|rm|list>")
	}
}

func cmdSSHConfig(args []string) error {
	fs := flag.NewFlagSet("ssh-config", flag.ContinueOnError)
	writeFlag := fs.Bool("write", false, "Write generated block into ~/.ssh/config")
	outPath := fs.String("path", "", "Override output SSH config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	var v *vault.VaultData
	if _, err := os.Stat(cfg.VaultPath); err == nil {
		v, _, err = tryLoadVault(cfg, false)
		if err != nil {
			return err
		}
		if _, err := vault.MaterializeKeys(v, cfg.KeysDir); err != nil {
			return err
		}
	}
	nodes, _ := fetchHubNodes(cfg)
	selfBin, _ := os.Executable()
	block := vault.GenerateSSHConfigBlock(v, nodes, cfg.KeysDir, selfBin)

	if !*writeFlag {
		fmt.Print(block)
		return nil
	}
	target := *outPath
	if target == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		target = filepath.Join(home, ".ssh", "config")
	}
	if err := vault.SyncSSHConfig(target, block); err != nil {
		return err
	}
	fmt.Printf("Updated %s with ssh-fleet managed hosts.\n", target)
	return nil
}

func cmdHub(args []string) error {
	fs := flag.NewFlagSet("hub", flag.ContinueOnError)
	listen := fs.String("listen", ":8090", "Listen address (e.g. :8090 or 127.0.0.1:8090)")
	token := fs.String("token", os.Getenv("SF_HUB_TOKEN"), "Bearer token for agents and clients")
	dataDir := fs.String("data-dir", "", "Directory to persist node state and encrypted vault")
	installSvc := fs.Bool("install-service", false, "Install and start Hub as a background service")
	publicURL := fs.String("public-url", "", "Public URL of this Hub for join command output")
	trustCF := fs.Bool("trust-cf-access", false, "Trust Cloudflare Access Zero Trust authenticated headers for Web UI & API")
	cfEmail := fs.String("cf-access-email", os.Getenv("SF_CF_ACCESS_EMAIL"), "Comma-separated Cloudflare Access emails allowed (implies --trust-cf-access)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dataDir == "" {
		dir, err := vault.DefaultConfigDir()
		if err != nil {
			return err
		}
		*dataDir = filepath.Join(dir, "hub-data")
	}
	if strings.TrimSpace(*token) == "" {
		if cfg, err := vault.LoadOrInitConfig(configPath()); err == nil && cfg.HubToken != "" && *installSvc {
			*token = cfg.HubToken
		} else {
			b := make([]byte, 24)
			_, _ = rand.Read(b)
			*token = "sf_" + hex.EncodeToString(b)
			fmt.Printf("Generated Hub Bearer Token: %s\n", *token)
		}
	}

	if *installSvc {
		return installAndStartHub(*listen, *token, *dataDir, *publicURL, *trustCF, *cfEmail)
	}

	srv, err := hub.NewServerWithOptions(hub.Options{
		Token:         *token,
		DataDir:       *dataDir,
		TrustCFAccess: *trustCF,
		CFAccessEmail: *cfEmail,
	})
	if err != nil {
		return err
	}
	fmt.Printf("ssh-fleet Hub listening on %s (dataDir=%s, cfAccess=%v)\n", *listen, *dataDir, *trustCF || *cfEmail != "")
	return srv.ListenAndServe(*listen)
}

func installAndStartHub(listen, token, dataDir, publicURL string, trustCF bool, cfEmail string) error {
	selfBin, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}

	port := "8090"
	if idx := strings.LastIndex(listen, ":"); idx >= 0 && idx+1 < len(listen) {
		port = listen[idx+1:]
	}

	localHubURL := "http://127.0.0.1:" + port
	cfg, _ := vault.LoadOrInitConfig(configPath())
	cfg.HubURL = localHubURL
	cfg.HubToken = token
	_ = vault.SaveConfig(configPath(), cfg)

	extraFlags := ""
	extraArgs := []string{"hub", "--listen", listen, "--token", token, "--data-dir", dataDir}
	if trustCF {
		extraFlags += " --trust-cf-access"
		extraArgs = append(extraArgs, "--trust-cf-access")
	}
	if strings.TrimSpace(cfEmail) != "" {
		extraFlags += fmt.Sprintf(" --cf-access-email %q", cfEmail)
		extraArgs = append(extraArgs, "--cf-access-email", cfEmail)
	}

	startedMsg := ""
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() == 0 {
			unitPath := "/etc/systemd/system/ssh-fleet-hub.service"
			unit := fmt.Sprintf(`[Unit]
Description=ssh-fleet Relay Hub
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="%s" hub --listen "%s" --token "%s" --data-dir "%s"%s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, selfBin, listen, token, dataDir, extraFlags)
			if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
				return err
			}
			_ = exec.Command("systemctl", "daemon-reload").Run()
			if err := exec.Command("systemctl", "enable", "--now", "ssh-fleet-hub").Run(); err == nil {
				startedMsg = "systemd service active: ssh-fleet-hub"
			}
		} else {
			home, _ := os.UserHomeDir()
			unitPath := filepath.Join(home, ".config", "systemd", "user", "ssh-fleet-hub.service")
			_ = os.MkdirAll(filepath.Dir(unitPath), 0755)
			unit := fmt.Sprintf(`[Unit]
Description=ssh-fleet Relay Hub
After=network-online.target

[Service]
Type=simple
ExecStart="%s" hub --listen "%s" --token "%s" --data-dir "%s"%s
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, selfBin, listen, token, dataDir, extraFlags)
			_ = os.WriteFile(unitPath, []byte(unit), 0644)
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			if err := exec.Command("systemctl", "--user", "enable", "--now", "ssh-fleet-hub").Run(); err == nil {
				if user := os.Getenv("USER"); user != "" {
					_ = exec.Command("loginctl", "enable-linger", user).Run()
				}
				startedMsg = "systemd user service active: ssh-fleet-hub"
			}
		}
		if startedMsg == "" {
			logPath, err := startDetachedProcess(selfBin, extraArgs, "hub.log")
			if err != nil {
				return err
			}
			startedMsg = "detached background process (log: " + logPath + ")"
		}
	default:
		logPath, err := startDetachedProcess(selfBin, extraArgs, "hub.log")
		if err != nil {
			return err
		}
		startedMsg = "background process (log: " + logPath + ")"
	}

	advURL := strings.TrimRight(publicURL, "/")
	if advURL == "" {
		ip := detectPublicOrLocalIP()
		advURL = fmt.Sprintf("http://%s:%s", ip, port)
	}

	fmt.Println("\n=== ssh-fleet Hub Ready ===")
	fmt.Printf("Status:   %s\n", startedMsg)
	fmt.Printf("Hub URL:  %s\n", advURL)
	fmt.Printf("Token:    %s\n", token)
	fmt.Printf("DB Dir:   %s\n", dataDir)
	fmt.Println("\nRun this 1-line command on any Linux/macOS device to join:")
	fmt.Printf("  curl -fsSL https://raw.githubusercontent.com/Khoinguyen002/ssh-fleet/main/install.sh | bash -s -- join %s %s\n", advURL, token)
	fmt.Println("\nOr on Windows PowerShell:")
	fmt.Printf("  $env:SF_HUB=%q; $env:SF_TOKEN=%q; irm https://raw.githubusercontent.com/Khoinguyen002/ssh-fleet/main/install.ps1 | iex\n", advURL, token)
	return nil
}

func cmdJoin(args []string) error {
	// Support both positional `sf join <url> <token> [flags]` and flags-first `sf join --hub ... --token ...`.
	var positional []string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i:]...)
			break
		}
		positional = append(positional, args[i])
	}

	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	hubFlag := fs.String("hub", "", "Hub URL")
	tokenFlag := fs.String("token", "", "Hub Bearer token")
	cfIDFlag := fs.String("cf-client-id", os.Getenv("SF_CF_CLIENT_ID"), "Cloudflare Access Service Token Client ID")
	cfSecretFlag := fs.String("cf-client-secret", os.Getenv("SF_CF_CLIENT_SECRET"), "Cloudflare Access Service Token Client Secret")
	nameFlag := fs.String("name", cfg.AgentName, "Device display name")
	nodeIDFlag := fs.String("node-id", cfg.NodeID, "Unique node ID")
	sshPortFlag := fs.Int("ssh-port", cfg.SSHPort, "Local SSH daemon port")
	noAgent := fs.Bool("no-agent", false, "Only configure client access without starting background device agent")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	rest := append(positional, fs.Args()...)
	hubURL := *hubFlag
	token := *tokenFlag
	if hubURL == "" && len(rest) >= 1 {
		hubURL = rest[0]
	}
	if token == "" && len(rest) >= 2 {
		token = rest[1]
	}
	if len(rest) >= 3 && *nameFlag == cfg.AgentName {
		*nameFlag = rest[2]
	}

	if strings.TrimSpace(hubURL) == "" || strings.TrimSpace(token) == "" {
		return errors.New("usage: sf join <hub-url> <token> [--cf-client-id ID --cf-client-secret SECRET] [--name DEVICE_NAME] [--ssh-port 22] [--no-agent]")
	}

	cfg.HubURL = strings.TrimRight(hubURL, "/")
	cfg.HubToken = token
	if *cfIDFlag != "" {
		cfg.CFClientID = *cfIDFlag
	}
	if *cfSecretFlag != "" {
		cfg.CFClientSecret = *cfSecretFlag
	}
	if *nameFlag != "" {
		cfg.AgentName = *nameFlag
	}
	if *nodeIDFlag != "" {
		cfg.NodeID = *nodeIDFlag
	}
	if *sshPortFlag > 0 {
		cfg.SSHPort = *sshPortFlag
	}
	if err := vault.SaveConfig(configPath(), cfg); err != nil {
		return err
	}
	fmt.Printf("Configured ssh-fleet -> Hub=%s (node=%s)\n", cfg.HubURL, cfg.NodeID)

	if !*noAgent {
		selfBin, err := os.Executable()
		if err != nil {
			return err
		}
		svcMsg, err := installAndStartAgent(selfBin, cfg)
		if err != nil {
			return err
		}
		fmt.Printf("Agent started: %s\n", svcMsg)

		// Give the agent up to 3s to register on the Hub before syncing ~/.ssh/config.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			nodes, err := fetchHubNodes(cfg)
			if err == nil {
				for _, n := range nodes {
					if n.NodeID == cfg.NodeID && n.Online {
						goto SyncSSH
					}
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
	}

SyncSSH:
	nodes, err := fetchHubNodes(cfg)
	if err == nil {
		selfBin, _ := os.Executable()
		block := vault.GenerateSSHConfigBlock(nil, nodes, cfg.KeysDir, selfBin)
		if home, hErr := os.UserHomeDir(); hErr == nil {
			sshCfg := filepath.Join(home, ".ssh", "config")
			if sErr := vault.SyncSSHConfig(sshCfg, block); sErr == nil {
				fmt.Printf("Synced %d Hub device(s) into %s\n", len(nodes), sshCfg)
			}
		}
	}

	fmt.Println("Done! Try `sf list` or `sf` to see and connect to your devices.")
	return nil
}

func installAndStartAgent(selfBin string, cfg vault.LocalConfig) (string, error) {
	targetPath, content, hint, err := agent.GenerateServiceFile(
		runtime.GOOS,
		selfBin,
		cfg.HubURL,
		cfg.HubToken,
		cfg.NodeID,
		cfg.AgentName,
		cfg.SSHPort,
	)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		if err := exec.Command("systemctl", "--user", "enable", "--now", "ssh-fleet-agent").Run(); err == nil {
			_ = exec.Command("systemctl", "--user", "restart", "ssh-fleet-agent").Run()
			return "systemd user service (" + targetPath + ")", nil
		}
		logPath, err := startDetachedProcess(selfBin, []string{"agent"}, "agent.log")
		if err != nil {
			return "", fmt.Errorf("systemd --user failed and fallback failed (%v). Manual: %s", err, hint)
		}
		return "detached process (log: " + logPath + ")", nil
	case "darwin":
		_ = exec.Command("launchctl", "unload", targetPath).Run()
		if err := exec.Command("launchctl", "load", "-w", targetPath).Run(); err == nil {
			return "LaunchAgent (" + targetPath + ")", nil
		}
		logPath, err := startDetachedProcess(selfBin, []string{"agent"}, "agent.log")
		if err != nil {
			return "", err
		}
		return "detached process (log: " + logPath + ")", nil
	case "windows":
		_ = exec.Command("wscript.exe", targetPath).Start()
		return "Windows Startup script (" + targetPath + ")", nil
	default:
		return targetPath, nil
	}
}

func startDetachedProcess(binPath string, args []string, logName string) (string, error) {
	dir, err := vault.DefaultConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	logPath := filepath.Join(dir, logName)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return "", err
	}
	_ = cmd.Process.Release()
	_ = f.Close()
	return logPath, nil
}

func detectPublicOrLocalIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	if resp, err := client.Get("https://api.ipify.org"); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if b, err := io.ReadAll(io.LimitReader(resp.Body, 64)); err == nil {
				ip := strings.TrimSpace(string(b))
				if ip != "" {
					return ip
				}
			}
		}
	}
	if ifaces, err := wol.DetectNetworkInterfaces(); err == nil && len(ifaces) > 0 {
		return ifaces[0].IPv4
	}
	return "<HUB_PUBLIC_IP>"
}

func cmdAgent(args []string) error {
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	hubURL := fs.String("hub", cfg.HubURL, "Hub URL")
	token := fs.String("token", cfg.HubToken, "Hub bearer token")
	cfID := fs.String("cf-client-id", cfg.CFClientID, "Cloudflare Access Client ID")
	cfSecret := fs.String("cf-client-secret", cfg.CFClientSecret, "Cloudflare Access Client Secret")
	nodeID := fs.String("node-id", cfg.NodeID, "Unique node ID")
	name := fs.String("name", cfg.AgentName, "Display name")
	sshPort := fs.Int("ssh-port", cfg.SSHPort, "Local SSH server port")
	installSvc := fs.Bool("install-service", false, "Install OS background service (systemd / LaunchAgent / Windows Startup)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *hubURL == "" || *token == "" {
		return errors.New("both --hub and --token (or `sf config set`) are required")
	}

	if *installSvc {
		selfBin, err := os.Executable()
		if err != nil {
			return err
		}
		targetPath, content, hint, err := agent.GenerateServiceFile(runtime.GOOS, selfBin, *hubURL, *token, *nodeID, *name, *sshPort)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
			return err
		}
		cfg.HubURL = strings.TrimRight(*hubURL, "/")
		cfg.HubToken = *token
		cfg.CFClientID = *cfID
		cfg.CFClientSecret = *cfSecret
		cfg.NodeID = *nodeID
		cfg.AgentName = *name
		cfg.SSHPort = *sshPort
		_ = vault.SaveConfig(configPath(), cfg)
		fmt.Printf("Wrote service file: %s\nNext step: %s\n", targetPath, hint)
		return nil
	}

	client, err := agent.NewClient(agent.Options{
		HubURL:         *hubURL,
		Token:          *token,
		CFClientID:     *cfID,
		CFClientSecret: *cfSecret,
		NodeID:         *nodeID,
		Name:           *name,
		SSHPort:        *sshPort,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("ssh-fleet Agent starting (node=%s, hub=%s, sshPort=%d)\n", *nodeID, *hubURL, *sshPort)
	return client.Run(ctx)
}

func cmdProxy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sf proxy <node-id>")
	}
	cfg, err := vault.LoadOrInitConfig(configPath())
	if err != nil {
		return err
	}
	if cfg.HubURL == "" || cfg.HubToken == "" {
		return errors.New("hub_url and hub_token must be configured via `sf config set`")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.PipeStdioToProxy(ctx, cfg.HubURL, cfg.HubToken, args[0], cfHeaderMap(cfg))
}
