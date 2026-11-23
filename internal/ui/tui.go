package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ssh-fleet/internal/fuzzy"
	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/vault"
)

type FleetTarget struct {
	Name        string
	Kind        string // "vps" | "hub-device"
	Host        string
	User        string
	Port        int
	KeyName     string
	ViaHub      bool
	NodeID      string
	OS          string
	PowerState  protocol.PowerState
	Online      bool
	MAC         string
	BroadcastIP string
	RelayNodeID string
	Tags        []string
}

// MergeFleet combines static/vault HostEntries with live/persisted Hub nodes into a unified slice.
func MergeFleet(v *vault.VaultData, nodes []protocol.NodeInfo) []FleetTarget {
	nodeByID := make(map[string]protocol.NodeInfo, len(nodes))
	nodeByName := make(map[string]protocol.NodeInfo, len(nodes))
	for _, n := range nodes {
		nodeByID[strings.ToLower(n.NodeID)] = n
		if n.Name != "" {
			nodeByName[strings.ToLower(n.Name)] = n
		}
	}

	usedNodes := map[string]bool{}
	var out []FleetTarget

	if v != nil {
		for _, h := range v.Hosts {
			t := FleetTarget{
				Name:        h.Name,
				Kind:        "vps",
				Host:        h.Host,
				User:        h.User,
				Port:        h.Port,
				KeyName:     h.KeyName,
				ViaHub:      h.ViaHub,
				NodeID:      h.NodeID,
				MAC:         h.MAC,
				BroadcastIP: h.BroadcastIP,
				RelayNodeID: h.RelayNodeID,
				Tags:        h.Tags,
				PowerState:  protocol.PowerState("static"),
			}
			if t.Port <= 0 {
				t.Port = 22
			}
			var matchedNode *protocol.NodeInfo
			if h.NodeID != "" {
				if n, ok := nodeByID[strings.ToLower(h.NodeID)]; ok {
					matchedNode = &n
				}
			} else if n, ok := nodeByName[strings.ToLower(h.Name)]; ok && h.ViaHub {
				matchedNode = &n
			}
			if matchedNode != nil {
				usedNodes[strings.ToLower(matchedNode.NodeID)] = true
				t.Kind = "hub-device"
				t.ViaHub = true
				t.NodeID = matchedNode.NodeID
				t.OS = matchedNode.OS + "/" + matchedNode.Arch
				t.Online = matchedNode.Online
				t.PowerState = matchedNode.PowerState
				if t.User == "" {
					t.User = matchedNode.SSHUser
				}
				if t.MAC == "" && len(matchedNode.MACAddrs) > 0 {
					t.MAC = matchedNode.MACAddrs[0]
				}
				if t.BroadcastIP == "" {
					t.BroadcastIP = matchedNode.BroadcastIP
				}
				if len(matchedNode.LocalIPs) > 0 && t.Host == "" {
					t.Host = matchedNode.LocalIPs[0]
				}
			} else if h.ViaHub {
				t.Kind = "hub-device"
				t.PowerState = protocol.PowerOffline
			}
			out = append(out, t)
		}
	}

	for _, n := range nodes {
		if usedNodes[strings.ToLower(n.NodeID)] {
			continue
		}
		mac := ""
		if len(n.MACAddrs) > 0 {
			mac = n.MACAddrs[0]
		}
		ip := n.NodeID
		if len(n.LocalIPs) > 0 {
			ip = n.LocalIPs[0]
		}
		out = append(out, FleetTarget{
			Name:        n.Name,
			Kind:        "hub-device",
			Host:        ip,
			User:        n.SSHUser,
			Port:        n.SSHPort,
			ViaHub:      true,
			NodeID:      n.NodeID,
			OS:          n.OS + "/" + n.Arch,
			PowerState:  n.PowerState,
			Online:      n.Online,
			MAC:         mac,
			BroadcastIP: n.BroadcastIP,
		})
	}

	return out
}

func FilterTargets(targets []FleetTarget, query string) []FleetTarget {
	return fuzzy.Rank(targets, query, func(t FleetTarget) []string {
		fields := []string{t.Name, t.NodeID, t.Host, t.OS, string(t.PowerState), t.User}
		fields = append(fields, t.Tags...)
		return fields
	})
}

func PrintFleetTable(targets []FleetTarget) {
	if len(targets) == 0 {
		fmt.Println("No hosts or devices found. Add a VPS with `sf host add` or run `sf agent` on a machine.")
		return
	}
	fmt.Printf("%-3s %-20s %-12s %-18s %-12s %-14s %s\n", "#", "NAME", "TYPE", "HOST / IP", "OS", "POWER/STATE", "TAGS / MAC")
	fmt.Println(strings.Repeat("-", 96))
	for i, t := range targets {
		addr := t.Host
		if addr == "" {
			addr = t.NodeID
		}
		osStr := t.OS
		if osStr == "" {
			osStr = "ssh-vps"
		}
		state := string(t.PowerState)
		if t.Kind == "hub-device" {
			if t.Online {
				state = "ON:" + state
			} else {
				state = "OFF:" + state
			}
		}
		extra := strings.Join(t.Tags, ",")
		if t.MAC != "" {
			if extra != "" {
				extra += " "
			}
			extra += "[" + t.MAC + "]"
		}
		fmt.Printf("%-3d %-20s %-12s %-18s %-12s %-14s %s\n",
			i+1, truncate(t.Name, 20), t.Kind, truncate(addr, 18), truncate(osStr, 12), truncate(state, 14), extra)
	}
}

type SelectorChoice struct {
	Target FleetTarget
	Action string // "ssh", "wake", "soft-sleep", "hard-sleep", "keep-awake-on", "keep-awake-off"
}

// RunInteractiveSelector runs a lightweight terminal fuzzy filter & action picker using standard input.
func RunInteractiveSelector(targets []FleetTarget, initialQuery string) (*SelectorChoice, error) {
	reader := bufio.NewReader(os.Stdin)
	query := initialQuery

	for {
		filtered := FilterTargets(targets, query)
		fmt.Println()
		fmt.Printf("=== ssh-fleet (query: %q) ===\n", query)
		PrintFleetTable(filtered)
		fmt.Println("\nType filter text, #<number> (e.g. 1), or q to quit:")
		fmt.Print("> ")

		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		input := strings.TrimSpace(line)
		if input == "q" || input == "quit" || input == "exit" {
			return nil, nil
		}

		if idx, err := strconv.Atoi(input); err == nil && idx >= 1 && idx <= len(filtered) {
			chosen := filtered[idx-1]
			return pickAction(reader, chosen)
		}

		if input == "" && len(filtered) == 1 {
			return pickAction(reader, filtered[0])
		}

		if input == "" {
			query = ""
			continue
		}
		query = input
	}
}

func pickAction(reader *bufio.Reader, target FleetTarget) (*SelectorChoice, error) {
	if target.Kind != "hub-device" {
		return &SelectorChoice{Target: target, Action: "ssh"}, nil
	}
	fmt.Printf("\nSelected %s (%s | %s):\n", target.Name, target.NodeID, target.PowerState)
	fmt.Println("  [Enter / a] Agent Shell (direct via fleet tunnel, no sshd needed)")
	fmt.Println("  [s]         SSH Connect")
	fmt.Println("  [w]         Wake (Soft-Wake or LAN Relay WoL)")
	fmt.Println("  [z]         Soft-Sleep (screen off + lock, keep network alive)")
	fmt.Println("  [H]         Hard-Sleep (OS Suspend-to-RAM)")
	fmt.Println("  [P]         Power Off (OS Shutdown)")
	fmt.Println("  [k]         Keep-Awake ON")
	fmt.Println("  [o]         Keep-Awake OFF")
	fmt.Println("  [b]         Back")
	fmt.Print("Action [a]: ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	act := strings.TrimSpace(line)
	switch strings.ToLower(act) {
	case "", "a":
		return &SelectorChoice{Target: target, Action: "shell"}, nil
	case "s":
		return &SelectorChoice{Target: target, Action: "ssh"}, nil
	case "w":
		return &SelectorChoice{Target: target, Action: "wake"}, nil
	case "z":
		return &SelectorChoice{Target: target, Action: "soft-sleep"}, nil
	case "k":
		return &SelectorChoice{Target: target, Action: "keep-awake-on"}, nil
	case "o":
		return &SelectorChoice{Target: target, Action: "keep-awake-off"}, nil
	case "b":
		return RunInteractiveSelector([]FleetTarget{target}, "")
	default:
		if act == "H" {
			return &SelectorChoice{Target: target, Action: "hard-sleep"}, nil
		}
		if act == "P" {
			return &SelectorChoice{Target: target, Action: "poweroff"}, nil
		}
		return &SelectorChoice{Target: target, Action: "shell"}, nil
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
