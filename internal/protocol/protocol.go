package protocol

import "time"

type PowerState string

const (
	PowerActive    PowerState = "active"
	PowerKeepAwake PowerState = "keep-awake"
	PowerSoftSleep PowerState = "soft-sleep"
	PowerSleeping  PowerState = "sleeping"
	PowerOffline   PowerState = "offline"
)

type PowerAction string

const (
	ActionKeepAwakeOn  PowerAction = "keep-awake-on"
	ActionKeepAwakeOff PowerAction = "keep-awake-off"
	ActionSoftSleep    PowerAction = "soft-sleep"
	ActionHardSleep    PowerAction = "hard-sleep"
	ActionWake         PowerAction = "wake"
)

type NodeInfo struct {
	NodeID      string     `json:"node_id"`
	Name        string     `json:"name"`
	Hostname    string     `json:"hostname"`
	OS          string     `json:"os"`
	Arch        string     `json:"arch"`
	SSHUser     string     `json:"ssh_user"`
	SSHPort     int        `json:"ssh_port"`
	LocalIPs    []string   `json:"local_ips,omitempty"`
	SubnetCIDRs []string   `json:"subnet_cidrs,omitempty"`
	MACAddrs    []string   `json:"mac_addrs,omitempty"`
	BroadcastIP string     `json:"broadcast_ip,omitempty"`
	PowerState  PowerState `json:"power_state"`
	Online      bool       `json:"online"`
	IsVPS       bool       `json:"is_vps,omitempty"`
	ConnectedAt time.Time  `json:"connected_at,omitempty"`
	LastSeen    time.Time  `json:"last_seen"`
}

// ControlFrame represents a single newline-delimited JSON message over the Hub <-> Agent control channel.
type ControlFrame struct {
	Type        string     `json:"t"`
	ReqID       string     `json:"req_id,omitempty"`
	StreamID    string     `json:"stream_id,omitempty"`
	Node        *NodeInfo  `json:"node,omitempty"`
	PowerState  PowerState `json:"power_state,omitempty"`
	Action      string     `json:"action,omitempty"`
	MAC         string     `json:"mac,omitempty"`
	BroadcastIP string     `json:"broadcast_ip,omitempty"`
	TargetPort  int        `json:"target_port,omitempty"`
	OK          bool       `json:"ok,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type PowerRequest struct {
	Action      PowerAction `json:"action"`
	MAC         string      `json:"mac,omitempty"`
	BroadcastIP string      `json:"broadcast_ip,omitempty"`
	RelayNodeID string      `json:"relay_node_id,omitempty"`
}

type PowerResponse struct {
	OK         bool       `json:"ok"`
	NodeID     string     `json:"node_id"`
	Method     string     `json:"method"`
	PowerState PowerState `json:"power_state,omitempty"`
	Relays     []string   `json:"relays,omitempty"`
	Error      string     `json:"error,omitempty"`
}
