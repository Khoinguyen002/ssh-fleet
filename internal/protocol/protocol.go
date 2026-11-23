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
	ActionPowerOff     PowerAction = "poweroff"
	ActionWake         PowerAction = "wake"
)

type NodeWolConfig struct {
	MAC         string `json:"mac"`
	BroadcastIP string `json:"broadcast_ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	WakeRelayID string `json:"wake_relay_id"`
}

type WakeRelaySummary struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Online          bool       `json:"online"`
	FirmwareVersion string     `json:"firmware_version,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
}

type NodeInfo struct {
	NodeID      string         `json:"node_id"`
	Name        string         `json:"name"`
	CustomName  bool           `json:"custom_name,omitempty"`
	Version     string         `json:"version,omitempty"`
	Hostname    string         `json:"hostname"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	SSHUser     string         `json:"ssh_user"`
	SSHPort     int            `json:"ssh_port"`
	LocalIPs    []string       `json:"local_ips,omitempty"`
	SubnetCIDRs []string       `json:"subnet_cidrs,omitempty"`
	MACAddrs    []string       `json:"mac_addrs,omitempty"`
	BroadcastIP string         `json:"broadcast_ip,omitempty"`
	PowerState           PowerState     `json:"power_state"`
	Online               bool           `json:"online"`
	IsVPS                bool           `json:"is_vps,omitempty"`
	WoL                  *NodeWolConfig `json:"wol,omitempty"`
	KeyringLocked        *bool          `json:"keyring_locked,omitempty"`
	KeyringUnlockPending bool           `json:"keyring_unlock_pending,omitempty"`
	KeyringUnlockError   string         `json:"keyring_unlock_error,omitempty"`
	ConnectedAt          time.Time      `json:"connected_at,omitempty"`
	LastSeen             time.Time      `json:"last_seen"`
}

// ControlFrame represents a single newline-delimited JSON message over the Hub <-> Agent control channel.
type ControlFrame struct {
	Type          string     `json:"t"`
	ReqID         string     `json:"req_id,omitempty"`
	StreamID      string     `json:"stream_id,omitempty"`
	Node          *NodeInfo  `json:"node,omitempty"`
	PowerState    PowerState `json:"power_state,omitempty"`
	Action        string     `json:"action,omitempty"`
	MAC           string     `json:"mac,omitempty"`
	BroadcastIP   string     `json:"broadcast_ip,omitempty"`
	TargetPort    int        `json:"target_port,omitempty"`
	Password      string     `json:"password,omitempty"`
	KeyringLocked *bool      `json:"keyring_locked,omitempty"`
	Cols          int        `json:"cols,omitempty"`
	Rows          int        `json:"rows,omitempty"`
	Version       string     `json:"version,omitempty"`
	Updated       bool       `json:"updated,omitempty"`
	OK            bool       `json:"ok,omitempty"`
	Error         string     `json:"error,omitempty"`
}

type PowerRequest struct {
	Action          PowerAction `json:"action"`
	MAC             string      `json:"mac,omitempty"`
	BroadcastIP     string      `json:"broadcast_ip,omitempty"`
	RelayNodeID     string      `json:"relay_node_id,omitempty"`
	KeyringPassword string      `json:"keyring_password,omitempty"`
}

type PowerResponse struct {
	OK              bool       `json:"ok"`
	NodeID          string     `json:"node_id"`
	Method          string     `json:"method"`
	PowerState      PowerState `json:"power_state,omitempty"`
	Relays          []string   `json:"relays,omitempty"`
	UnlockQueued    bool       `json:"unlock_queued,omitempty"`
	KeyringUnlocked bool       `json:"keyring_unlocked,omitempty"`
	KeyringError    string     `json:"keyring_error,omitempty"`
	Error           string     `json:"error,omitempty"`
}

type UnlockKeyringRequest struct {
	Password string `json:"password"`
}

type UnlockKeyringResponse struct {
	OK            bool   `json:"ok"`
	NodeID        string `json:"node_id"`
	KeyringLocked *bool  `json:"keyring_locked,omitempty"`
	Error         string `json:"error,omitempty"`
}
