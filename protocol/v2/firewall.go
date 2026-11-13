package v2

const (
	FirewallActionAllow = "allow"
	FirewallActionDeny  = "deny"
	FirewallProtoTCP    = "tcp"
	FirewallProtoUDP    = "udp"
	FirewallProtoBoth   = "both"
	FirewallStackV4     = "v4"
	FirewallStackV6     = "v6"

	FirewallOriginWeb      = "web"
	FirewallOriginImported = "imported"
	FirewallOriginInbound  = "inbound"
	FirewallOriginFile     = "file"
	FirewallOriginHost     = "host"
	FirewallOriginKeep     = "keep"

	FirewallBackendNFT       = "nft"
	FirewallBackendIptables  = "iptables"
	FirewallBackendUFW       = "ufw"
	FirewallBackendFirewalld = "firewalld"
	FirewallBackendWindows   = "windows"
	FirewallBackendNone      = "none"

	FirewallStatusOK          = "ok"
	FirewallStatusError       = "error"
	FirewallStatusUnsupported = "unsupported"
	FirewallStatusRolledBack  = "rolled_back"
	FirewallKindSnapshot      = "snapshot"
	FirewallKindApply         = "apply"
	FirewallKindAdopt         = "adopt"
	FirewallKindInstall       = "install"
)

type FirewallRule struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
	Source    string `json:"source,omitempty"`
	Stack     string `json:"stack"`
	Comment   string `json:"comment,omitempty"`
	Origin    string `json:"origin,omitempty"`
	Priority  int    `json:"priority"`
	InboundID string `json:"inbound_id,omitempty"`
	HostKey   string `json:"host_key,omitempty"`
}

type FirewallIntent struct {
	Revision     uint64         `json:"revision"`
	BlockPing4   bool           `json:"block_ping_v4"`
	BlockPing6   bool           `json:"block_ping_v6"`
	DefaultDeny4 bool           `json:"default_deny_v4"`
	DefaultDeny6 bool           `json:"default_deny_v6"`
	SshPort      string         `json:"ssh_port,omitempty"`
	OmitKeep     []string       `json:"omit_keep,omitempty"`
	Rules        []FirewallRule `json:"rules"`
}

type FirewallHole struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Stack    string `json:"stack"`
	Comment  string `json:"comment,omitempty"`
}

type FirewallHostRule struct {
	Key       string `json:"key"`
	Adoptable bool   `json:"adoptable"`
	Action    string `json:"action,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      string `json:"port,omitempty"`
	Source    string `json:"source,omitempty"`
	Stack     string `json:"stack,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Raw       string `json:"raw,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type FirewallSnapshotParams struct {
	RequestID string `json:"request_id"`
}

type FirewallApplyParams struct {
	RequestID   string         `json:"request_id"`
	Intent      FirewallIntent `json:"intent"`
	ListenHoles []FirewallHole `json:"listen_holes,omitempty"`
}

type FirewallAdoptParams struct {
	RequestID string   `json:"request_id"`
	Keys      []string `json:"keys"`
}

type FirewallInstallParams struct {
	RequestID string `json:"request_id"`
}

type FirewallResultParams struct {
	RequestID              string             `json:"request_id"`
	Kind                   string             `json:"kind"`
	Status                 string             `json:"status"`
	Error                  string             `json:"error,omitempty"`
	Revision               uint64             `json:"revision,omitempty"`
	Backend                string             `json:"backend,omitempty"`
	Privileged             bool               `json:"privileged"`
	Supported              bool               `json:"supported"`
	CanInstallNftables     bool               `json:"can_install_nftables,omitempty"`
	OuterFilter            bool               `json:"outer_filter"`
	OuterHint              string             `json:"outer_hint,omitempty"`
	OuterManagers          []string           `json:"outer_managers,omitempty"`
	DefaultDenyBlocked     bool               `json:"default_deny_blocked"`
	DefaultDenyBlockReason string             `json:"default_deny_block_reason,omitempty"`
	BlockPing4             bool               `json:"block_ping_v4"`
	BlockPing6             bool               `json:"block_ping_v6"`
	DefaultDeny4           bool               `json:"default_deny_v4"`
	DefaultDeny6           bool               `json:"default_deny_v6"`
	HasStacks              bool               `json:"has_stacks"`
	StackV4                bool               `json:"stack_v4"`
	StackV6                bool               `json:"stack_v6"`
	AppliedRules           []FirewallRule     `json:"applied_rules,omitempty"`
	KeepRules              []FirewallRule     `json:"keep_rules,omitempty"`
	HostRules              []FirewallHostRule `json:"host_rules,omitempty"`
	SshPort                string             `json:"ssh_port,omitempty"`
}
