package v2

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	CapabilityServiceProtection = "service_protection"
	ServiceProtectionVersion    = 1

	MethodAgentProtectionPrecheck      = "agent.protection.precheck"
	MethodAgentProtectionUpgrade       = "agent.protection.upgrade"
	MethodAgentProtectionApplyConfig   = "agent.protection.applyConfig"
	MethodAgentProtectionBan           = "agent.protection.ban"
	MethodAgentProtectionUnban         = "agent.protection.unban"
	MethodAgentProtectionGroupSnapshot = "agent.protection.groupSnapshot"
	MethodAgentProtectionPreview       = "agent.protection.preview"
	MethodAgentProtectionResult        = "agent.protection.result"
	MethodAgentProtectionReport        = "agent.protection.report"

	ProtectionStatusOK          = "ok"
	ProtectionStatusError       = "error"
	ProtectionStatusUnsupported = "unsupported"

	ProtectionKindPrecheck      = "precheck"
	ProtectionKindUpgrade       = "upgrade"
	ProtectionKindApplyConfig   = "apply_config"
	ProtectionKindBan           = "ban"
	ProtectionKindUnban         = "unban"
	ProtectionKindGroupSnapshot = "group_snapshot"
	ProtectionKindPreview       = "preview"
	ProtectionKindReport        = "report"

	ProtectionModeObserve = "observe"
	ProtectionModeEnforce = "enforce"

	ProtectionLogCaddyJSON     = "caddy_json"
	ProtectionLogNginxCombined = "nginx_combined"
	ProtectionLogNginxJSON     = "nginx_json"
	ProtectionLogSSHD          = "sshd"
	ProtectionJournalSSHD      = "journal:sshd"

	ProtectionDeployDirect = "direct"
	ProtectionDeployProxy  = "proxy"

	ProtectionReasonPathScan    = "path_scan"
	ProtectionReasonRequestRate = "request_rate"
	ProtectionReasonSSHAuth     = "ssh_auth"
	ProtectionReasonShared      = "shared"

	ProtectionUpgradePhasePrecheck = "precheck"
	ProtectionUpgradePhaseInstall  = "install"
	ProtectionUpgradePhaseEnable   = "enable"
	ProtectionUpgradePhaseVerify   = "verify"
	ProtectionUpgradePhaseReady    = "ready"
	ProtectionUpgradePhaseFailed   = "failed"

	ProtectionBanActive  = "active"
	ProtectionBanExpired = "expired"
	ProtectionBanRevoked = "revoked"

	ProtectionDefaultBanSec   = 600
	ProtectionBanPermanentSec = -1
)

type ProtectionFeatures struct {
	SetsTimeout bool `json:"sets_timeout"`
	ConnLimit   bool `json:"conn_limit"`
	Meter       bool `json:"meter"`
	Nflog       bool `json:"nflog"`
	IPv4        bool `json:"ipv4"`
	IPv6        bool `json:"ipv6"`
}

type ProtectionCapability struct {
	Platform         string             `json:"platform"`
	Linux            bool               `json:"linux"`
	Privileged       bool               `json:"privileged"`
	StaticBackend    string             `json:"static_backend,omitempty"`
	NftPresent       bool               `json:"nft_present"`
	NftVersion       string             `json:"nft_version,omitempty"`
	RuntimeReady     bool               `json:"runtime_ready"`
	RuntimeEnabled   bool               `json:"runtime_enabled"`
	CanInstall       bool               `json:"can_install"`
	CanUpdate        bool               `json:"can_update"`
	CanEnableRuntime bool               `json:"can_enable_runtime"`
	PackageManager   string             `json:"package_manager,omitempty"`
	Missing          []string           `json:"missing,omitempty"`
	Conflicts        []string           `json:"conflicts,omitempty"`
	ManualHints      []string           `json:"manual_hints,omitempty"`
	PlannedSteps     []string           `json:"planned_steps,omitempty"`
	Features         ProtectionFeatures `json:"features"`
	ScopeNote        string             `json:"scope_note,omitempty"`
	SshdLogPath      string             `json:"sshd_log_path,omitempty"`
}

type ProtectionLogSource struct {
	ID           string `json:"id"`
	Format       string `json:"format"`
	Path         string `json:"path"`
	DeployMode   string `json:"deploy_mode,omitempty"`
	HostFilter   string `json:"host_filter,omitempty"`
	BindProtocol string `json:"bind_protocol,omitempty"`
	BindPort     string `json:"bind_port,omitempty"`
	BindAddr     string `json:"bind_addr,omitempty"`
}

type ProtectionPolicy struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	Enabled          bool     `json:"enabled"`
	Mode             string   `json:"mode"`
	BindAddr         string   `json:"bind_addr,omitempty"`
	Protocol         string   `json:"protocol"`
	Port             string   `json:"port"`
	BanDurationSec   int      `json:"ban_duration_sec,omitempty"`
	GroupID          string   `json:"group_id,omitempty"`
	SynRate          int      `json:"syn_rate,omitempty"`
	SynBurst         int      `json:"syn_burst,omitempty"`
	ConnLimit        int      `json:"conn_limit,omitempty"`
	RequestWindowSec int      `json:"request_window_sec,omitempty"`
	RequestThreshold int      `json:"request_threshold,omitempty"`
	PathWindowSec    int      `json:"path_window_sec,omitempty"`
	PathThreshold    int      `json:"path_threshold,omitempty"`
	Paths            []string `json:"paths,omitempty"`
	PathStatus       []int    `json:"path_status,omitempty"`
	SourceID         string   `json:"source_id,omitempty"`
}

type ProtectionConfig struct {
	Revision       uint64                `json:"revision"`
	Enabled        bool                  `json:"enabled"`
	RuntimeEnabled bool                  `json:"runtime_enabled"`
	Whitelist      []string              `json:"whitelist,omitempty"`
	Sources        []ProtectionLogSource `json:"sources,omitempty"`
	Policies       []ProtectionPolicy    `json:"policies,omitempty"`
	CounterResetAt map[string]string     `json:"counter_reset_at,omitempty"`
}

type ProtectionBanReason struct {
	BanID            string `json:"ban_id"`
	EventID          string `json:"event_id"`
	IP               string `json:"ip"`
	SourceNode       string `json:"source_node,omitempty"`
	PolicyID         string `json:"policy_id,omitempty"`
	ReasonType       string `json:"reason_type"`
	CreatedAt        string `json:"created_at"`
	ExpiresAt        string `json:"expires_at"`
	GroupID          string `json:"group_id,omitempty"`
	Status           string `json:"status,omitempty"`
	ObservedRevision uint64 `json:"observed_revision,omitempty"`
}

type ProtectionGroupSnapshot struct {
	Group    string                      `json:"group_id"`
	Revision uint64                      `json:"revision"`
	Bans     []ProtectionBanReason       `json:"bans,omitempty"`
	Revoked  map[string]ProtectionRevoke `json:"revoked,omitempty"`
}

type ProtectionRevoke struct {
	Revision uint64 `json:"revision"`
	ResetAt  string `json:"reset_at,omitempty"`
}

type ProtectionPreviewRecord struct {
	TS        string `json:"ts,omitempty"`
	IP        string `json:"ip,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Host      string `json:"host,omitempty"`
	Status    int    `json:"status,omitempty"`
	Transport string `json:"transport,omitempty"`
	Port      int    `json:"port,omitempty"`
	Error     string `json:"error,omitempty"`
}

type ProtectionSourceStats struct {
	ID           string `json:"id"`
	Path         string `json:"path,omitempty"`
	LastReadAt   string `json:"last_read_at,omitempty"`
	LagMS        int64  `json:"lag_ms,omitempty"`
	Parsed       uint64 `json:"parsed"`
	Dropped      uint64 `json:"dropped"`
	Errors       uint64 `json:"errors"`
	QueueDropped uint64 `json:"queue_dropped"`
}

type ProtectionNflogSample struct {
	At     string `json:"at,omitempty"`
	IP     string `json:"ip,omitempty"`
	Dport  int    `json:"dport,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

type ProtectionRequest struct {
	RequestID string `json:"request_id"`
}

type ProtectionUpgradeParams struct {
	RequestID string `json:"request_id"`
	OpID      string `json:"op_id,omitempty"`
}

type ProtectionApplyConfigParams struct {
	RequestID string           `json:"request_id"`
	Config    ProtectionConfig `json:"config"`
}

type ProtectionBanParams struct {
	RequestID        string              `json:"request_id"`
	Reason           ProtectionBanReason `json:"reason"`
	ObservedRevision uint64              `json:"observed_revision,omitempty"`
}

type ProtectionUnbanParams struct {
	RequestID string `json:"request_id"`
	IP        string `json:"ip"`
	GroupID   string `json:"group_id,omitempty"`
	Revision  uint64 `json:"revision,omitempty"`
	ResetAt   string `json:"reset_at,omitempty"`
	Local     bool   `json:"local,omitempty"`
}

type ProtectionGroupSnapshotParams struct {
	RequestID string                  `json:"request_id"`
	Snapshot  ProtectionGroupSnapshot `json:"snapshot"`
}

type ProtectionPreviewParams struct {
	RequestID string `json:"request_id"`
	SourceID  string `json:"source_id,omitempty"`
	Path      string `json:"path,omitempty"`
	Format    string `json:"format,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type ProtectionResultParams struct {
	RequestID        string                    `json:"request_id"`
	Kind             string                    `json:"kind"`
	Status           string                    `json:"status"`
	Error            string                    `json:"error,omitempty"`
	OpID             string                    `json:"op_id,omitempty"`
	Phase            string                    `json:"phase,omitempty"`
	Revision         uint64                    `json:"revision,omitempty"`
	GroupID          string                    `json:"group_id,omitempty"`
	GroupRevision    uint64                    `json:"group_revision,omitempty"`
	Capability       *ProtectionCapability     `json:"capability,omitempty"`
	RuntimeEnabled   bool                      `json:"runtime_enabled,omitempty"`
	AppliedBans      []ProtectionBanReason     `json:"applied_bans,omitempty"`
	Preview          []ProtectionPreviewRecord `json:"preview,omitempty"`
	SourceStats      []ProtectionSourceStats   `json:"source_stats,omitempty"`
	Nflog            []ProtectionNflogSample   `json:"nflog,omitempty"`
	PackageInstalled bool                      `json:"package_installed,omitempty"`
	RuntimeApplied   bool                      `json:"runtime_applied,omitempty"`
	Restored         bool                      `json:"restored,omitempty"`
}

type ProtectionReportParams struct {
	Kind         string                  `json:"kind,omitempty"`
	Hits         []ProtectionBanReason   `json:"hits,omitempty"`
	Executions   []ProtectionBanReason   `json:"executions,omitempty"`
	SourceStats  []ProtectionSourceStats `json:"source_stats,omitempty"`
	Nflog        []ProtectionNflogSample `json:"nflog,omitempty"`
	Capability   *ProtectionCapability   `json:"capability,omitempty"`
	ConfigRev    uint64                  `json:"config_revision,omitempty"`
	GroupApplied map[string]uint64       `json:"group_applied,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

func NormalizeProtectionIP(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

func ProtectionIPFamily(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return "v4"
	}
	return "v6"
}

func ValidProtectionLogFormat(format string) bool {
	switch strings.TrimSpace(format) {
	case ProtectionLogCaddyJSON, ProtectionLogNginxCombined, ProtectionLogNginxJSON, ProtectionLogSSHD:
		return true
	default:
		return false
	}
}

func IsProtectionJournalPath(path string) bool {
	return strings.TrimSpace(path) == ProtectionJournalSSHD
}

func ProtectionAutoBanReasons() []string {
	return []string{ProtectionReasonPathScan, ProtectionReasonRequestRate, ProtectionReasonSSHAuth}
}

func CheckProtectionSSHSources(cfg ProtectionConfig) error {
	var sshd []ProtectionLogSource
	byID := map[string]ProtectionLogSource{}
	for _, src := range cfg.Sources {
		id := strings.TrimSpace(src.ID)
		if id != "" {
			byID[id] = src
		}
		if strings.TrimSpace(src.Format) == ProtectionLogSSHD {
			sshd = append(sshd, src)
		}
	}
	if len(sshd) > 1 {
		return fmt.Errorf("同一节点只能接入一条 SSH 日志，journal 和文件日志同时接会把一次失败计两次")
	}
	for _, pol := range cfg.Policies {
		src, linked := byID[strings.TrimSpace(pol.SourceID)]
		if linked && strings.TrimSpace(src.Format) == ProtectionLogSSHD {
			if err := sshPolicyMatchesSource(pol, src); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(pol.SourceID) != "" || !policyUsesLogDetection(pol) || len(sshd) != 1 {
			continue
		}
		if sshPolicyMatchesSource(pol, sshd[0]) == nil || autoLogSourceCoversPolicy(cfg.Sources, pol) {
			continue
		}
		return sshPolicyMatchesSource(pol, sshd[0])
	}
	return nil
}

func policyUsesLogDetection(pol ProtectionPolicy) bool {
	return pol.RequestThreshold > 0 && pol.RequestWindowSec > 0
}

func sshPolicyMatchesSource(pol ProtectionPolicy, src ProtectionLogSource) error {
	proto := strings.ToLower(strings.TrimSpace(pol.Protocol))
	if proto == "" {
		proto = FirewallProtoTCP
	}
	if proto != FirewallProtoTCP {
		return fmt.Errorf("SSH 防护策略必须是 TCP")
	}
	if strings.TrimSpace(pol.Port) != strings.TrimSpace(src.BindPort) {
		return fmt.Errorf("SSH 日志绑定端口必须与防护策略端口一致")
	}
	return nil
}

func autoLogSourceCoversPolicy(sources []ProtectionLogSource, pol ProtectionPolicy) bool {
	for _, src := range sources {
		if strings.TrimSpace(src.Format) == "" || strings.TrimSpace(src.Format) == ProtectionLogSSHD {
			continue
		}
		if strings.TrimSpace(src.BindPort) == "" {
			continue
		}
		if logSourceCoversPolicy(src, pol) {
			return true
		}
	}
	return false
}

func logSourceCoversPolicy(src ProtectionLogSource, pol ProtectionPolicy) bool {
	if strings.TrimSpace(src.Format) == ProtectionLogSSHD {
		return sshPolicyMatchesSource(pol, src) == nil
	}
	proto := strings.ToLower(strings.TrimSpace(pol.Protocol))
	if proto == "" {
		proto = FirewallProtoTCP
	}
	bindProto := strings.ToLower(strings.TrimSpace(src.BindProtocol))
	if bindProto != "" && bindProto != proto {
		return false
	}
	port := strings.TrimSpace(pol.Port)
	bindPort := strings.TrimSpace(src.BindPort)
	if bindPort == "" || port == "" || port == "*" {
		return true
	}
	if strings.Contains(bindPort, ",") {
		return false
	}
	return bindPort == port
}

var ProtectionBanNeverAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func NormalizeProtectionBanSec(sec int) int {
	if sec < 0 {
		return ProtectionBanPermanentSec
	}
	if sec == 0 {
		return ProtectionDefaultBanSec
	}
	return sec
}

func ProtectionBanNever(exp time.Time) bool {
	return !exp.IsZero() && exp.UTC().Year() >= 9999
}

func ProtectionBanExpiry(now time.Time, sec int) time.Time {
	sec = NormalizeProtectionBanSec(sec)
	if sec < 0 {
		return ProtectionBanNeverAt
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.UTC().Add(time.Duration(sec) * time.Second)
}

func FormatProtectionBanExpiry(now time.Time, sec int) string {
	return ProtectionBanExpiry(now, sec).Format(time.RFC3339Nano)
}
