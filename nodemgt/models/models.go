package models

import (
	"strings"
	"time"
)

const (
	CoreXray    = "xray"
	CoreSingBox = "sing-box"

	UserActive   = "active"
	UserDisabled = "disabled"
	UserExpired  = "expired"
	UserKindRelay     = "relay"
	RelayUsernamePrefix = "__relay__"

	CmdPending    = "pending"
	CmdSent       = "sent"
	CmdApplied    = "applied"
	CmdFailed     = "failed"
	CmdSuperseded = "superseded"

	CertPending = "pending"
	CertIssued  = "issued"
	CertFailed  = "failed"

	CertSourceACME = "acme"
	CertSourceFile = "file"
	CertSourceRoot = "root"
)

type Inbound struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID     string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Core         string    `json:"core" gorm:"type:varchar(16);not null"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	Protocol     string    `json:"protocol" gorm:"type:varchar(32);not null"`
	Listen       string    `json:"listen" gorm:"type:varchar(128);not null;default:'0.0.0.0'"`
	Port         int       `json:"port" gorm:"not null"`
	SortIndex    int       `json:"sort_index" gorm:"not null;default:0;index"`
	SettingsJSON string    `json:"settings_json" gorm:"type:longtext"`
	StreamJSON   string    `json:"stream_json" gorm:"type:longtext"`
	Enabled      bool      `json:"enabled" gorm:"not null;default:true"`
	Revision     uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Inbound) TableName() string { return "nodemgt_inbounds" }

type Outbound struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID     string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Core         string    `json:"core" gorm:"type:varchar(16);not null"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	Protocol     string    `json:"protocol" gorm:"type:varchar(32);not null"`
	SettingsJSON string    `json:"settings_json" gorm:"type:longtext"`
	Enabled      bool      `json:"enabled" gorm:"not null;default:true"`
	Revision     uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Outbound) TableName() string { return "nodemgt_outbounds" }

type Route struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID  string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Name      string    `json:"name" gorm:"type:varchar(100);not null"`
	Priority  int       `json:"priority" gorm:"not null;default:0"`
	RuleJSON  string    `json:"rule_json" gorm:"type:longtext"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	Revision  uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Route) TableName() string { return "nodemgt_routes" }

type ForwardChain struct {
	ID             string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name           string    `json:"name" gorm:"type:varchar(100);not null"`
	Strategy       string    `json:"strategy" gorm:"type:varchar(16);not null;default:'none'"`
	BackupDirect   bool      `json:"backup_direct" gorm:"not null;default:false"`
	FallbackDirect bool      `json:"fallback_direct" gorm:"not null;default:false"`
	Enabled        bool      `json:"enabled" gorm:"not null;default:true"`
	Revision       uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (ForwardChain) TableName() string { return "nodemgt_forward_chains" }

type ForwardLanding struct {
	ID               string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	ChainID          string    `json:"chain_id" gorm:"type:varchar(36);index;not null"`
	LandingInboundID string    `json:"landing_inbound_id" gorm:"type:varchar(36);index;not null"`
	SortIndex        int       `json:"sort_index" gorm:"not null;default:0"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (ForwardLanding) TableName() string { return "nodemgt_forward_landings" }

type ForwardLink struct {
	ID              string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	ChainID         string    `json:"chain_id" gorm:"type:varchar(36);index;not null"`
	SourceInboundID string    `json:"source_inbound_id" gorm:"type:varchar(36);uniqueIndex;not null"`
	OutboundID      string    `json:"outbound_id" gorm:"type:varchar(36);index"`
	RouteID         string    `json:"route_id" gorm:"type:varchar(36);index"`
	SortIndex       int       `json:"sort_index" gorm:"not null;default:0"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (ForwardLink) TableName() string { return "nodemgt_forward_links" }

type Grant struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	InboundID string    `json:"inbound_id" gorm:"type:varchar(36);index;not null"`
	CreatedAt time.Time `json:"created_at"`
}

func (Grant) TableName() string { return "nodemgt_grants" }

type NodeUser struct {
	ID                string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID          string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Username          string     `json:"username" gorm:"type:varchar(100);not null"`
	DisplayName       string     `json:"display_name" gorm:"type:varchar(100)"`
	Kind              string     `json:"kind" gorm:"type:varchar(16);not null;default:''"`
	Status            string     `json:"status" gorm:"type:varchar(16);not null;default:'active'"`
	ExpiresAt         *time.Time `json:"expires_at"`
	TrafficResetDay   int        `json:"traffic_reset_day" gorm:"not null;default:0"`
	TrafficResetCycle string     `json:"traffic_reset_cycle" gorm:"type:varchar(64)"`
	RateLimitBps      int64      `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit       int        `json:"device_limit" gorm:"not null;default:0"`
	QuotaBytes        int64      `json:"quota_bytes" gorm:"not null;default:0"`
	UsedBytes         int64      `json:"used_bytes" gorm:"not null;default:0"`
	Flow              string     `json:"flow" gorm:"type:varchar(64)"`
	SharedPoolID      string     `json:"shared_pool_id" gorm:"type:varchar(36);index"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	IPsClearedAt      *time.Time `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (NodeUser) TableName() string { return "nodemgt_node_users" }

func IsRelayUser(kind, username string) bool {
	if strings.EqualFold(strings.TrimSpace(kind), UserKindRelay) {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(username), RelayUsernamePrefix)
}

type Credential struct {
	ID             string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID         string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Kind           string     `json:"kind" gorm:"type:varchar(16);not null"`
	SecretHash     string     `json:"-" gorm:"type:varchar(128);not null"`
	SecretHint     string     `json:"secret_hint" gorm:"type:varchar(16)"`
	SecretMaterial string     `json:"-" gorm:"type:longtext"`
	UUID           string     `json:"uuid,omitempty" gorm:"type:varchar(36)"`
	Enabled        bool       `json:"enabled" gorm:"not null;default:true"`
	ExpiresAt      *time.Time `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (Credential) TableName() string { return "nodemgt_credentials" }

type Plan struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	TrafficBytes int64     `json:"traffic_bytes" gorm:"not null;default:0"`
	DurationDays int       `json:"duration_days" gorm:"not null;default:30"`
	RateLimitBps int64     `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit  int       `json:"device_limit" gorm:"not null;default:0"`
	SharedPool   bool      `json:"shared_pool" gorm:"not null;default:false"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Plan) TableName() string { return "nodemgt_plans" }

type Assignment struct {
	ID           string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID       string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	PlanID       string     `json:"plan_id" gorm:"type:varchar(36);index;not null"`
	StartsAt     time.Time  `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at"`
	TrafficBytes int64      `json:"traffic_bytes" gorm:"not null;default:0"`
	RateLimitBps int64      `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit  int        `json:"device_limit" gorm:"not null;default:0"`
	OperationID  string     `json:"operation_id" gorm:"type:varchar(64);uniqueIndex"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (Assignment) TableName() string { return "nodemgt_assignments" }

type QuotaLedger struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Delta     int64     `json:"delta" gorm:"not null"`
	Reason    string    `json:"reason" gorm:"type:varchar(32);not null"`
	OpID      string    `json:"operation_id" gorm:"type:varchar(64);uniqueIndex"`
	CreatedAt time.Time `json:"created_at"`
}

func (QuotaLedger) TableName() string { return "nodemgt_quota_ledger" }

type QuotaLease struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	PoolID    string    `json:"pool_id" gorm:"type:varchar(36);index;not null"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Bytes     int64     `json:"bytes" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (QuotaLease) TableName() string { return "nodemgt_quota_leases" }

type Subscription struct {
	ID         string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID     string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Token      string    `json:"token" gorm:"type:varchar(64);uniqueIndex;not null"`
	TokenHash  string    `json:"-" gorm:"type:varchar(64);index"`
	Format     string    `json:"format" gorm:"type:varchar(16);not null;default:'xray'"`
	AutoDetect bool      `json:"auto_detect" gorm:"not null;default:false"`
	ExtraURLs  string    `json:"extra_urls" gorm:"type:longtext"`
	Enabled    bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (Subscription) TableName() string { return "nodemgt_subscriptions" }

// Templates never contain user credentials. Nodes are injected after grants are resolved.
type SubscriptionTemplate struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name      string    `json:"name" gorm:"type:varchar(100);not null"`
	Kind      string    `json:"kind" gorm:"type:varchar(16);not null"`
	Content   string    `json:"content" gorm:"type:longtext;not null"`
	Revision  uint64    `json:"revision" gorm:"not null;default:1"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (SubscriptionTemplate) TableName() string { return "nodemgt_subscription_templates" }

// One template per scope and client. Empty global scope_id is intentional.
type SubscriptionTemplateBinding struct {
	ID         string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Scope      string    `json:"scope" gorm:"type:varchar(16);not null;uniqueIndex:subtpl_scope_client"`
	ScopeID    string    `json:"scope_id" gorm:"type:varchar(36);not null;uniqueIndex:subtpl_scope_client"`
	Client     string    `json:"client" gorm:"type:varchar(16);not null;uniqueIndex:subtpl_scope_client"`
	TemplateID string    `json:"template_id" gorm:"type:varchar(36);not null;index"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (SubscriptionTemplateBinding) TableName() string {
	return "nodemgt_subscription_template_bindings"
}

const (
	ExtraLinkKindLink         = "link"
	ExtraLinkKindSubscription = "subscription"
)

type UserExtraLink struct {
	ID             string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID         string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Kind           string     `json:"kind" gorm:"type:varchar(16);not null;default:'link'"`
	Value          string     `json:"value" gorm:"type:longtext;not null"`
	Remark         string     `json:"remark" gorm:"type:varchar(200)"`
	NamePrefix     string     `json:"name_prefix" gorm:"type:varchar(64)"`
	Enabled        bool       `json:"enabled" gorm:"not null;default:true"`
	ExpiresAt      *time.Time `json:"expires_at"`
	SortIndex      int        `json:"sort_index" gorm:"not null;default:0;index"`
	LastFetchAt    *time.Time `json:"last_fetch_at"`
	LastFetchError string     `json:"last_fetch_error" gorm:"type:varchar(512)"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (UserExtraLink) TableName() string { return "nodemgt_user_extra_links" }

type RootCertificate struct {
	ID          string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	Domain      string     `json:"domain" gorm:"type:varchar(253);uniqueIndex;not null"`
	KeyPEM      string     `json:"-" gorm:"type:longtext"`
	ChainPEM    string     `json:"-" gorm:"type:longtext"`
	Fingerprint string     `json:"fingerprint" gorm:"type:varchar(128)"`
	Issuer      string     `json:"issuer" gorm:"type:varchar(64);not null;default:''"`
	NotAfter    *time.Time `json:"not_after"`
	AutoRenew   bool       `json:"auto_renew" gorm:"not null;default:true"`
	Status      string     `json:"status" gorm:"type:varchar(16);not null;default:'pending'"`
	LastError   string     `json:"last_error" gorm:"type:varchar(512)"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (RootCertificate) TableName() string { return "nodemgt_root_certs" }

type Certificate struct {
	ID             string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID       string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Domain         string     `json:"domain" gorm:"type:varchar(253);not null"`
	RootCertID     string     `json:"root_cert_id" gorm:"type:varchar(36);index"`
	ShareDomain    string     `json:"share_domain" gorm:"type:varchar(253);not null;default:''"`
	CoverWildcard  bool       `json:"cover_wildcard" gorm:"not null;default:false"`
	Source         string     `json:"source" gorm:"type:varchar(16);not null;default:'acme'"`
	Issuer         string     `json:"issuer" gorm:"type:varchar(64);not null;default:''"`
	Fingerprint    string     `json:"fingerprint" gorm:"type:varchar(128)"`
	NotAfter       *time.Time `json:"not_after"`
	AutoRenew      bool       `json:"auto_renew" gorm:"not null;default:true"`
	CertPath       string     `json:"cert_path" gorm:"type:varchar(512)"`
	KeyPath        string     `json:"key_path" gorm:"type:varchar(512)"`
	ChainPEM       string     `json:"chain_pem,omitempty" gorm:"type:longtext"`
	Status         string     `json:"status" gorm:"type:varchar(16);not null;default:'pending'"`
	LastError      string     `json:"last_error" gorm:"type:varchar(512)"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (Certificate) TableName() string { return "nodemgt_certs" }

type ControlCommand struct {
	ID          string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	OperationID string     `json:"operation_id" gorm:"type:varchar(64);uniqueIndex;not null"`
	NodeUUID    string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Kind        string     `json:"kind" gorm:"type:varchar(32);not null"`
	PayloadJSON string     `json:"payload_json" gorm:"type:longtext"`
	Status      string     `json:"status" gorm:"type:varchar(16);not null;default:'pending'"`
	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	LastError   string     `json:"last_error" gorm:"type:varchar(512)"`
	AckedAt     *time.Time `json:"acked_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (ControlCommand) TableName() string { return "nodemgt_control_commands" }

type AuditEvent struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Actor     string    `json:"actor" gorm:"type:varchar(100);not null"`
	Action    string    `json:"action" gorm:"type:varchar(64);not null"`
	Target    string    `json:"target" gorm:"type:varchar(128)"`
	Detail    string    `json:"detail" gorm:"type:longtext"`
	CreatedAt time.Time `json:"created_at"`
}

func (AuditEvent) TableName() string { return "nodemgt_audit_events" }

type Setting struct {
	Key       string    `json:"key" gorm:"type:varchar(64);primaryKey"`
	Value     string    `json:"value" gorm:"type:longtext"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Setting) TableName() string { return "nodemgt_settings" }

type NodeProfile struct {
	NodeUUID  string    `json:"node_uuid" gorm:"type:varchar(36);primaryKey"`
	DialStack string    `json:"dial_stack" gorm:"type:varchar(32);not null;default:'dual'"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (NodeProfile) TableName() string { return "nodemgt_node_profiles" }

type UserIP struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);uniqueIndex:uid_ip_node;not null"`
	IP        string    `json:"ip" gorm:"type:varchar(64);uniqueIndex:uid_ip_node;not null"`
	NodeUUID  string    `json:"node_uuid" gorm:"type:varchar(36);uniqueIndex:uid_ip_node;index;not null"`
	SeenAt    time.Time `json:"seen_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (UserIP) TableName() string { return "nodemgt_user_ips" }

func All() []any {
	return []any{
		&Inbound{},
		&Outbound{},
		&Route{},
		&ForwardChain{},
		&ForwardLanding{},
		&ForwardLink{},
		&Grant{},
		&NodeUser{},
		&Credential{},
		&Plan{},
		&Assignment{},
		&QuotaLedger{},
		&QuotaLease{},
		&Subscription{},
		&SubscriptionTemplate{},
		&SubscriptionTemplateBinding{},
		&UserExtraLink{},
		&RootCertificate{},
		&Certificate{},
		&ControlCommand{},
		&AuditEvent{},
		&Setting{},
		&NodeProfile{},
		&UserIP{},
	}
}
