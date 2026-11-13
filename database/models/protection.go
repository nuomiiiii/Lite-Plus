package models

import "time"

type ClientProtectionConfig struct {
	Client            string     `json:"-" gorm:"type:varchar(36);primaryKey"`
	Revision          uint64     `json:"revision" gorm:"not null;default:0"`
	Enabled           bool       `json:"enabled" gorm:"not null;default:false"`
	RuntimeWanted     bool       `json:"runtime_wanted" gorm:"not null;default:false"`
	WhitelistJSON     string     `json:"-" gorm:"type:longtext;not null;default:'[]'"`
	SourcesJSON       string     `json:"-" gorm:"type:longtext;not null;default:'[]'"`
	PoliciesJSON      string     `json:"-" gorm:"type:longtext;not null;default:'[]'"`
	DeliveryStatus    string     `json:"delivery_status" gorm:"type:varchar(16);not null;default:''"`
	DeliveryError     string     `json:"delivery_error" gorm:"type:varchar(512);not null;default:''"`
	AppliedRevision   uint64     `json:"applied_revision" gorm:"not null;default:0"`
	CapabilityJSON    string     `json:"-" gorm:"type:longtext;not null;default:''"`
	CapabilityAt      *time.Time `json:"capability_at,omitempty"`
	ReportJSON        string     `json:"-" gorm:"type:longtext;not null;default:''"`
	DeliveryUpdatedAt *time.Time `json:"delivery_updated_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (ClientProtectionConfig) TableName() string { return "client_protection_configs" }

type ProtectionGroup struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name      string    `json:"name" gorm:"type:varchar(100);not null"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	Revision  uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ProtectionGroup) TableName() string { return "protection_groups" }

type ProtectionGroupMember struct {
	ID               uint      `json:"-" gorm:"primaryKey"`
	GroupID          string    `json:"group_id" gorm:"type:varchar(36);not null;uniqueIndex:uidx_prot_member"`
	Client           string    `json:"client" gorm:"type:varchar(36);not null;uniqueIndex:uidx_prot_member"`
	AppliedRevision  uint64    `json:"applied_revision" gorm:"not null;default:0"`
	DeliveryStatus   string    `json:"delivery_status" gorm:"type:varchar(16);not null;default:''"`
	DeliveryError    string    `json:"delivery_error" gorm:"type:varchar(512);not null;default:''"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (ProtectionGroupMember) TableName() string { return "protection_group_members" }

type ProtectionGroupLeave struct {
	GroupID           string     `json:"group_id" gorm:"type:varchar(36);primaryKey"`
	Client            string     `json:"client" gorm:"type:varchar(36);primaryKey"`
	Revision          uint64     `json:"revision" gorm:"not null;default:0"`
	DeliveryStatus    string     `json:"delivery_status" gorm:"type:varchar(16);not null;default:''"`
	DeliveryError     string     `json:"delivery_error" gorm:"type:varchar(512);not null;default:''"`
	DeliveryUpdatedAt *time.Time `json:"delivery_updated_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (ProtectionGroupLeave) TableName() string { return "protection_group_leaves" }

type ProtectionBan struct {
	BanID           string     `json:"ban_id" gorm:"type:varchar(128);primaryKey"`
	EventID         string     `json:"event_id" gorm:"type:varchar(128);not null;uniqueIndex"`
	IP              string     `json:"ip" gorm:"type:varchar(64);not null;index"`
	SourceNode      string     `json:"source_node" gorm:"type:varchar(36);not null;index"`
	PolicyID        string     `json:"policy_id" gorm:"type:varchar(36);not null;default:''"`
	ReasonType      string     `json:"reason_type" gorm:"type:varchar(32);not null"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at;index"`
	GroupID         string     `json:"group_id" gorm:"type:varchar(36);not null;default:'';index"`
	Status          string     `json:"status" gorm:"type:varchar(16);not null;default:'active';index"`
	RevokedRevision uint64     `json:"revoked_revision" gorm:"not null;default:0"`
}

func (ProtectionBan) TableName() string { return "protection_bans" }

type ProtectionRevoke struct {
	GroupID  string    `json:"group_id" gorm:"type:varchar(36);primaryKey"`
	IP       string    `json:"ip" gorm:"type:varchar(64);primaryKey"`
	Revision uint64    `json:"revision" gorm:"not null;default:0"`
	ResetAt  time.Time `json:"reset_at"`
}

func (ProtectionRevoke) TableName() string { return "protection_revokes" }

type ProtectionUpgradeOp struct {
	ID         string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	Client     string     `json:"client" gorm:"type:varchar(36);not null;index"`
	Phase      string     `json:"phase" gorm:"type:varchar(24);not null"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Result     string     `json:"result" gorm:"type:varchar(24);not null;default:''"`
	Error      string     `json:"error" gorm:"type:varchar(512);not null;default:''"`
	RequestID  string     `json:"request_id" gorm:"type:varchar(32);not null;default:''"`
}

func (ProtectionUpgradeOp) TableName() string { return "protection_upgrade_ops" }
