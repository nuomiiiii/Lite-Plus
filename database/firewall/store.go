package firewall

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/database/models"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	DeliveryPending     = "pending"
	DeliveryQueued      = "queued"
	DeliverySent        = "sent"
	DeliveryApplied     = "applied"
	DeliveryFailed      = "failed"
	DeliveryUnsupported = "unsupported"
)

func Get(clientUUID string) (*models.ClientFirewallIntent, error) {
	clientUUID = strings.TrimSpace(clientUUID)
	if clientUUID == "" {
		return nil, nil
	}
	var row models.ClientFirewallIntent
	err := dbcore.GetDBInstance().Where("client = ?", clientUUID).Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func SaveIntent(clientUUID string, intent v2.FirewallIntent) (*models.ClientFirewallIntent, error) {
	clientUUID = strings.TrimSpace(clientUUID)
	now := time.Now().UTC()
	raw, err := json.Marshal(intent.Rules)
	if err != nil {
		return nil, err
	}
	row, err := Get(clientUUID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		row = &models.ClientFirewallIntent{
			Client:    clientUUID,
			CreatedAt: now,
		}
	}
	v2.UnifyPairedPolicy(&intent)
	row.Revision++
	row.BlockPing4 = intent.BlockPing4
	row.BlockPing6 = intent.BlockPing6
	row.DefaultDeny4 = intent.DefaultDeny4
	row.DefaultDeny6 = intent.DefaultDeny6
	row.SshPort = strings.TrimSpace(intent.SshPort)
	row.OmitKeep = strings.Join(intent.OmitKeep, ",")
	row.RulesJSON = string(raw)
	row.DeliveryStatus = DeliveryPending
	row.DeliveryError = ""
	row.UpdatedAt = now
	row.DeliveryUpdatedAt = &now
	err = dbcore.GetDBInstance().Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(row).Error
	return row, err
}

func IntentFromRow(row *models.ClientFirewallIntent) v2.FirewallIntent {
	if row == nil {
		return v2.FirewallIntent{Rules: []v2.FirewallRule{}}
	}
	rules := []v2.FirewallRule{}
	if strings.TrimSpace(row.RulesJSON) != "" {
		_ = json.Unmarshal([]byte(row.RulesJSON), &rules)
	}
	if rules == nil {
		rules = []v2.FirewallRule{}
	}
	intent := v2.FirewallIntent{
		Revision:     row.Revision,
		BlockPing4:   row.BlockPing4,
		BlockPing6:   row.BlockPing6,
		DefaultDeny4: row.DefaultDeny4,
		DefaultDeny6: row.DefaultDeny6,
		SshPort:      strings.TrimSpace(row.SshPort),
		OmitKeep:     splitOmitKeep(row.OmitKeep),
		Rules:        rules,
	}
	v2.UnifyPairedPolicy(&intent)
	return intent
}

func HealPairedPolicy(row *models.ClientFirewallIntent) (bool, error) {
	if row == nil {
		return false, nil
	}
	intent := IntentFromRow(row)
	if row.BlockPing4 == intent.BlockPing4 && row.BlockPing6 == intent.BlockPing6 && row.DefaultDeny4 == intent.DefaultDeny4 && row.DefaultDeny6 == intent.DefaultDeny6 {
		return false, nil
	}
	now := time.Now().UTC()
	if err := dbcore.GetDBInstance().Model(row).Updates(map[string]any{
		"block_ping_v4":   intent.BlockPing4,
		"block_ping_v6":   intent.BlockPing6,
		"default_deny_v4": intent.DefaultDeny4,
		"default_deny_v6": intent.DefaultDeny6,
		"updated_at":      now,
	}).Error; err != nil {
		return false, err
	}
	row.BlockPing4 = intent.BlockPing4
	row.BlockPing6 = intent.BlockPing6
	row.DefaultDeny4 = intent.DefaultDeny4
	row.DefaultDeny6 = intent.DefaultDeny6
	row.UpdatedAt = now
	return true, nil
}

func splitOmitKeep(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func MarkDelivery(clientUUID, status, message string, appliedRevision uint64) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"delivery_status":     status,
		"delivery_error":      strings.TrimSpace(message),
		"delivery_updated_at": now,
		"updated_at":          now,
	}
	if appliedRevision > 0 {
		updates["applied_revision"] = appliedRevision
	}
	return dbcore.GetDBInstance().Model(&models.ClientFirewallIntent{}).
		Where("client = ?", clientUUID).
		Updates(updates).Error
}

func RevertSshPort(clientUUID, port string) error {
	clientUUID = strings.TrimSpace(clientUUID)
	if clientUUID == "" {
		return nil
	}
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ClientFirewallIntent{}).
		Where("client = ?", clientUUID).
		Updates(map[string]any{
			"ssh_port":   strings.TrimSpace(port),
			"updated_at": now,
		}).Error
}

func SaveSnapshot(clientUUID string, snapshot v2.FirewallResultParams) error {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ClientFirewallIntent{}).
		Where("client = ?", clientUUID).
		Updates(map[string]any{
			"snapshot_json": string(raw),
			"snapshot_at":   now,
			"updated_at":    now,
		}).Error
}

func SnapshotFromRow(row *models.ClientFirewallIntent) *v2.FirewallResultParams {
	if row == nil || strings.TrimSpace(row.SnapshotJSON) == "" {
		return nil
	}
	var snapshot v2.FirewallResultParams
	if err := json.Unmarshal([]byte(row.SnapshotJSON), &snapshot); err != nil {
		return nil
	}
	return &snapshot
}

func DueApplies() ([]models.ClientFirewallIntent, error) {
	var rows []models.ClientFirewallIntent
	err := dbcore.GetDBInstance().
		Where("revision > applied_revision AND delivery_status IN ?", []string{DeliveryPending, DeliveryQueued, DeliverySent, DeliveryFailed}).
		Find(&rows).Error
	return rows, err
}

func DisableDefaultDeny(clientUUID string) error {
	clientUUID = strings.TrimSpace(clientUUID)
	if clientUUID == "" {
		return nil
	}
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ClientFirewallIntent{}).
		Where("client = ?", clientUUID).
		Updates(map[string]any{
			"default_deny_v4": false,
			"default_deny_v6": false,
			"updated_at":      now,
		}).Error
}

func DeleteClient(clientUUID string) error {
	return dbcore.GetDBInstance().Where("client = ?", clientUUID).Delete(&models.ClientFirewallIntent{}).Error
}

func EnsureRow(clientUUID string) (*models.ClientFirewallIntent, error) {
	row, err := Get(clientUUID)
	if err != nil || row != nil {
		return row, err
	}
	now := time.Now().UTC()
	row = &models.ClientFirewallIntent{
		Client:    clientUUID,
		RulesJSON: "[]",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := dbcore.GetDBInstance().Create(row).Error; err != nil {
		return nil, err
	}
	return row, nil
}
