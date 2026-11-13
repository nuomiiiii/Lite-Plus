package protection

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

func GetConfig(uuid string) (*models.ClientProtectionConfig, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil, nil
	}
	var row models.ClientProtectionConfig
	err := dbcore.GetDBInstance().Where("client = ?", uuid).Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func EnsureConfig(uuid string) (*models.ClientProtectionConfig, error) {
	row, err := GetConfig(uuid)
	if err != nil {
		return nil, err
	}
	if row != nil {
		return row, nil
	}
	now := time.Now().UTC()
	row = &models.ClientProtectionConfig{
		Client:        uuid,
		WhitelistJSON: "[]",
		SourcesJSON:   "[]",
		PoliciesJSON:  "[]",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := dbcore.GetDBInstance().Create(row).Error; err != nil {
		return nil, err
	}
	return row, nil
}

func SaveConfig(uuid string, cfg v2.ProtectionConfig) (*models.ClientProtectionConfig, error) {
	row, err := EnsureConfig(uuid)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	row.Revision++
	row.Enabled = cfg.Enabled
	row.RuntimeWanted = cfg.RuntimeEnabled
	row.WhitelistJSON = marshalJSON(cfg.Whitelist)
	row.SourcesJSON = marshalJSON(cfg.Sources)
	row.PoliciesJSON = marshalJSON(cfg.Policies)
	row.DeliveryStatus = DeliveryPending
	row.DeliveryError = ""
	row.UpdatedAt = now
	row.DeliveryUpdatedAt = &now
	err = dbcore.GetDBInstance().Clauses(clause.OnConflict{UpdateAll: true}).Create(row).Error
	return row, err
}

func ConfigFromRow(row *models.ClientProtectionConfig) v2.ProtectionConfig {
	if row == nil {
		return v2.ProtectionConfig{}
	}
	cfg := v2.ProtectionConfig{
		Revision:       row.Revision,
		Enabled:        row.Enabled,
		RuntimeEnabled: row.RuntimeWanted,
	}
	_ = json.Unmarshal([]byte(row.WhitelistJSON), &cfg.Whitelist)
	_ = json.Unmarshal([]byte(row.SourcesJSON), &cfg.Sources)
	_ = json.Unmarshal([]byte(row.PoliciesJSON), &cfg.Policies)
	if cfg.Sources == nil {
		cfg.Sources = []v2.ProtectionLogSource{}
	}
	if cfg.Policies == nil {
		cfg.Policies = []v2.ProtectionPolicy{}
	}
	return cfg
}

func MarkRuntimeWanted(uuid string, wanted bool) error {
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ClientProtectionConfig{}).Where("client = ?", uuid).Updates(map[string]any{
		"runtime_wanted": wanted,
		"updated_at":     now,
	}).Error
}

func MarkDelivery(uuid, status, msg string, applied uint64) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"delivery_status":     status,
		"delivery_error":      strings.TrimSpace(msg),
		"delivery_updated_at": now,
		"updated_at":          now,
	}
	if applied > 0 {
		updates["applied_revision"] = applied
	}
	return dbcore.GetDBInstance().Model(&models.ClientProtectionConfig{}).Where("client = ?", uuid).Updates(updates).Error
}

func SaveCapability(uuid string, cap v2.ProtectionCapability) error {
	now := time.Now().UTC()
	raw, _ := json.Marshal(cap)
	return dbcore.GetDBInstance().Model(&models.ClientProtectionConfig{}).Where("client = ?", uuid).Updates(map[string]any{
		"capability_json": string(raw),
		"capability_at":   now,
		"updated_at":      now,
	}).Error
}

func CapabilityFromRow(row *models.ClientProtectionConfig) *v2.ProtectionCapability {
	if row == nil || strings.TrimSpace(row.CapabilityJSON) == "" {
		return nil
	}
	var cap v2.ProtectionCapability
	if json.Unmarshal([]byte(row.CapabilityJSON), &cap) != nil {
		return nil
	}
	return &cap
}

const (
	maxStoredObserveHits  = 20
	maxStoredActivityBans = 50
	activityRetention     = 7 * 24 * time.Hour
	activityCleanupBatch  = 5000
)

func activityCutoff(now time.Time) time.Time {
	return now.UTC().Add(-activityRetention)
}

func parseActivityTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, value)
	}
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func protectionBanLive(status string, expiresAt, now time.Time) bool {
	return status != v2.ProtectionBanRevoked && expiresAt.After(now)
}

func protectionActivityStale(status string, createdAt, expiresAt, now time.Time) bool {
	if protectionBanLive(status, expiresAt, now) {
		return false
	}
	cutoff := activityCutoff(now)
	if v2.ProtectionBanNever(expiresAt) {
		return !createdAt.IsZero() && !createdAt.After(cutoff)
	}
	last := createdAt
	if expiresAt.After(last) {
		last = expiresAt
	}
	return !last.IsZero() && !last.After(cutoff)
}

func pruneReportHits(hits []v2.ProtectionBanReason, now time.Time) []v2.ProtectionBanReason {
	out := hits[:0]
	for _, hit := range hits {
		if protectionActivityStale(hit.Status, parseActivityTime(hit.CreatedAt), parseActivityTime(hit.ExpiresAt), now) {
			continue
		}
		out = append(out, hit)
	}
	if len(out) > maxStoredObserveHits {
		out = out[len(out)-maxStoredObserveHits:]
	}
	return out
}

func PruneExpiredActivity(now time.Time) error {
	return pruneExpiredActivity(dbcore.GetDBInstance(), now)
}

func pruneExpiredActivity(db *gorm.DB, now time.Time) error {
	if db == nil {
		return nil
	}
	now = now.UTC()
	cutoff := activityCutoff(now)
	for {
		var ids []string
		err := db.Model(&models.ProtectionBan{}).
			Where("(status = ? AND created_at < ?) OR expires_at < ?", v2.ProtectionBanRevoked, cutoff, cutoff).
			Limit(activityCleanupBatch).
			Pluck("ban_id", &ids).Error
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		if err := db.Where("ban_id IN ?", ids).Delete(&models.ProtectionBan{}).Error; err != nil {
			return err
		}
	}
	var rows []models.ClientProtectionConfig
	if err := db.Where("report_json <> '' AND report_json <> 'null'").Find(&rows).Error; err != nil {
		return err
	}
	for i := range rows {
		report := ReportFromRow(&rows[i])
		if report == nil || len(report.Hits) == 0 {
			continue
		}
		next := pruneReportHits(append([]v2.ProtectionBanReason(nil), report.Hits...), now)
		if len(next) == len(report.Hits) {
			continue
		}
		report.Hits = next
		raw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		if err := db.Model(&models.ClientProtectionConfig{}).Where("client = ?", rows[i].Client).Updates(map[string]any{
			"report_json": string(raw),
			"updated_at":  now,
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

func SaveReport(uuid string, report v2.ProtectionReportParams) error {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil
	}
	row, err := EnsureConfig(uuid)
	if err != nil || row == nil {
		return err
	}
	merged := ReportFromRow(row)
	if merged == nil {
		merged = &v2.ProtectionReportParams{}
	}
	if len(report.SourceStats) > 0 {
		merged.SourceStats = report.SourceStats
	}
	if len(report.Hits) > 0 {
		merged.Hits = pruneReportHits(append(merged.Hits, report.Hits...), time.Now().UTC())
	}
	if len(report.Nflog) > 0 {
		merged.Nflog = report.Nflog
	}
	if report.ConfigRev > 0 {
		merged.ConfigRev = report.ConfigRev
	}
	if strings.TrimSpace(report.Error) != "" {
		merged.Error = report.Error
	} else {
		merged.Error = ""
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ClientProtectionConfig{}).Where("client = ?", uuid).Updates(map[string]any{
		"report_json": string(raw),
		"updated_at":  now,
	}).Error
}

func ReportFromRow(row *models.ClientProtectionConfig) *v2.ProtectionReportParams {
	if row == nil || strings.TrimSpace(row.ReportJSON) == "" {
		return nil
	}
	var report v2.ProtectionReportParams
	if json.Unmarshal([]byte(row.ReportJSON), &report) != nil {
		return nil
	}
	return &report
}

func ListGroups() ([]models.ProtectionGroup, error) {
	var rows []models.ProtectionGroup
	err := dbcore.GetDBInstance().Order("name").Find(&rows).Error
	return rows, err
}

func GetGroup(id string) (*models.ProtectionGroup, error) {
	var row models.ProtectionGroup
	err := dbcore.GetDBInstance().Where("id = ?", id).Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func SaveGroup(row *models.ProtectionGroup) error {
	now := time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	row.UpdatedAt = now
	return dbcore.GetDBInstance().Clauses(clause.OnConflict{UpdateAll: true}).Create(row).Error
}

func DeleteGroup(id string) error {
	db := dbcore.GetDBInstance()
	if err := db.Where("group_id = ?", id).Delete(&models.ProtectionGroupMember{}).Error; err != nil {
		return err
	}
	return db.Where("id = ?", id).Delete(&models.ProtectionGroup{}).Error
}

func ClaimSharedFanout(groupID, source, ip, eventID string, created time.Time) (uint64, bool, error) {
	groupID = strings.TrimSpace(groupID)
	source = strings.TrimSpace(source)
	ip = strings.TrimSpace(ip)
	if groupID == "" || source == "" || ip == "" {
		return 0, false, nil
	}
	var revision uint64
	claimed := false
	err := dbcore.GetDBInstance().Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		res := tx.Model(&models.ProtectionGroup{}).Where("id = ?", groupID).Updates(map[string]any{
			"updated_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		var group models.ProtectionGroup
		if err := tx.Where("id = ?", groupID).Take(&group).Error; err != nil {
			return err
		}
		if !group.Enabled {
			return nil
		}
		var members int64
		if err := tx.Model(&models.ProtectionGroupMember{}).Where("group_id = ? AND client = ?", groupID, source).Count(&members).Error; err != nil {
			return err
		}
		if members == 0 {
			return nil
		}
		var revoke models.ProtectionRevoke
		rerr := tx.Where("group_id = ? AND ip = ?", groupID, ip).Take(&revoke).Error
		if rerr == nil && eventBeforeReset(created, revoke.ResetAt) {
			return nil
		}
		if rerr != nil && rerr != gorm.ErrRecordNotFound {
			return rerr
		}
		if eventID = strings.TrimSpace(eventID); eventID != "" {
			var ban models.ProtectionBan
			berr := tx.Where("event_id = ?", eventID).Take(&ban).Error
			if berr == nil && ban.Status == v2.ProtectionBanRevoked {
				return nil
			}
			if berr != nil && berr != gorm.ErrRecordNotFound {
				return berr
			}
		}
		bump := tx.Model(&models.ProtectionGroup{}).Where("id = ?", groupID).Updates(map[string]any{
			"revision":   gorm.Expr("revision + 1"),
			"updated_at": now,
		})
		if bump.Error != nil {
			return bump.Error
		}
		if err := tx.Where("id = ?", groupID).Take(&group).Error; err != nil {
			return err
		}
		revision = group.Revision
		claimed = true
		return nil
	})
	return revision, claimed, err
}

func eventBeforeReset(created, resetAt time.Time) bool {
	if resetAt.IsZero() || created.IsZero() {
		return true
	}
	return !created.UTC().After(resetAt.UTC())
}

func BumpGroupRevision(id string) (uint64, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, nil
	}
	db := dbcore.GetDBInstance()
	now := time.Now().UTC()
	tx := db.Begin()
	if tx.Error != nil {
		return 0, tx.Error
	}
	res := tx.Model(&models.ProtectionGroup{}).Where("id = ?", id).Updates(map[string]any{
		"revision":   gorm.Expr("revision + 1"),
		"updated_at": now,
	})
	if res.Error != nil {
		tx.Rollback()
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		tx.Rollback()
		return 0, gorm.ErrRecordNotFound
	}
	var row models.ProtectionGroup
	if err := tx.Where("id = ?", id).Take(&row).Error; err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	return row.Revision, nil
}

func UpdateGroupAndBump(id, name string, enabled bool) (*models.ProtectionGroup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, gorm.ErrRecordNotFound
	}
	db := dbcore.GetDBInstance()
	now := time.Now().UTC()
	tx := db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	updates := map[string]any{
		"enabled":    enabled,
		"revision":   gorm.Expr("revision + 1"),
		"updated_at": now,
	}
	if strings.TrimSpace(name) != "" {
		updates["name"] = strings.TrimSpace(name)
	}
	res := tx.Model(&models.ProtectionGroup{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		tx.Rollback()
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		tx.Rollback()
		return nil, gorm.ErrRecordNotFound
	}
	var row models.ProtectionGroup
	if err := tx.Where("id = ?", id).Take(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func ListMembers(groupID string) ([]models.ProtectionGroupMember, error) {
	var rows []models.ProtectionGroupMember
	err := dbcore.GetDBInstance().Where("group_id = ?", groupID).Find(&rows).Error
	return rows, err
}

func ListMemberships(uuid string) ([]models.ProtectionGroupMember, error) {
	var rows []models.ProtectionGroupMember
	err := dbcore.GetDBInstance().Where("client = ?", uuid).Find(&rows).Error
	return rows, err
}

func ReplaceMembers(groupID string, clients []string) error {
	db := dbcore.GetDBInstance()
	if err := db.Where("group_id = ?", groupID).Delete(&models.ProtectionGroupMember{}).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, uuid := range clients {
		uuid = strings.TrimSpace(uuid)
		if uuid == "" {
			continue
		}
		row := models.ProtectionGroupMember{GroupID: groupID, Client: uuid, UpdatedAt: now}
		if err := db.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func IsMember(groupID, uuid string) bool {
	groupID = strings.TrimSpace(groupID)
	uuid = strings.TrimSpace(uuid)
	if groupID == "" || uuid == "" {
		return false
	}
	var n int64
	if err := dbcore.GetDBInstance().Model(&models.ProtectionGroupMember{}).Where("group_id = ? AND client = ?", groupID, uuid).Count(&n).Error; err != nil {
		return false
	}
	return n > 0
}

func RecordLeave(groupID, uuid string, revision uint64) error {
	groupID = strings.TrimSpace(groupID)
	uuid = strings.TrimSpace(uuid)
	if groupID == "" || uuid == "" {
		return nil
	}
	now := time.Now().UTC()
	row := models.ProtectionGroupLeave{
		GroupID:           groupID,
		Client:            uuid,
		Revision:          revision,
		DeliveryStatus:    DeliveryPending,
		DeliveryError:     "",
		DeliveryUpdatedAt: &now,
		CreatedAt:         now,
	}
	return dbcore.GetDBInstance().Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error
}

func ListPendingLeaves(uuid string) ([]models.ProtectionGroupLeave, error) {
	var rows []models.ProtectionGroupLeave
	err := dbcore.GetDBInstance().Where("client = ?", strings.TrimSpace(uuid)).Find(&rows).Error
	return rows, err
}

func ClearLeave(groupID, uuid string) error {
	return dbcore.GetDBInstance().Where("group_id = ? AND client = ?", groupID, uuid).Delete(&models.ProtectionGroupLeave{}).Error
}

func MarkLeave(groupID, uuid, status, msg string) error {
	now := time.Now().UTC()
	return dbcore.GetDBInstance().Model(&models.ProtectionGroupLeave{}).Where("group_id = ? AND client = ?", groupID, uuid).Updates(map[string]any{
		"delivery_status":     status,
		"delivery_error":      strings.TrimSpace(msg),
		"delivery_updated_at": now,
	}).Error
}

func MarkMember(groupID, uuid, status, msg string, applied uint64) error {
	updates := map[string]any{
		"delivery_status": status,
		"delivery_error":  strings.TrimSpace(msg),
		"updated_at":      time.Now().UTC(),
	}
	if applied > 0 {
		updates["applied_revision"] = applied
	}
	return dbcore.GetDBInstance().Model(&models.ProtectionGroupMember{}).Where("group_id = ? AND client = ?", groupID, uuid).Updates(updates).Error
}

func UpsertBan(row models.ProtectionBan) (bool, error) {
	if strings.TrimSpace(row.GroupID) != "" {
		return upsertGroupBan(row)
	}
	return upsertBanRow(dbcore.GetDBInstance(), row)
}

func upsertGroupBan(row models.ProtectionBan) (bool, error) {
	var inserted bool
	err := dbcore.GetDBInstance().Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		res := tx.Model(&models.ProtectionGroup{}).Where("id = ?", row.GroupID).Updates(map[string]any{
			"updated_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			row.GroupID = ""
			ok, err := upsertBanRow(tx, row)
			inserted = ok
			return err
		}
		var revoke models.ProtectionRevoke
		rerr := tx.Where("group_id = ? AND ip = ?", row.GroupID, row.IP).Take(&revoke).Error
		if rerr == nil && eventBeforeReset(row.CreatedAt, revoke.ResetAt) {
			row.Status = v2.ProtectionBanRevoked
			row.RevokedRevision = revoke.Revision
		} else if rerr != nil && rerr != gorm.ErrRecordNotFound {
			return rerr
		}
		ok, err := upsertBanRow(tx, row)
		inserted = ok
		return err
	})
	return inserted, err
}

func upsertBanRow(db *gorm.DB, row models.ProtectionBan) (bool, error) {
	if row.Status == "" {
		row.Status = v2.ProtectionBanActive
	}
	var existing models.ProtectionBan
	err := db.Where("event_id = ?", row.EventID).Take(&existing).Error
	if err == gorm.ErrRecordNotFound {
		if err := db.Create(&row).Error; err != nil {
			return false, err
		}
		return row.Status == v2.ProtectionBanActive, nil
	}
	if err != nil {
		return false, err
	}
	if existing.Status == v2.ProtectionBanRevoked && row.Status == v2.ProtectionBanActive {
		err := db.Model(&models.ProtectionBan{}).Where("event_id = ?", row.EventID).Updates(map[string]any{
			"status":           v2.ProtectionBanActive,
			"expires_at":       row.ExpiresAt,
			"created_at":       row.CreatedAt,
			"source_node":      row.SourceNode,
			"policy_id":        row.PolicyID,
			"reason_type":      row.ReasonType,
			"group_id":         row.GroupID,
			"revoked_revision": 0,
		}).Error
		return err == nil, err
	}
	if existing.Status == v2.ProtectionBanActive && row.Status == v2.ProtectionBanRevoked {
		return false, db.Model(&models.ProtectionBan{}).Where("event_id = ?", row.EventID).Updates(map[string]any{
			"status":           v2.ProtectionBanRevoked,
			"revoked_revision": row.RevokedRevision,
		}).Error
	}
	return false, nil
}

func GetBanByEvent(eventID string) (*models.ProtectionBan, error) {
	var row models.ProtectionBan
	err := dbcore.GetDBInstance().Where("event_id = ?", eventID).Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func ListActiveBans(uuid string) ([]models.ProtectionBan, error) {
	var rows []models.ProtectionBan
	now := time.Now().UTC()
	q := dbcore.GetDBInstance().Where("status = ? AND expires_at > ?", v2.ProtectionBanActive, now)
	if uuid != "" {
		q = q.Where("source_node = ? OR group_id IN (SELECT group_id FROM protection_group_members WHERE client = ?)", uuid, uuid)
	}
	err := q.Order("expires_at").Find(&rows).Error
	return rows, err
}

func ListRecentBans(uuid string, limit int) ([]models.ProtectionBan, error) {
	if limit <= 0 {
		limit = maxStoredActivityBans
	}
	var rows []models.ProtectionBan
	q := dbcore.GetDBInstance()
	if uuid != "" {
		q = q.Where("source_node = ? OR group_id IN (SELECT group_id FROM protection_group_members WHERE client = ?)", uuid, uuid)
	}
	err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

func ListGroupBans(groupID string) ([]models.ProtectionBan, error) {
	var rows []models.ProtectionBan
	now := time.Now().UTC()
	err := dbcore.GetDBInstance().Where("group_id = ? AND status = ? AND expires_at > ?", groupID, v2.ProtectionBanActive, now).Find(&rows).Error
	return rows, err
}

func RevokeGroupIP(groupID, ip string, resetAt time.Time) (uint64, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return 0, nil
	}
	var revision uint64
	err := dbcore.GetDBInstance().Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		res := tx.Model(&models.ProtectionGroup{}).Where("id = ?", groupID).Updates(map[string]any{
			"revision":   gorm.Expr("revision + 1"),
			"updated_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		var group models.ProtectionGroup
		if err := tx.Where("id = ?", groupID).Take(&group).Error; err != nil {
			return err
		}
		revision = group.Revision
		if err := tx.Model(&models.ProtectionBan{}).Where("group_id = ? AND ip = ? AND status = ?", groupID, ip, v2.ProtectionBanActive).Updates(map[string]any{
			"status":           v2.ProtectionBanRevoked,
			"revoked_revision": revision,
		}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.ProtectionBan{}).Where("ip = ? AND reason_type IN ? AND status = ? AND group_id = ?", ip, v2.ProtectionAutoBanReasons(), v2.ProtectionBanActive, groupID).Updates(map[string]any{
			"status":           v2.ProtectionBanRevoked,
			"revoked_revision": revision,
		}).Error; err != nil {
			return err
		}
		row := models.ProtectionRevoke{GroupID: groupID, IP: ip, Revision: revision, ResetAt: resetAt}
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error
	})
	return revision, err
}

func LoadGroupSnapshot(groupID string) (uint64, []models.ProtectionBan, map[string]v2.ProtectionRevoke, error) {
	var revision uint64
	var bans []models.ProtectionBan
	revoked := map[string]v2.ProtectionRevoke{}
	err := dbcore.GetDBInstance().Transaction(func(tx *gorm.DB) error {
		var group models.ProtectionGroup
		if err := tx.Where("id = ?", groupID).Take(&group).Error; err != nil {
			return err
		}
		revision = group.Revision
		now := time.Now().UTC()
		if err := tx.Where("group_id = ? AND status = ? AND expires_at > ?", groupID, v2.ProtectionBanActive, now).Find(&bans).Error; err != nil {
			return err
		}
		var rows []models.ProtectionRevoke
		if err := tx.Where("group_id = ?", groupID).Find(&rows).Error; err != nil {
			return err
		}
		resetAt := map[string]time.Time{}
		for _, row := range rows {
			revoked[row.IP] = v2.ProtectionRevoke{Revision: row.Revision, ResetAt: row.ResetAt.UTC().Format(time.RFC3339Nano)}
			resetAt[row.IP] = row.ResetAt
		}
		kept := bans[:0]
		for _, ban := range bans {
			if reset, ok := resetAt[ban.IP]; ok && eventBeforeReset(ban.CreatedAt, reset) {
				continue
			}
			kept = append(kept, ban)
		}
		bans = append([]models.ProtectionBan(nil), kept...)
		return nil
	})
	return revision, bans, revoked, err
}

func RevokeLocalIP(uuid, ip string) (int64, error) {
	res := dbcore.GetDBInstance().Model(&models.ProtectionBan{}).Where("source_node = ? AND ip = ? AND group_id = ? AND reason_type IN ? AND status = ?", uuid, ip, "", v2.ProtectionAutoBanReasons(), v2.ProtectionBanActive).Updates(map[string]any{
		"status": v2.ProtectionBanRevoked,
	})
	return res.RowsAffected, res.Error
}

func HasGroupedBan(uuid, ip string) bool {
	uuid = strings.TrimSpace(uuid)
	ip = strings.TrimSpace(ip)
	if uuid == "" || ip == "" {
		return false
	}
	var n int64
	now := time.Now().UTC()
	err := dbcore.GetDBInstance().Model(&models.ProtectionBan{}).Where(
		"ip = ? AND status = ? AND group_id <> ? AND expires_at > ? AND (source_node = ? OR group_id IN (SELECT group_id FROM protection_group_members WHERE client = ?))",
		ip, v2.ProtectionBanActive, "", now, uuid, uuid,
	).Count(&n).Error
	return err == nil && n > 0
}

func LocalAutoSourceNodes(groupID, ip string) map[string]bool {
	var rows []models.ProtectionBan
	err := dbcore.GetDBInstance().Where("ip = ? AND reason_type IN ? AND (group_id = ? OR (group_id = ? AND source_node IN (SELECT client FROM protection_group_members WHERE group_id = ?)))", ip, v2.ProtectionAutoBanReasons(), groupID, "", groupID).Find(&rows).Error
	if err != nil {
		return map[string]bool{}
	}
	out := map[string]bool{}
	for _, row := range rows {
		out[row.SourceNode] = true
	}
	return out
}

func RevokeWhitelisted(uuid string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	return dbcore.GetDBInstance().Model(&models.ProtectionBan{}).Where("status = ? AND ip IN ? AND (source_node = ? OR group_id IN (SELECT group_id FROM protection_group_members WHERE client = ?))", v2.ProtectionBanActive, ips, uuid, uuid).Updates(map[string]any{
		"status": v2.ProtectionBanRevoked,
	}).Error
}

func ListRevokes(groupID string) (map[string]v2.ProtectionRevoke, error) {
	var rows []models.ProtectionRevoke
	if err := dbcore.GetDBInstance().Where("group_id = ?", groupID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]v2.ProtectionRevoke{}
	for _, row := range rows {
		out[row.IP] = v2.ProtectionRevoke{Revision: row.Revision, ResetAt: row.ResetAt.UTC().Format(time.RFC3339Nano)}
	}
	return out, nil
}

func SaveUpgradeOp(row *models.ProtectionUpgradeOp) error {
	return dbcore.GetDBInstance().Clauses(clause.OnConflict{UpdateAll: true}).Create(row).Error
}

func LatestUpgradeOp(uuid string) (*models.ProtectionUpgradeOp, error) {
	var row models.ProtectionUpgradeOp
	err := dbcore.GetDBInstance().Where("client = ?", uuid).Order("started_at desc").Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func ActiveUpgradeOp(uuid string) (*models.ProtectionUpgradeOp, error) {
	var row models.ProtectionUpgradeOp
	err := dbcore.GetDBInstance().Where("client = ? AND finished_at IS NULL", uuid).Order("started_at desc").Take(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func DeleteClient(uuid string) error {
	db := dbcore.GetDBInstance()
	if err := db.Where("client = ?", uuid).Delete(&models.ClientProtectionConfig{}).Error; err != nil {
		return err
	}
	if err := db.Where("client = ?", uuid).Delete(&models.ProtectionGroupMember{}).Error; err != nil {
		return err
	}
	if err := db.Where("client = ?", uuid).Delete(&models.ProtectionGroupLeave{}).Error; err != nil {
		return err
	}
	if err := db.Where("source_node = ?", uuid).Delete(&models.ProtectionBan{}).Error; err != nil {
		return err
	}
	return db.Where("client = ?", uuid).Delete(&models.ProtectionUpgradeOp{}).Error
}

func marshalJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil || string(raw) == "null" {
		return "[]"
	}
	return string(raw)
}
