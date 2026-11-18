package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/pkg/trafficreset"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrNotFound     = errors.New("nodemgt: not found")
	ErrConflict     = errors.New("nodemgt: conflict")
	ErrInvalid      = errors.New("nodemgt: invalid")
	ErrQuota        = errors.New("nodemgt: quota exceeded")
	ErrUserDisabled = errors.New("nodemgt: user disabled")
	ErrUserExpired  = errors.New("nodemgt: user expired")
	ErrForbidden    = errors.New("nodemgt: node mismatch")

	OnSubSettingChange func()
)

type Store struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Store { return &Store{db: db} }

func (s *Store) saveAll(value any) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		attrs, err := columnAttrs(tx, value)
		if err != nil {
			return err
		}
		if err := tx.Model(value).Clauses(clause.OnConflict{DoNothing: true}).Create(attrs).Error; err != nil {
			return err
		}
		return tx.Select("*").Updates(value).Error
	})
}

func columnAttrs(tx *gorm.DB, value any) (map[string]any, error) {
	stmt := &gorm.Statement{DB: tx}
	if err := stmt.Parse(value); err != nil {
		return nil, err
	}
	rv := reflect.Indirect(reflect.ValueOf(value))
	attrs := make(map[string]any, len(stmt.Schema.DBNames))
	for _, name := range stmt.Schema.DBNames {
		field := stmt.Schema.FieldsByDBName[name]
		val, _ := field.ValueOf(context.Background(), rv)
		attrs[name] = val
	}
	return attrs, nil
}

func (s *Store) keepCreatedAt(model any, id string, created *time.Time) {
	if created == nil || !created.IsZero() || strings.TrimSpace(id) == "" {
		return
	}
	var t time.Time
	if err := s.db.Model(model).Where("id = ?", id).Select("created_at").Scan(&t).Error; err != nil || t.IsZero() {
		return
	}
	*created = t
}

func (s *Store) DB() *gorm.DB { return s.db }

func (s *Store) Migrate() error {
	if err := dropLegacyUserIPIndex(s.db); err != nil {
		return err
	}
	if err := dropLegacySubscriptionTokenIndex(s.db); err != nil {
		return err
	}
	if err := s.db.AutoMigrate(models.All()...); err != nil {
		return err
	}
	if err := s.backfillCertAutoRenew(); err != nil {
		return err
	}
	if err := s.pruneOrphanGrants(); err != nil {
		return err
	}
	if err := s.migrateAuditEventsToLogs(); err != nil {
		return err
	}
	return s.PurgeMissingNodes()
}

func (s *Store) pruneOrphanGrants() error {
	if !s.db.Migrator().HasTable(&models.Grant{}) || !s.db.Migrator().HasTable(&models.Inbound{}) {
		return nil
	}
	return s.db.Where("inbound_id NOT IN (?)", s.db.Model(&models.Inbound{}).Select("id")).Delete(&models.Grant{}).Error
}

func (s *Store) backfillCertAutoRenew() error {
	v, err := s.GetSetting("cert_auto_renew_backfill")
	if err == nil && v == "1" {
		return nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.db.Model(&models.Certificate{}).Where("1 = 1").Update("auto_renew", true).Error; err != nil {
		return err
	}
	if err := s.db.Model(&models.RootCertificate{}).Where("1 = 1").Update("auto_renew", true).Error; err != nil {
		return err
	}
	return s.SetSetting("cert_auto_renew_backfill", "1")
}

func dropLegacyUserIPIndex(db *gorm.DB) error {
	m := db.Migrator()
	if !m.HasTable(&models.UserIP{}) {
		return nil
	}
	for _, name := range []string{"uid_ip", "idx_nodemgt_user_ips_uid_ip"} {
		if !m.HasIndex(&models.UserIP{}, name) {
			continue
		}
		if err := m.DropIndex(&models.UserIP{}, name); err != nil {
			return err
		}
	}
	return nil
}

func dropLegacySubscriptionTokenIndex(db *gorm.DB) error {
	m := db.Migrator()
	if !m.HasTable(&models.Subscription{}) {
		return nil
	}
	for _, name := range []string{"idx_nodemgt_subscriptions_token", "uni_nodemgt_subscriptions_token"} {
		if !m.HasIndex(&models.Subscription{}, name) {
			continue
		}
		if err := m.DropIndex(&models.Subscription{}, name); err != nil {
			return err
		}
	}
	return nil
}

func sealInboundSecrets(settingsJSON, streamJSON string) (string, string, error) {
	outSettings := settingsJSON
	if strings.TrimSpace(settingsJSON) != "" {
		var m map[string]any
		if json.Unmarshal([]byte(settingsJSON), &m) == nil && m != nil {
			changed := false
			for _, key := range []string{"reality_private_key", "ss_password"} {
				if raw, ok := m[key].(string); ok && strings.TrimSpace(raw) != "" {
					enc, err := secretcrypt.Seal(raw)
					if err != nil {
						return "", "", err
					}
					if enc != raw {
						m[key] = enc
						changed = true
					}
				}
			}
			if accs, ok := m["accounts"].([]any); ok {
				for i := range accs {
					accMap, ok := accs[i].(map[string]any)
					if !ok {
						continue
					}
					if pass, ok := accMap["pass"].(string); ok && strings.TrimSpace(pass) != "" {
						enc, err := secretcrypt.Seal(pass)
						if err != nil {
							return "", "", err
						}
						if enc != pass {
							accMap["pass"] = enc
							changed = true
						}
					}
				}
			}
			if changed {
				if b, err := json.Marshal(m); err == nil {
					outSettings = string(b)
				}
			}
		}
	}
	outStream := streamJSON
	if strings.TrimSpace(streamJSON) != "" {
		var sm map[string]any
		if json.Unmarshal([]byte(streamJSON), &sm) == nil && sm != nil {
			if reality, ok := sm["realitySettings"].(map[string]any); ok {
				if pk, ok := reality["privateKey"].(string); ok && strings.TrimSpace(pk) != "" {
					enc, err := secretcrypt.Seal(pk)
					if err != nil {
						return "", "", err
					}
					if enc != pk {
						reality["privateKey"] = enc
						if b, err := json.Marshal(sm); err == nil {
							outStream = string(b)
						}
					}
				}
			}
		}
	}
	return outSettings, outStream, nil
}

const sqliteChunkSize = 500

func chunkStrings(ids []string, size int) [][]string {
	if size <= 0 {
		size = sqliteChunkSize
	}
	if len(ids) == 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(ids)+size-1)/size)
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[start:end])
	}
	return chunks
}

func openInboundSecretsStrict(row models.Inbound) (models.Inbound, error) {
	if strings.TrimSpace(row.SettingsJSON) != "" && strings.Contains(row.SettingsJSON, secretcrypt.Prefix) {
		var m map[string]any
		if json.Unmarshal([]byte(row.SettingsJSON), &m) == nil && m != nil {
			changed := false
			for _, key := range []string{"reality_private_key", "ss_password"} {
				if raw, ok := m[key].(string); ok && strings.HasPrefix(raw, secretcrypt.Prefix) {
					plain, err := secretcrypt.Open(raw)
					if err != nil {
						return row, fmt.Errorf("decrypt inbound %s %s: %w", row.ID, key, err)
					}
					m[key] = plain
					changed = true
				}
			}
			if accs, ok := m["accounts"].([]any); ok {
				for i := range accs {
					accMap, ok := accs[i].(map[string]any)
					if !ok {
						continue
					}
					if pass, ok := accMap["pass"].(string); ok && strings.HasPrefix(pass, secretcrypt.Prefix) {
						plain, err := secretcrypt.Open(pass)
						if err != nil {
							return row, fmt.Errorf("decrypt inbound %s account password: %w", row.ID, err)
						}
						accMap["pass"] = plain
						changed = true
					}
				}
			}
			if changed {
				if b, err := json.Marshal(m); err == nil {
					row.SettingsJSON = string(b)
				}
			}
		}
	}
	if strings.TrimSpace(row.StreamJSON) != "" && strings.Contains(row.StreamJSON, secretcrypt.Prefix) {
		var sm map[string]any
		if json.Unmarshal([]byte(row.StreamJSON), &sm) == nil && sm != nil {
			if reality, ok := sm["realitySettings"].(map[string]any); ok {
				if pk, ok := reality["privateKey"].(string); ok && strings.HasPrefix(pk, secretcrypt.Prefix) {
					plain, err := secretcrypt.Open(pk)
					if err != nil {
						return row, fmt.Errorf("decrypt inbound %s stream privateKey: %w", row.ID, err)
					}
					reality["privateKey"] = plain
					if b, err := json.Marshal(sm); err == nil {
						row.StreamJSON = string(b)
					}
				}
			}
		}
	}
	return row, nil
}

func openOutboundSecretsStrict(row models.Outbound) (models.Outbound, error) {
	if strings.TrimSpace(row.SettingsJSON) == "" || !strings.Contains(row.SettingsJSON, secretcrypt.Prefix) {
		return row, nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(row.SettingsJSON), &m) != nil || m == nil {
		return row, nil
	}
	if pass, ok := m["password"].(string); ok && strings.HasPrefix(pass, secretcrypt.Prefix) {
		plain, err := secretcrypt.Open(pass)
		if err != nil {
			return row, fmt.Errorf("decrypt outbound %s password: %w", row.ID, err)
		}
		m["password"] = plain
		if b, err := json.Marshal(m); err == nil {
			row.SettingsJSON = string(b)
		}
	}
	return row, nil
}

func OpenInboundSecrets(row models.Inbound) models.Inbound {
	if strings.TrimSpace(row.SettingsJSON) != "" && strings.Contains(row.SettingsJSON, secretcrypt.Prefix) {
		var m map[string]any
		if json.Unmarshal([]byte(row.SettingsJSON), &m) == nil && m != nil {
			changed := false
			for _, key := range []string{"reality_private_key", "ss_password"} {
				if raw, ok := m[key].(string); ok && strings.HasPrefix(raw, secretcrypt.Prefix) {
					if plain, err := secretcrypt.Open(raw); err == nil {
						m[key] = plain
						changed = true
					}
				}
			}
			if accs, ok := m["accounts"].([]any); ok {
				for i := range accs {
					accMap, ok := accs[i].(map[string]any)
					if !ok {
						continue
					}
					if pass, ok := accMap["pass"].(string); ok && strings.HasPrefix(pass, secretcrypt.Prefix) {
						if plain, err := secretcrypt.Open(pass); err == nil {
							accMap["pass"] = plain
							changed = true
						}
					}
				}
			}
			if changed {
				if b, err := json.Marshal(m); err == nil {
					row.SettingsJSON = string(b)
				}
			}
		}
	}
	if strings.TrimSpace(row.StreamJSON) != "" && strings.Contains(row.StreamJSON, secretcrypt.Prefix) {
		var sm map[string]any
		if json.Unmarshal([]byte(row.StreamJSON), &sm) == nil && sm != nil {
			if reality, ok := sm["realitySettings"].(map[string]any); ok {
				if pk, ok := reality["privateKey"].(string); ok && strings.HasPrefix(pk, secretcrypt.Prefix) {
					if plain, err := secretcrypt.Open(pk); err == nil {
						reality["privateKey"] = plain
						if b, err := json.Marshal(sm); err == nil {
							row.StreamJSON = string(b)
						}
					}
				}
			}
		}
	}
	return row
}

func sealOutboundSecrets(settingsJSON string) (string, error) {
	if strings.TrimSpace(settingsJSON) == "" {
		return settingsJSON, nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(settingsJSON), &m) != nil || m == nil {
		return settingsJSON, nil
	}
	pass, ok := m["password"].(string)
	if !ok || strings.TrimSpace(pass) == "" {
		return settingsJSON, nil
	}
	enc, err := secretcrypt.Seal(pass)
	if err != nil {
		return "", err
	}
	if enc == pass {
		return settingsJSON, nil
	}
	m["password"] = enc
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func OpenOutboundSecrets(row models.Outbound) models.Outbound {
	if strings.TrimSpace(row.SettingsJSON) == "" || !strings.Contains(row.SettingsJSON, secretcrypt.Prefix) {
		return row
	}
	var m map[string]any
	if json.Unmarshal([]byte(row.SettingsJSON), &m) != nil || m == nil {
		return row
	}
	if pass, ok := m["password"].(string); ok && strings.HasPrefix(pass, secretcrypt.Prefix) {
		if plain, err := secretcrypt.Open(pass); err == nil {
			m["password"] = plain
			if b, err := json.Marshal(m); err == nil {
				row.SettingsJSON = string(b)
			}
		}
	}
	return row
}

func newID() string { return uuid.NewString() }

func now() time.Time { return time.Now().UTC() }

func (s *Store) ListInbounds(nodeUUID string) ([]models.Inbound, error) {
	var rows []models.Inbound
	q := s.db.Order("sort_index ASC, created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = OpenInboundSecrets(rows[i])
	}
	return rows, nil
}

func (s *Store) NextInboundSortIndex(nodeUUID string) int {
	var max *int
	q := s.db.Model(&models.Inbound{})
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	if err := q.Select("MAX(sort_index)").Scan(&max).Error; err != nil || max == nil {
		return 1
	}
	return *max + 1
}

func (s *Store) ReorderInbounds(nodeUUID string, ids []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for i, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			q := tx.Model(&models.Inbound{}).Where("id = ?", id)
			if nodeUUID != "" {
				q = q.Where("node_uuid = ?", nodeUUID)
			}
			if err := q.Updates(map[string]any{
				"sort_index": i + 1,
				"updated_at": now(),
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) GetInbound(id string) (*models.Inbound, error) {
	var row models.Inbound
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	row = OpenInboundSecrets(row)
	return &row, nil
}

func (s *Store) UpsertInbound(row *models.Inbound) error {
	if row.ID == "" {
		row.ID = newID()
	}
	if row.Core == "" {
		row.Core = models.CoreXray
	}
	if strings.TrimSpace(row.Listen) == "" {
		row.Listen = inboundcfg.ListenForStack(inboundcfg.Parse(row.SettingsJSON).Stack, "")
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	plainSettings := row.SettingsJSON
	plainStream := row.StreamJSON
	sealedSettings, sealedStream, err := sealInboundSecrets(row.SettingsJSON, row.StreamJSON)
	if err != nil {
		return err
	}
	row.SettingsJSON = sealedSettings
	row.StreamJSON = sealedStream
	err = s.saveAll(row)
	row.SettingsJSON = plainSettings
	row.StreamJSON = plainStream
	return err
}

func (s *Store) DeleteInbound(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.Inbound{}).Where("id = ?", id).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		if _, err := detachInboundChainsTx(tx, id); err != nil {
			return err
		}
		if err := tx.Where("inbound_id = ?", id).Delete(&models.Grant{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Inbound{}, "id = ?", id).Error
	})
}

func (s *Store) ListOutbounds(nodeUUID string) ([]models.Outbound, error) {
	var rows []models.Outbound
	q := s.db.Order("created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = OpenOutboundSecrets(rows[i])
	}
	return rows, nil
}

func reservedOutboundTag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "direct", "block":
		return true
	default:
		return false
	}
}

func (s *Store) UpsertOutbound(row *models.Outbound) error {
	if row == nil {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	row.Name = strings.TrimSpace(row.Name)
	row.NodeUUID = strings.TrimSpace(row.NodeUUID)
	if row.Name == "" || row.NodeUUID == "" {
		return fmt.Errorf("%w: name and node required", ErrInvalid)
	}
	if reservedOutboundTag(row.Name) {
		return fmt.Errorf("%w: outbound_tag_reserved", ErrInvalid)
	}
	if !settingsFlag(row.SettingsJSON, "chain_managed") && !settingsFlag(row.SettingsJSON, "route_managed") {
		for _, key := range []string{"source_inbound_id", "landing_inbound_id"} {
			if id := settingsString(row.SettingsJSON, key); id != "" && s.InboundBoundToChain(id) {
				return fmt.Errorf("%w: chain_in_use", ErrConflict)
			}
		}
	}
	q := s.db.Model(&models.Outbound{}).Where("node_uuid = ? AND name = ?", row.NodeUUID, row.Name)
	if strings.TrimSpace(row.ID) != "" {
		q = q.Where("id <> ?", row.ID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: outbound_tag_duplicate", ErrConflict)
	}
	if row.ID == "" {
		row.ID = newID()
	}
	if row.Core == "" {
		row.Core = models.CoreXray
	}
	s.keepCreatedAt(&models.Outbound{}, row.ID, &row.CreatedAt)
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	plainSettings := row.SettingsJSON
	sealedSettings, err := sealOutboundSecrets(row.SettingsJSON)
	if err != nil {
		return err
	}
	row.SettingsJSON = sealedSettings
	err = s.saveAll(row)
	row.SettingsJSON = plainSettings
	return err
}

func (s *Store) GetOutbound(id string) (*models.Outbound, error) {
	var row models.Outbound
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	row = OpenOutboundSecrets(row)
	return &row, nil
}

func routeRuleInboundID(ruleJSON string) string {
	var rule struct {
		InboundID string `json:"inbound_id"`
	}
	_ = json.Unmarshal([]byte(ruleJSON), &rule)
	return strings.TrimSpace(rule.InboundID)
}

func routeRuleOutboundID(ruleJSON string) string {
	var rule struct {
		OutboundID string `json:"outbound_id"`
	}
	_ = json.Unmarshal([]byte(ruleJSON), &rule)
	return strings.TrimSpace(rule.OutboundID)
}

func (s *Store) DeleteOutbound(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrInvalid
	}
	if s.ChainManagedOutbound(id) || s.RouteManagedOutbound(id) {
		return fmt.Errorf("%w: chain_managed", ErrConflict)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		st := New(tx)
		res := tx.Delete(&models.Outbound{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return st.deleteRoutesUsingOutbound(id)
	})
}

func (s *Store) ListRoutes(nodeUUID string) ([]models.Route, error) {
	var rows []models.Route
	q := s.db.Order("priority ASC, created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) UpsertRoute(row *models.Route) error {
	if !settingsFlag(row.RuleJSON, "chain_managed") {
		if id := routeRuleInboundID(row.RuleJSON); id != "" && s.InboundBoundToChain(id) {
			return fmt.Errorf("%w: chain_in_use", ErrConflict)
		}
	}
	if row.ID == "" {
		row.ID = newID()
	}
	s.keepCreatedAt(&models.Route{}, row.ID, &row.CreatedAt)
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.saveAll(row)
}

func (s *Store) GetRoute(id string) (*models.Route, error) {
	var row models.Route
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) DeleteRoute(id string) error {
	if s.ChainManagedRoute(id) {
		return fmt.Errorf("%w: chain_managed", ErrConflict)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		st := New(tx)
		row, err := st.GetRoute(id)
		if err != nil {
			return err
		}
		groupID := settingsString(row.RuleJSON, "group_outbound_id")
		res := tx.Delete(&models.Route{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return st.dropRouteGroup(groupID)
	})
}

func (s *Store) ListUsers(nodeUUID string) ([]models.NodeUser, error) {
	var rows []models.NodeUser
	q := s.db.Order("created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) GetUser(id string) (*models.NodeUser, error) {
	var row models.NodeUser
	if err := s.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) UpsertUser(row *models.NodeUser) error {
	if strings.TrimSpace(row.Username) == "" {
		return fmt.Errorf("%w: username required", ErrInvalid)
	}
	if row.ID == "" {
		row.ID = newID()
	}
	if row.Status == "" {
		row.Status = models.UserActive
	}
	if row.DeviceLimit < 0 {
		row.DeviceLimit = 0
	}
	s.keepCreatedAt(&models.NodeUser{}, row.ID, &row.CreatedAt)
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.db.Omit("IPsClearedAt", "LastUsageOp").Save(row).Error
}

// SaveUserProfile creates a user or updates display fields without touching
// quota, usage, expiry, or shared-pool state that JSON omitempty would zero.
func (s *Store) SaveUserProfile(row *models.NodeUser) error {
	if row == nil {
		return fmt.Errorf("%w: user required", ErrInvalid)
	}
	if strings.TrimSpace(row.ID) == "" {
		return s.UpsertUser(row)
	}
	if _, err := s.GetUser(row.ID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.UpsertUser(row)
		}
		return err
	}
	updates := map[string]any{
		"username":       row.Username,
		"display_name":   row.DisplayName,
		"flow":           row.Flow,
		"rate_limit_bps": row.RateLimitBps,
		"device_limit":   row.DeviceLimit,
		"updated_at":     now(),
	}
	if strings.TrimSpace(row.Kind) != "" {
		updates["kind"] = row.Kind
	}
	if strings.TrimSpace(row.Status) != "" {
		updates["status"] = row.Status
	}
	if strings.TrimSpace(row.NodeUUID) != "" {
		updates["node_uuid"] = row.NodeUUID
	}
	return s.db.Model(&models.NodeUser{}).Where("id = ?", row.ID).Updates(updates).Error
}

func (s *Store) SetUserExpiryAndReset(id string, expires *time.Time, resetDay int, at time.Time) error {
	if resetDay < 0 || resetDay > 31 {
		return fmt.Errorf("%w: traffic_reset_day", ErrInvalid)
	}
	if at.IsZero() {
		at = now()
	}
	user, err := s.GetUser(id)
	if err != nil {
		return err
	}
	updates := map[string]any{
		"traffic_reset_day": resetDay,
		"updated_at":        at,
	}
	switch {
	case resetDay < 1:
		updates["traffic_reset_cycle"] = ""
	case user.TrafficResetDay != resetDay:
		day := resetDay
		updates["traffic_reset_cycle"] = trafficreset.FromFields(&day, "", "").CycleKey(at)
	}
	if err := s.db.Model(&models.NodeUser{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	if err := s.db.Model(&models.NodeUser{}).Where("id = ?", id).Update("expires_at", expires).Error; err != nil {
		return err
	}
	asg, err := s.ListAssignments(id)
	if err != nil || len(asg) == 0 {
		return err
	}
	return s.db.Model(&models.Assignment{}).Where("id = ?", asg[0].ID).Update("ends_at", expires).Error
}

func (s *Store) ApplyUserTrafficReset(id string, at time.Time) (bool, error) {
	user, err := s.GetUser(id)
	if err != nil {
		return false, err
	}
	return s.applyUserTrafficReset(user, at)
}

func (s *Store) ListMonthlyResetUsers() ([]models.NodeUser, error) {
	var users []models.NodeUser
	err := s.db.Where("traffic_reset_day >= 1 AND traffic_reset_day <= 31").Order("id ASC").Find(&users).Error
	return users, err
}

func (s *Store) ApplyDueTrafficResets(at time.Time) ([]string, error) {
	users, err := s.ListMonthlyResetUsers()
	if err != nil {
		return nil, err
	}
	var ids []string
	for i := range users {
		ok, err := s.applyUserTrafficReset(&users[i], at)
		if err != nil {
			return ids, err
		}
		if ok {
			ids = append(ids, users[i].ID)
		}
	}
	return ids, nil
}

func (s *Store) applyUserTrafficReset(user *models.NodeUser, at time.Time) (bool, error) {
	if user == nil || user.TrafficResetDay < 1 || user.TrafficResetDay > 31 {
		return false, nil
	}
	if at.IsZero() {
		at = now()
	}
	day := user.TrafficResetDay
	key := trafficreset.FromFields(&day, "", "").CycleKey(at)
	if key == "" || key == user.TrafficResetCycle {
		return false, nil
	}
	if err := s.db.Model(&models.NodeUser{}).Where("id = ?", user.ID).Updates(map[string]any{
		"used_bytes":          0,
		"traffic_reset_cycle": key,
		"updated_at":          at,
	}).Error; err != nil {
		return false, err
	}
	user.UsedBytes = 0
	user.TrafficResetCycle = key
	return true, nil
}

func (s *Store) DeleteUser(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", id).Delete(&models.Credential{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Assignment{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.QuotaLedger{}).Error; err != nil {
			return err
		}
		if err := tx.Where("scope = ? AND scope_id IN (?)", "subscription", tx.Model(&models.Subscription{}).Select("id").Where("user_id = ?", id)).Delete(&models.SubscriptionTemplateBinding{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Subscription{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Grant{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.UserIP{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.UserExtraLink{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&models.NodeUser{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) SetUserStatus(id, status string) error {
	switch status {
	case models.UserActive, models.UserDisabled, models.UserExpired:
	default:
		return fmt.Errorf("%w: status", ErrInvalid)
	}
	res := s.db.Model(&models.NodeUser{}).Where("id = ?", id).Updates(map[string]any{
		"status":     status,
		"updated_at": now(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

type UserIPView struct {
	IP     string    `json:"ip"`
	SeenAt time.Time `json:"seen_at"`
}

type UserPresence struct {
	UserID string       `json:"user_id"`
	Online bool         `json:"online"`
	IPs    []UserIPView `json:"ips"`
}

type UserView struct {
	models.NodeUser
	PlanID           string                 `json:"plan_id"`
	PlanName         string                 `json:"plan_name"`
	UUID             string                 `json:"uuid"`
	InboundIDs       []string               `json:"inbound_ids"`
	InboundNames     []string               `json:"inbound_names"`
	AssignmentEndsAt *time.Time             `json:"assignment_ends_at"`
	Online           bool                   `json:"online"`
	OnlineIPs        []UserIPView           `json:"online_ips"`
	ExtraLinks       []models.UserExtraLink `json:"extra_links"`
}

func (s *Store) ReplaceGrants(userID string, inboundIDs []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.Grant{}).Error; err != nil {
			return err
		}
		seen := map[string]struct{}{}
		for _, inboundID := range inboundIDs {
			inboundID = strings.TrimSpace(inboundID)
			if inboundID == "" {
				continue
			}
			if _, ok := seen[inboundID]; ok {
				continue
			}
			seen[inboundID] = struct{}{}
			row := models.Grant{ID: newID(), UserID: userID, InboundID: inboundID, CreatedAt: now()}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ListGrants(userID string) ([]models.Grant, error) {
	var rows []models.Grant
	q := s.db.Order("created_at ASC")
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) ListUserViews(nodeUUID string) ([]UserView, error) {
	users, err := s.ListUsers(nodeUUID)
	if err != nil {
		return nil, err
	}
	return s.userViews(users)
}

func (s *Store) GetUserView(id string) (*UserView, error) {
	user, err := s.GetUser(id)
	if err != nil {
		return nil, err
	}
	views, err := s.userViews([]models.NodeUser{*user})
	if err != nil {
		return nil, err
	}
	if len(views) == 0 {
		return nil, ErrNotFound
	}
	return &views[0], nil
}

func (s *Store) userViews(users []models.NodeUser) ([]UserView, error) {
	filtered := make([]models.NodeUser, 0, len(users))
	userIDs := make([]string, 0, len(users))
	for _, user := range users {
		if models.IsRelayUser(user.Kind, user.Username) {
			continue
		}
		filtered = append(filtered, user)
		userIDs = append(userIDs, user.ID)
	}
	if len(filtered) == 0 {
		return []UserView{}, nil
	}

	type credRow struct {
		UserID  string
		UUID    string
		Enabled bool
	}
	var credRows []credRow
	for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
		var part []credRow
		if err := s.db.Model(&models.Credential{}).
			Select("user_id, uuid, enabled").
			Where("user_id IN ?", chunk).
			Order("created_at ASC").
			Find(&part).Error; err != nil {
			return nil, err
		}
		credRows = append(credRows, part...)
	}
	uuidByUser := make(map[string]string, len(userIDs))
	for _, cred := range credRows {
		if cred.Enabled && cred.UUID != "" && uuidByUser[cred.UserID] == "" {
			uuidByUser[cred.UserID] = cred.UUID
		}
	}

	var grantRows []models.Grant
	for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
		var part []models.Grant
		if err := s.db.Where("user_id IN ?", chunk).Order("created_at ASC").Find(&part).Error; err != nil {
			return nil, err
		}
		grantRows = append(grantRows, part...)
	}
	grantsByUser := make(map[string][]models.Grant, len(userIDs))
	inboundIDSet := map[string]struct{}{}
	for _, g := range grantRows {
		grantsByUser[g.UserID] = append(grantsByUser[g.UserID], g)
		if g.InboundID != "" {
			inboundIDSet[g.InboundID] = struct{}{}
		}
	}

	inboundNameByID := map[string]string{}
	if len(inboundIDSet) > 0 {
		inboundIDs := make([]string, 0, len(inboundIDSet))
		for id := range inboundIDSet {
			inboundIDs = append(inboundIDs, id)
		}
		type inNameRow struct {
			ID   string
			Name string
		}
		for _, chunk := range chunkStrings(inboundIDs, sqliteChunkSize) {
			var inRows []inNameRow
			if err := s.db.Model(&models.Inbound{}).Select("id, name").Where("id IN ?", chunk).Find(&inRows).Error; err != nil {
				return nil, err
			}
			for _, in := range inRows {
				inboundNameByID[in.ID] = in.Name
			}
		}
	}

	latestAsg := make(map[string]models.Assignment, len(userIDs))
	planIDSet := map[string]struct{}{}
	for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
		var asgRows []models.Assignment
		if err := s.db.Where("user_id IN ?", chunk).Order("created_at DESC").Find(&asgRows).Error; err != nil {
			return nil, err
		}
		for _, a := range asgRows {
			if _, ok := latestAsg[a.UserID]; !ok {
				latestAsg[a.UserID] = a
				if a.PlanID != "" {
					planIDSet[a.PlanID] = struct{}{}
				}
			}
		}
	}

	planByID := map[string]models.Plan{}
	if len(planIDSet) > 0 {
		planIDs := make([]string, 0, len(planIDSet))
		for id := range planIDSet {
			planIDs = append(planIDs, id)
		}
		for _, chunk := range chunkStrings(planIDs, sqliteChunkSize) {
			var planRows []models.Plan
			if err := s.db.Where("id IN ?", chunk).Find(&planRows).Error; err != nil {
				return nil, err
			}
			for _, p := range planRows {
				planByID[p.ID] = p
			}
		}
	}

	ipsByUser := make(map[string][]UserIPView, len(userIDs))
	for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
		var ipRows []models.UserIP
		if err := s.db.Where("user_id IN ?", chunk).Order("seen_at DESC").Find(&ipRows).Error; err != nil {
			return nil, err
		}
		for _, row := range ipRows {
			if publicClientIP(row.IP) == "" {
				continue
			}
			ipsByUser[row.UserID] = append(ipsByUser[row.UserID], UserIPView{IP: row.IP, SeenAt: row.SeenAt})
		}
	}

	extras := make(map[string][]models.UserExtraLink, len(userIDs))
	for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
		var extraRows []models.UserExtraLink
		if err := s.db.Where("user_id IN ?", chunk).Order("sort_index ASC, created_at ASC").Find(&extraRows).Error; err != nil {
			return nil, err
		}
		for _, row := range extraRows {
			extras[row.UserID] = append(extras[row.UserID], row)
		}
	}

	at := now()
	out := make([]UserView, 0, len(filtered))
	for _, user := range filtered {
		view := UserView{
			NodeUser:     user,
			UUID:         uuidByUser[user.ID],
			InboundIDs:   []string{},
			InboundNames: []string{},
			ExtraLinks:   extras[user.ID],
		}
		if view.ExtraLinks == nil {
			view.ExtraLinks = []models.UserExtraLink{}
		}
		for _, g := range grantsByUser[user.ID] {
			view.InboundIDs = append(view.InboundIDs, g.InboundID)
			if name, ok := inboundNameByID[g.InboundID]; ok {
				view.InboundNames = append(view.InboundNames, name)
			}
		}
		if asg, ok := latestAsg[user.ID]; ok {
			view.PlanID = asg.PlanID
			view.AssignmentEndsAt = asg.EndsAt
			if plan, pok := planByID[asg.PlanID]; pok {
				view.PlanName = plan.Name
				if view.RateLimitBps <= 0 && (asg.EndsAt == nil || asg.EndsAt.After(at)) {
					view.RateLimitBps = plan.RateLimitBps
				}
			}
		}
		view.Online = userOnline(user.LastSeenAt, at)
		if view.Online {
			view.OnlineIPs = concurrentUserIPs(ipsByUser[user.ID], at)
		} else {
			view.OnlineIPs = []UserIPView{}
		}
		out = append(out, view)
	}
	return out, nil
}

const presenceFresh = 45 * time.Second

func userOnline(last *time.Time, at time.Time) bool {
	return last != nil && !last.IsZero() && at.Sub(*last) <= presenceFresh
}

func concurrentUserIPs(ips []UserIPView, at time.Time) []UserIPView {
	best := map[string]UserIPView{}
	order := make([]string, 0, len(ips))
	for _, ip := range ips {
		seen := ip.SeenAt
		if !userOnline(&seen, at) {
			continue
		}
		if prev, ok := best[ip.IP]; ok {
			if seen.After(prev.SeenAt) {
				best[ip.IP] = ip
			}
			continue
		}
		best[ip.IP] = ip
		order = append(order, ip.IP)
	}
	out := make([]UserIPView, 0, len(order))
	for _, addr := range order {
		out = append(out, best[addr])
	}
	return out
}

func (s *Store) ListUserIPs(userID string) ([]UserIPView, error) {
	var rows []models.UserIP
	if err := s.db.Where("user_id = ?", userID).Order("seen_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]UserIPView, 0, len(rows))
	for _, row := range rows {
		if publicClientIP(row.IP) == "" {
			continue
		}
		out = append(out, UserIPView{IP: row.IP, SeenAt: row.SeenAt})
	}
	return out, nil
}

func publicClientIP(addr string) string {
	host := strings.TrimSpace(addr)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func (s *Store) RecordUserPresence(nodeUUID, userID string, online bool, ips []UserIPView) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("%w: user required", ErrInvalid)
	}
	if err := s.UserOnNode(userID, nodeUUID); err != nil {
		return err
	}
	nowAt := now()
	return s.db.Transaction(func(tx *gorm.DB) error {
		var owner models.NodeUser
		if err := tx.Select("id", "ips_cleared_at").Where("id = ?", userID).First(&owner).Error; err != nil {
			return err
		}
		keep := make([]string, 0, len(ips))
		held := map[string]struct{}{}
		if online {
			for _, ip := range ips {
				addr := publicClientIP(ip.IP)
				if addr == "" {
					continue
				}
				seen := ip.SeenAt
				if seen.IsZero() {
					seen = nowAt
				}
				if owner.IPsClearedAt != nil && !seen.UTC().After(owner.IPsClearedAt.UTC()) {
					continue
				}
				if !userOnline(&seen, nowAt) {
					continue
				}
				var row models.UserIP
				err := tx.Where("user_id = ? AND ip = ? AND node_uuid = ?", userID, addr, nodeUUID).First(&row).Error
				if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				if errors.Is(err, gorm.ErrRecordNotFound) {
					row = models.UserIP{
						ID:        newID(),
						UserID:    userID,
						IP:        addr,
						NodeUUID:  nodeUUID,
						SeenAt:    seen.UTC(),
						CreatedAt: nowAt,
					}
					if err := tx.Create(&row).Error; err != nil {
						return err
					}
				} else if err := tx.Model(&models.UserIP{}).Where("id = ?", row.ID).Update("seen_at", seen.UTC()).Error; err != nil {
					return err
				}
				if _, ok := held[addr]; !ok {
					held[addr] = struct{}{}
					keep = append(keep, addr)
				}
			}
		}
		q := tx.Where("user_id = ?", userID)
		if nodeUUID != "" {
			q = q.Where("node_uuid = ?", nodeUUID)
		}
		if len(keep) > 0 {
			q = q.Where("ip NOT IN ?", keep)
		}
		if err := q.Delete(&models.UserIP{}).Error; err != nil {
			return err
		}
		cutoff := nowAt.Add(-presenceFresh)
		if err := tx.Where("user_id = ? AND seen_at < ?", userID, cutoff).Delete(&models.UserIP{}).Error; err != nil {
			return err
		}
		if online {
			return tx.Model(&models.NodeUser{}).Where("id = ?", userID).Update("last_seen_at", nowAt).Error
		}
		var remaining int64
		if err := tx.Model(&models.UserIP{}).Where("user_id = ? AND seen_at >= ?", userID, cutoff).Count(&remaining).Error; err != nil {
			return err
		}
		if remaining > 0 {
			return nil
		}
		stale := nowAt.Add(-presenceFresh - time.Second)
		return tx.Model(&models.NodeUser{}).Where("id = ?", userID).Update("last_seen_at", stale).Error
	})
}

func (s *Store) ClearUserIPs(userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("%w: user required", ErrInvalid)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserIP{}).Error; err != nil {
			return err
		}
		return tx.Model(&models.NodeUser{}).Where("id = ?", userID).Update("ips_cleared_at", now()).Error
	})
}

func HashSecret(plain string) (hash, hint string, err error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return "", "", fmt.Errorf("%w: empty secret", ErrInvalid)
	}
	sum, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	hint = plain
	if len(hint) > 4 {
		hint = hint[:2] + "…" + hint[len(hint)-2:]
	}
	return string(sum), hint, nil
}

func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func RandomToken(n int) (string, error) {
	if n < 8 {
		n = 24
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func protocolSecret(kind, plain string) (secret, id string, err error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = uuid.NewString()
	secret = strings.TrimSpace(plain)
	if kind == "" || kind == "uuid" {
		if secret == "" {
			secret = id
		} else {
			id = secret
		}
		return secret, id, nil
	}
	if secret == "" {
		secret, err = RandomToken(16)
		if err != nil {
			return "", "", err
		}
	}
	return secret, id, nil
}

func (s *Store) IssueCredential(userID, kind, plain string, expires *time.Time) (*models.Credential, string, error) {
	if kind == "" {
		kind = "uuid"
	}
	secret, id, err := protocolSecret(kind, plain)
	if err != nil {
		return nil, "", err
	}
	hash, hint, err := HashSecret(secret)
	if err != nil {
		return nil, "", err
	}
	material, err := secretcrypt.Seal(secret)
	if err != nil {
		return nil, "", err
	}
	row := models.Credential{
		ID:             newID(),
		UserID:         userID,
		Kind:           kind,
		SecretHash:     hash,
		SecretHint:     hint,
		SecretMaterial: material,
		UUID:           id,
		Enabled:        true,
		ExpiresAt:      expires,
		CreatedAt:      now(),
		UpdatedAt:      now(),
	}
	if err := s.db.Create(&row).Error; err != nil {
		return nil, "", err
	}
	return &row, secret, nil
}

func (s *Store) RotateCredential(id string) (*models.Credential, string, error) {
	var row models.Credential
	if err := s.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	secret, protocolID, err := protocolSecret(row.Kind, "")
	if err != nil {
		return nil, "", err
	}
	hash, hint, err := HashSecret(secret)
	if err != nil {
		return nil, "", err
	}
	material, err := secretcrypt.Seal(secret)
	if err != nil {
		return nil, "", err
	}
	row.SecretHash = hash
	row.SecretHint = hint
	row.SecretMaterial = material
	row.UUID = protocolID
	row.UpdatedAt = now()
	if err := s.db.Save(&row).Error; err != nil {
		return nil, "", err
	}
	return &row, secret, nil
}

func (s *Store) RevokeCredential(id string) error {
	res := s.db.Model(&models.Credential{}).Where("id = ?", id).Updates(map[string]any{
		"enabled":    false,
		"updated_at": now(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListCredentials(userID string) ([]models.Credential, error) {
	var rows []models.Credential
	if err := s.db.Where("user_id = ?", userID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		if plain, err := secretcrypt.Open(rows[i].SecretMaterial); err == nil {
			rows[i].SecretMaterial = plain
		}
	}
	return rows, nil
}

func (s *Store) GetCredential(id string) (*models.Credential, error) {
	var row models.Credential
	if err := s.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if plain, err := secretcrypt.Open(row.SecretMaterial); err == nil {
		row.SecretMaterial = plain
	}
	return &row, nil
}

func MatchSecret(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

func (s *Store) ListPlans() ([]models.Plan, error) {
	var rows []models.Plan
	return rows, s.db.Order("created_at ASC").Find(&rows).Error
}

func (s *Store) GetPlan(id string) (*models.Plan, error) {
	var row models.Plan
	if err := s.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) UpsertPlan(row *models.Plan) error {
	if strings.TrimSpace(row.Name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalid)
	}
	if row.ID == "" {
		row.ID = newID()
	}
	if row.DurationDays <= 0 {
		row.DurationDays = 30
	}
	if row.DeviceLimit < 0 {
		row.DeviceLimit = 0
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.db.Save(row).Error
}

func (s *Store) DeletePlan(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("scope = ? AND scope_id = ?", "plan", id).Delete(&models.SubscriptionTemplateBinding{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&models.Plan{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) FindAssignmentByOp(opID string) (*models.Assignment, error) {
	var row models.Assignment
	if err := s.db.First(&row, "operation_id = ?", opID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) ListAssignments(userID string) ([]models.Assignment, error) {
	var rows []models.Assignment
	q := s.db.Order("created_at DESC")
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) SaveAssignment(row *models.Assignment) error {
	if row.ID == "" {
		row.ID = newID()
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.db.Save(row).Error
}

func (s *Store) DeleteAssignments(userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ErrInvalid
	}
	return s.db.Where("user_id = ?", userID).Delete(&models.Assignment{}).Error
}

func (s *Store) UsageBatchSeen(userID, opID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	opID = strings.TrimSpace(opID)
	if userID == "" || opID == "" {
		return false, ErrInvalid
	}
	var current models.NodeUser
	if err := s.db.Select("id", "last_usage_op").First(&current, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, ErrNotFound
		}
		return false, err
	}
	return current.LastUsageOp == opID, nil
}

func (s *Store) ApplyUsageBatch(userID, opID string, bytes int64) error {
	userID = strings.TrimSpace(userID)
	opID = strings.TrimSpace(opID)
	if userID == "" || opID == "" {
		return ErrInvalid
	}
	res := s.db.Model(&models.NodeUser{}).Where("id = ? AND last_usage_op <> ?", userID, opID).Updates(map[string]any{
		"used_bytes":    gorm.Expr("used_bytes + ?", bytes),
		"last_usage_op": opID,
		"updated_at":    now(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return nil
	}
	seen, err := s.UsageBatchSeen(userID, opID)
	if err != nil {
		return err
	}
	if seen {
		return ErrConflict
	}
	return ErrNotFound
}

func UsageDedupOpID(nodeUUID, batchID, userID string) string {
	sum := sha256.Sum256([]byte("usage:" + strings.TrimSpace(nodeUUID) + ":" + strings.TrimSpace(batchID) + ":" + strings.TrimSpace(userID)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) AddUserUsage(nodeUUID, userID, batchID string, bytes int64) error {
	userID = strings.TrimSpace(userID)
	batchID = strings.TrimSpace(batchID)
	if userID == "" || batchID == "" {
		return ErrInvalid
	}
	if bytes <= 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		inner := New(tx)
		legacyOp := userID + ":" + batchID
		if strings.TrimSpace(nodeUUID) == "" {
			seen, err := inner.UsageBatchSeen(userID, legacyOp)
			if err != nil {
				return err
			}
			if seen {
				return ErrConflict
			}
		}
		dedupOp := UsageDedupOpID(nodeUUID, batchID, userID)
		if err := inner.AddLedger(userID, ledgerReasonUsageDedup, dedupOp, bytes); err != nil {
			return err
		}
		lastOp := legacyOp
		if strings.TrimSpace(nodeUUID) != "" {
			lastOp = dedupOp
		}
		res := tx.Model(&models.NodeUser{}).Where("id = ?", userID).Updates(map[string]any{
			"used_bytes":    gorm.Expr("used_bytes + ?", bytes),
			"last_usage_op": lastOp,
			"updated_at":    now(),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) AddLedger(userID, reason, opID string, delta int64) error {
	if opID == "" {
		opID = newID()
	}
	row := models.QuotaLedger{
		ID:        newID(),
		UserID:    userID,
		Delta:     delta,
		Reason:    reason,
		OpID:      opID,
		CreatedAt: now(),
	}
	if err := s.db.Create(&row).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) ListSubscriptions() ([]models.Subscription, error) {
	var rows []models.Subscription
	if err := s.db.Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		revealSubscription(&rows[i])
	}
	return rows, nil
}

func (s *Store) GetSubscription(id string) (*models.Subscription, error) {
	var row models.Subscription
	if err := s.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	revealSubscription(&row)
	return &row, nil
}

func (s *Store) GetSubscriptionByUser(userID string) (*models.Subscription, error) {
	var row models.Subscription
	if err := s.db.First(&row, "user_id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	revealSubscription(&row)
	return &row, nil
}

func (s *Store) HideRelaySubscriptions() error {
	var users []models.NodeUser
	if err := s.db.Where("kind = ? OR username LIKE ?", models.UserKindRelay, models.RelayUsernamePrefix+"%").Find(&users).Error; err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}
	ids := make([]string, 0, len(users))
	for _, user := range users {
		ids = append(ids, user.ID)
	}
	return s.db.Where("user_id IN ?", ids).Delete(&models.Subscription{}).Error
}

func (s *Store) EnsureSubscription(userID string) (*models.Subscription, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: user required", ErrInvalid)
	}
	user, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}
	if models.IsRelayUser(user.Kind, user.Username) {
		if err := s.HideRelaySubscriptions(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: relay user", ErrInvalid)
	}
	if row, err := s.GetSubscriptionByUser(userID); err == nil {
		return row, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	row := &models.Subscription{UserID: userID, Format: "xray", Enabled: true}
	if err := s.UpsertSubscription(row); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) GetSubscriptionByToken(token string) (*models.Subscription, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrNotFound
	}
	var row models.Subscription
	hash := HashToken(token)
	err := s.db.Where("enabled = ? AND token_hash = ?", true, hash).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = s.db.Where("enabled = ? AND token = ?", true, token).First(&row).Error
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if row.TokenHash == "" {
		row.TokenHash = hash
	}
	if !strings.HasPrefix(row.Token, secretcrypt.Prefix) {
		enc, encErr := secretcrypt.Seal(token)
		if encErr == nil {
			_ = s.db.Model(&row).Updates(map[string]any{"token": enc, "token_hash": hash}).Error
			row.Token = enc
		}
	}
	revealSubscription(&row)
	return &row, nil
}

func revealSubscription(row *models.Subscription) {
	if row == nil {
		return
	}
	if plain, err := secretcrypt.Open(row.Token); err == nil {
		row.Token = plain
	}
}

func (s *Store) UpsertSubscription(row *models.Subscription) error {
	if row.ID != "" && row.Token == "" {
		var old models.Subscription
		if err := s.db.First(&old, "id = ?", row.ID).Error; err != nil {
			return err
		}
		revealSubscription(&old)
		row.Token = old.Token
		row.CreatedAt = old.CreatedAt
	}
	if row.ID == "" {
		row.ID = newID()
	}
	plain := row.Token
	if strings.HasPrefix(plain, secretcrypt.Prefix) {
		opened, err := secretcrypt.Open(plain)
		if err != nil {
			return fmt.Errorf("decrypt subscription token: %w", err)
		}
		plain = opened
	}
	if plain == "" {
		tok, err := RandomToken(16)
		if err != nil {
			return err
		}
		plain = tok
	}
	enc, err := secretcrypt.Seal(plain)
	if err != nil {
		return err
	}
	row.Token = enc
	row.TokenHash = HashToken(plain)
	if row.Format == "" {
		row.Format = "xray"
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	if err := s.saveAll(row); err != nil {
		return err
	}
	row.Token = plain
	return nil
}

func (s *Store) DeleteSubscription(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("scope = ? AND scope_id = ?", "subscription", id).Delete(&models.SubscriptionTemplateBinding{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&models.Subscription{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) ListRootCerts() ([]models.RootCertificate, error) {
	var rows []models.RootCertificate
	return rows, s.db.Order("created_at ASC").Find(&rows).Error
}

func (s *Store) GetRootCert(id string) (*models.RootCertificate, error) {
	var row models.RootCertificate
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) GetRootCertByDomain(domain string) (*models.RootCertificate, error) {
	var row models.RootCertificate
	err := s.db.First(&row, "domain = ?", strings.ToLower(strings.TrimSpace(domain))).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) UpsertRootCert(row *models.RootCertificate) error {
	if row.ID == "" {
		row.ID = newID()
	}
	if row.Status == "" {
		row.Status = models.CertPending
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
		row.AutoRenew = true
	}
	return s.db.Save(row).Error
}

func (s *Store) DeleteRootCert(id string) error {
	var n int64
	if err := s.db.Model(&models.Certificate{}).Where("root_cert_id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: root certificate is in use", ErrConflict)
	}
	res := s.db.Delete(&models.RootCertificate{}, "id = ?", id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListCertsByRoot(rootID string) ([]models.Certificate, error) {
	var rows []models.Certificate
	return rows, s.db.Where("root_cert_id = ?", rootID).Order("created_at ASC").Find(&rows).Error
}

func (s *Store) ListCerts(nodeUUID string) ([]models.Certificate, error) {
	var rows []models.Certificate
	q := s.db.Order("created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) GetCert(id string) (*models.Certificate, error) {
	var row models.Certificate
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) inboundUsesCert(id string) (bool, error) {
	var rows []models.Inbound
	if err := s.db.Select("settings_json").Find(&rows).Error; err != nil {
		return false, err
	}
	for _, row := range rows {
		if inboundcfg.Parse(row.SettingsJSON).CertID == id {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) DeleteCert(id string) error {
	used, err := s.inboundUsesCert(id)
	if err != nil {
		return err
	}
	if used {
		return fmt.Errorf("%w: certificate is in use", ErrConflict)
	}
	res := s.db.Delete(&models.Certificate{}, "id = ?", id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpsertCert(row *models.Certificate) error {
	if row.ID == "" {
		row.ID = newID()
	}
	if row.Status == "" {
		row.Status = models.CertPending
	}
	if row.Source == "" {
		if strings.TrimSpace(row.CertPath) != "" {
			row.Source = models.CertSourceFile
		} else {
			row.Source = models.CertSourceACME
		}
	}
	if row.Issuer == "" && row.Source != models.CertSourceFile {
		row.Issuer = "Let's Encrypt"
	}
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
		row.AutoRenew = true
	}
	return s.db.Save(row).Error
}

func (s *Store) EnqueueCommand(cmd *models.ControlCommand) error {
	if cmd.ID == "" {
		cmd.ID = newID()
	}
	if cmd.OperationID == "" {
		cmd.OperationID = newID()
	}
	if cmd.Status == "" {
		cmd.Status = models.CmdPending
	}
	cmd.UpdatedAt = now()
	if cmd.CreatedAt.IsZero() {
		cmd.CreatedAt = cmd.UpdatedAt
	}
	var existing models.ControlCommand
	err := s.db.First(&existing, "operation_id = ?", cmd.OperationID).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if cmd.Kind == "applyConfig" && cmd.NodeUUID != "" {
		_ = s.db.Model(&models.ControlCommand{}).
			Where("node_uuid = ? AND kind = ? AND status IN ?", cmd.NodeUUID, "applyConfig", []string{models.CmdPending, models.CmdSent}).
			Updates(map[string]any{"status": models.CmdSuperseded, "payload_json": "", "updated_at": now()}).Error
	}
	if cmd.Kind == "applyConfig" || cmd.Kind == "syncQuota" || cmd.Kind == "applyCert" {
		sealed, err := secretcrypt.Seal(cmd.PayloadJSON)
		if err != nil {
			return err
		}
		cmd.PayloadJSON = sealed
	}
	return s.db.Create(cmd).Error
}

func (s *Store) PendingCommands(nodeUUID string) ([]models.ControlCommand, error) {
	var rows []models.ControlCommand
	q := s.db.Where("status = ?", models.CmdPending).Order("created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) DueCommands(nodeUUID string, staleSent time.Duration) ([]models.ControlCommand, error) {
	var rows []models.ControlCommand
	cutoff := now().Add(-staleSent)
	q := s.db.Where("(status = ? OR (status = ? AND updated_at <= ?)) AND status <> ?", models.CmdPending, models.CmdSent, cutoff, models.CmdSuperseded).
		Order("created_at ASC")
	if nodeUUID != "" {
		q = q.Where("node_uuid = ?", nodeUUID)
	}
	return rows, q.Find(&rows).Error
}

func (s *Store) MarkCommandSent(operationID string) error {
	if strings.TrimSpace(operationID) == "" {
		return nil
	}
	return s.db.Model(&models.ControlCommand{}).
		Where("operation_id = ? AND status = ?", operationID, models.CmdPending).
		Updates(map[string]any{"status": models.CmdSent, "updated_at": now()}).Error
}

func (s *Store) LatestCommands() ([]models.ControlCommand, error) {
	var rows []models.ControlCommand
	subQuery := s.db.Table("nodemgt_control_commands").
		Select("id, ROW_NUMBER() OVER (PARTITION BY node_uuid ORDER BY created_at DESC, rowid DESC) AS rn")
	err := s.db.Omit("PayloadJSON").
		Where("id IN (?)", s.db.Table("(?) AS ranked", subQuery).Select("id").Where("rn = 1")).
		Order("created_at DESC, rowid DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Store) LatestCommandForNode(nodeUUID string) (*models.ControlCommand, error) {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return nil, ErrNotFound
	}
	var row models.ControlCommand
	if err := s.db.Omit("PayloadJSON").Where("node_uuid = ?", nodeUUID).Order("created_at DESC, rowid DESC").First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) GetCommand(operationID string) (*models.ControlCommand, error) {
	var row models.ControlCommand
	if err := s.db.First(&row, "operation_id = ?", operationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) AckCommand(operationID, status, lastErr string) error {
	if status == "" {
		status = models.CmdApplied
	}
	updates := map[string]any{
		"status":     status,
		"last_error": lastErr,
		"updated_at": now(),
	}
	if status == models.CmdApplied {
		t := now()
		updates["acked_at"] = t
	}
	if status == models.CmdApplied || status == models.CmdFailed || status == models.CmdSuperseded {
		updates["payload_json"] = ""
	}
	res := s.db.Model(&models.ControlCommand{}).Where("operation_id = ?", operationID).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetSetting(key string) (string, error) {
	var row models.Setting
	if err := s.db.First(&row, "key = ?", key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	if key == "cf_api_token" {
		if strings.TrimSpace(row.Value) == "" {
			return "", nil
		}
		plain, err := secretcrypt.Open(row.Value)
		if err != nil {
			return "", err
		}
		return plain, nil
	}
	return row.Value, nil
}

func (s *Store) DeleteSetting(key string) error {
	err := s.db.Where("key = ?", key).Delete(&models.Setting{}).Error
	if err == nil && strings.HasPrefix(key, "sub_") && OnSubSettingChange != nil {
		OnSubSettingChange()
	}
	return err
}

func (s *Store) SetSetting(key, value string) error {
	if key == "cf_api_token" && value != "" {
		enc, err := secretcrypt.Seal(value)
		if err != nil {
			return err
		}
		value = enc
	}
	row := models.Setting{Key: key, Value: value, UpdatedAt: now()}
	err := s.db.Save(&row).Error
	if err == nil && strings.HasPrefix(key, "sub_") && OnSubSettingChange != nil {
		OnSubSettingChange()
	}
	return err
}
