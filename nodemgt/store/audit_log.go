package store

import (
	"encoding/json"
	"strings"

	dbmodels "github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

const nodemgtLogType = "nodemgt"

var nodemgtAuditKeys = map[string]string{
	"nodemgt.assign":                   "audit.nodemgt_assign",
	"nodemgt.plan.apply":               "audit.nodemgt_plan_apply",
	"nodemgt.unassign":                 "audit.nodemgt_unassign",
	"nodemgt.renew":                    "audit.nodemgt_renew",
	"nodemgt.topup":                    "audit.nodemgt_topup",
	"nodemgt.modify":                   "audit.nodemgt_modify",
	"nodemgt.disable":                  "audit.nodemgt_disable",
	"nodemgt.inbound.upsert":           "audit.nodemgt_inbound_upsert",
	"nodemgt.inbound.delete":           "audit.nodemgt_inbound_delete",
	"nodemgt.inbound.reorder":          "audit.nodemgt_inbound_reorder",
	"nodemgt.outbound.upsert":          "audit.nodemgt_outbound_upsert",
	"nodemgt.outbound.delete":          "audit.nodemgt_outbound_delete",
	"nodemgt.route.upsert":             "audit.nodemgt_route_upsert",
	"nodemgt.route.delete":             "audit.nodemgt_route_delete",
	"nodemgt.user.upsert":              "audit.nodemgt_user_upsert",
	"nodemgt.user.clearIPs":            "audit.nodemgt_user_clear_ips",
	"nodemgt.user.delete":              "audit.nodemgt_user_delete",
	"nodemgt.user.setStatus":           "audit.nodemgt_user_set_status",
	"nodemgt.credential.issue":         "audit.nodemgt_credential_issue",
	"nodemgt.credential.rotate":        "audit.nodemgt_credential_rotate",
	"nodemgt.credential.revoke":        "audit.nodemgt_credential_revoke",
	"nodemgt.plan.delete":              "audit.nodemgt_plan_delete",
	"nodemgt.plan.upsert":              "audit.nodemgt_plan_upsert",
	"nodemgt.root_cert.issue":          "audit.nodemgt_root_cert_issue",
	"nodemgt.root_cert.delete":         "audit.nodemgt_root_cert_delete",
	"nodemgt.root_cert.set_auto_renew": "audit.nodemgt_root_cert_auto_renew",
	"nodemgt.cert.set_auto_renew":      "audit.nodemgt_cert_auto_renew",
	"nodemgt.cert.deploy_root":         "audit.nodemgt_cert_deploy_root",
	"nodemgt.cert.bind_file":           "audit.nodemgt_cert_bind_file",
	"nodemgt.cert.issue":               "audit.nodemgt_cert_issue",
	"nodemgt.cert.delete":              "audit.nodemgt_cert_delete",
	"nodemgt.subscription.delete":      "audit.nodemgt_subscription_delete",
	"nodemgt.subscription.upsert":      "audit.nodemgt_subscription_upsert",
	"nodemgt.settings.set":             "audit.nodemgt_settings_set",
	"nodemgt.node.upsert":              "audit.nodemgt_node_upsert",
	"nodemgt.chain.upsert":             "audit.nodemgt_chain_upsert",
	"nodemgt.chain.delete":             "audit.nodemgt_chain_delete",
	"nodemgt.template.upsert":          "audit.nodemgt_template_upsert",
	"nodemgt.template.delete":          "audit.nodemgt_template_delete",
	"nodemgt.template.bind":            "audit.nodemgt_template_bind",
}

func NodemgtAuditPayload(action, target, detail string) (string, map[string]string) {
	key := nodemgtAuditKeys[action]
	if key == "" {
		key = "audit.nodemgt_action"
	}
	name := strings.TrimSpace(detail)
	if name == "" || name == "nodemgt" {
		name = strings.TrimSpace(target)
	}
	if name == "nodemgt" {
		name = ""
	}
	return key, map[string]string{"name": name, "target": strings.TrimSpace(target)}
}

func (s *Store) Audit(actor, action, target, detail string) error {
	return s.AuditFrom("", actor, action, target, detail)
}

func (s *Store) AuditFrom(ip, actor, action, target, detail string) error {
	if s.db == nil || !s.db.Migrator().HasTable(&dbmodels.Log{}) {
		return nil
	}
	key, params := NodemgtAuditPayload(action, target, detail)
	return s.db.Create(&dbmodels.Log{
		IP:      strings.TrimSpace(ip),
		UUID:    strings.TrimSpace(actor),
		Message: nodemgtLogMessage(key, params),
		MsgType: nodemgtLogType,
		Time:    now(),
	}).Error
}

func (s *Store) migrateAuditEventsToLogs() error {
	if !s.db.Migrator().HasTable(&models.AuditEvent{}) || !s.db.Migrator().HasTable(&dbmodels.Log{}) {
		return nil
	}
	var rows []models.AuditEvent
	if err := s.db.Order("created_at ASC").Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		key, params := NodemgtAuditPayload(row.Action, row.Target, row.Detail)
		entry := dbmodels.Log{
			IP:      "",
			UUID:    strings.TrimSpace(row.Actor),
			Message: nodemgtLogMessage(key, params),
			MsgType: nodemgtLogType,
			Time:    row.CreatedAt,
		}
		if err := s.db.Session(&gorm.Session{SkipHooks: true}).Create(&entry).Error; err != nil {
			return err
		}
	}
	return s.db.Where("1 = 1").Delete(&models.AuditEvent{}).Error
}

func nodemgtLogMessage(key string, params map[string]string) string {
	if params == nil {
		params = map[string]string{}
	}
	raw, err := json.Marshal(struct {
		K string            `json:"k"`
		P map[string]string `json:"p,omitempty"`
		S string            `json:"s,omitempty"`
	}{
		K: key,
		P: params,
		S: strings.TrimSpace(strings.Join([]string{params["name"], params["target"]}, " ")),
	})
	if err != nil {
		return key
	}
	return string(raw)
}
