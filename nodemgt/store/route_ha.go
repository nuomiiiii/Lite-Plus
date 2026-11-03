package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

func (s *Store) UpsertUserRoute(row *models.Route) error {
	if row == nil {
		return fmt.Errorf("%w: route required", ErrInvalid)
	}
	if settingsFlag(row.RuleJSON, "chain_managed") {
		return s.UpsertRoute(row)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		return New(tx).applyRouteHA(row)
	})
}

func (s *Store) RouteManagedOutbound(id string) bool {
	row, err := s.GetOutbound(id)
	if err != nil {
		return false
	}
	return settingsFlag(row.SettingsJSON, "route_managed")
}

func (s *Store) applyRouteHA(row *models.Route) error {
	if row.ID == "" {
		row.ID = newID()
	}
	existingGroup := ""
	if existing, err := s.GetRoute(row.ID); err == nil {
		existingGroup = settingsString(existing.RuleJSON, "group_outbound_id")
		if row.CreatedAt.IsZero() {
			row.CreatedAt = existing.CreatedAt
		}
	} else if !isNotFound(err) {
		return err
	}
	rule := routeRuleMap(row.RuleJSON)
	strategy := normalizeRouteStrategy(ruleString(rule, "strategy"))
	primary := ruleString(rule, "primary_outbound_id")
	if primary == "" {
		primary = ruleString(rule, "outbound_id")
	}
	if primary == "" {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	backupDirect := ruleBool(rule, "backup_direct") || strings.EqualFold(ruleString(rule, "backup_outbound_id"), "direct")
	backup := ruleString(rule, "backup_outbound_id")
	if backupDirect {
		backup = ""
	}
	fallback := ruleBool(rule, "fallback_direct")
	if strategy != chainStrategyFailover {
		if err := s.dropRouteGroup(existingGroup); err != nil {
			return err
		}
		rule["strategy"] = chainStrategyNone
		rule["outbound_id"] = primary
		rule["primary_outbound_id"] = primary
		delete(rule, "backup_outbound_id")
		delete(rule, "backup_direct")
		delete(rule, "fallback_direct")
		delete(rule, "group_outbound_id")
		row.RuleJSON = marshalRouteRule(rule)
		return s.UpsertRoute(row)
	}
	if backupDirect {
		fallback = false
	} else if backup == "" || backup == primary {
		return fmt.Errorf("%w: route_backup_required", ErrInvalid)
	}
	members := []string{primary}
	if !backupDirect {
		if err := s.routeOutboundOK(row.NodeUUID, backup); err != nil {
			return err
		}
		members = append(members, backup)
	}
	if err := s.routeOutboundOK(row.NodeUUID, primary); err != nil {
		return err
	}
	group, err := s.upsertRouteGroupOutbound(row, existingGroup, members, backupDirect, fallback)
	if err != nil {
		return err
	}
	rule["strategy"] = chainStrategyFailover
	rule["outbound_id"] = group.ID
	rule["primary_outbound_id"] = primary
	rule["backup_direct"] = backupDirect
	rule["fallback_direct"] = fallback && !backupDirect
	rule["group_outbound_id"] = group.ID
	if backupDirect {
		delete(rule, "backup_outbound_id")
	} else {
		rule["backup_outbound_id"] = backup
	}
	row.RuleJSON = marshalRouteRule(rule)
	return s.UpsertRoute(row)
}

func (s *Store) routeOutboundOK(nodeUUID, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	if id == "direct" || id == "block" {
		return nil
	}
	row, err := s.GetOutbound(id)
	if err != nil {
		return err
	}
	if settingsFlag(row.SettingsJSON, "chain_managed") || settingsFlag(row.SettingsJSON, "route_managed") {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	if strings.TrimSpace(row.NodeUUID) != strings.TrimSpace(nodeUUID) {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	return nil
}

func (s *Store) upsertRouteGroupOutbound(route *models.Route, existingID string, members []string, backupDirect, fallback bool) (*models.Outbound, error) {
	settings, _ := json.Marshal(map[string]any{
		"route_id":        route.ID,
		"route_managed":   true,
		"chain_group":     true,
		"strategy":        chainStrategyFailover,
		"backup_direct":   backupDirect,
		"fallback_direct": fallback && !backupDirect,
		"member_ids":      members,
		"interval":        "1m",
	})
	row := &models.Outbound{
		NodeUUID:     route.NodeUUID,
		Core:         s.routeGroupCore(route.NodeUUID, members[0]),
		Name:         routeGroupName(route.ID),
		Protocol:     "failover",
		SettingsJSON: string(settings),
		Enabled:      route.Enabled,
	}
	if existingID != "" {
		if existing, err := s.GetOutbound(existingID); err == nil && settingsFlag(existing.SettingsJSON, "route_managed") {
			row.ID = existing.ID
			row.CreatedAt = existing.CreatedAt
			row.Name = existing.Name
			if outboundConfigEqual(existing, row) {
				return existing, nil
			}
		} else if err != nil && !isNotFound(err) {
			return nil, err
		}
	}
	if err := s.UpsertOutbound(row); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) routeGroupCore(nodeUUID, primaryID string) string {
	if ob, err := s.GetOutbound(primaryID); err == nil && strings.TrimSpace(ob.Core) != "" {
		return ob.Core
	}
	ins, err := s.ListInbounds(nodeUUID)
	if err == nil {
		for _, in := range ins {
			if strings.TrimSpace(in.Core) != "" {
				return in.Core
			}
		}
	}
	return models.CoreXray
}

func (s *Store) dropRouteGroup(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if !s.RouteManagedOutbound(id) {
		return nil
	}
	return s.db.Delete(&models.Outbound{}, "id = ?", id).Error
}

func (s *Store) deleteRoutesUsingOutbound(id string) error {
	var routes []models.Route
	if err := s.db.Find(&routes).Error; err != nil {
		return err
	}
	for _, row := range routes {
		if !routeRefersOutbound(row.RuleJSON, id) {
			continue
		}
		groupID := settingsString(row.RuleJSON, "group_outbound_id")
		if err := s.db.Delete(&models.Route{}, "id = ?", row.ID).Error; err != nil {
			return err
		}
		if groupID != "" && groupID != id {
			if err := s.db.Delete(&models.Outbound{}, "id = ?", groupID).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func routeRefersOutbound(ruleJSON, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	if routeRuleOutboundID(ruleJSON) == id {
		return true
	}
	for _, key := range []string{"primary_outbound_id", "backup_outbound_id", "group_outbound_id"} {
		if settingsString(ruleJSON, key) == id {
			return true
		}
	}
	return false
}

func normalizeRouteStrategy(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), chainStrategyFailover) {
		return chainStrategyFailover
	}
	return chainStrategyNone
}

func routeGroupName(routeID string) string {
	return "route-" + shortID(routeID)
}

func routeRuleMap(raw string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func marshalRouteRule(rule map[string]any) string {
	raw, err := json.Marshal(rule)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func ruleString(rule map[string]any, key string) string {
	v, _ := rule[key].(string)
	return strings.TrimSpace(v)
}

func ruleBool(rule map[string]any, key string) bool {
	switch n := rule[key].(type) {
	case bool:
		return n
	case string:
		return strings.EqualFold(n, "true") || n == "1"
	default:
		return false
	}
}
