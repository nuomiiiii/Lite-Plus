package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

func CoreSupportsUserRoute(core, protocol string) bool {
	proto := strings.ToLower(strings.TrimSpace(protocol))
	switch strings.ToLower(strings.TrimSpace(core)) {
	case models.CoreXray, "":
		switch proto {
		case "vless", "vmess", "trojan", "shadowsocks", "http", "socks", "":
			return true
		default:
			return false
		}
	case models.CoreSingBox:
		switch proto {
		case "vless", "vmess", "trojan", "shadowsocks", "http", "socks", "mixed", "hysteria2", "tuic", "anytls", "":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func NormalizeRouteUserIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("%w: empty user id", ErrInvalid)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func ParseRouteUserIDsJSON(raw json.RawMessage) ([]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, fmt.Errorf("%w: user_ids", ErrInvalid)
	}
	return NormalizeRouteUserIDs(ids)
}

func routeRuleUserIDs(ruleJSON string) []string {
	ids, err := routeRuleUserIDsStrict(ruleJSON)
	if err != nil {
		return nil
	}
	return ids
}

func routeRuleUserIDsStrict(ruleJSON string) ([]string, error) {
	var rule struct {
		UserIDs json.RawMessage `json:"user_ids"`
	}
	if strings.TrimSpace(ruleJSON) == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		return nil, fmt.Errorf("%w: rule_json", ErrInvalid)
	}
	return ParseRouteUserIDsJSON(rule.UserIDs)
}

func routeHasUserConstraint(ruleJSON string) bool {
	return len(routeRuleUserIDs(ruleJSON)) > 0
}

func (s *Store) normalizeAndValidateRouteUsers(row *models.Route) error {
	if row == nil {
		return fmt.Errorf("%w: route required", ErrInvalid)
	}
	ids, err := routeRuleUserIDsStrict(row.RuleJSON)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	rule := routeRuleMap(row.RuleJSON)
	rule["user_ids"] = ids
	row.RuleJSON = marshalRouteRule(rule)
	if err := s.validateRouteUsersWithInbound(row, ids, nil); err != nil {
		return err
	}
	if err := s.validateUserRouteExit(row, nil); err != nil {
		return err
	}
	return s.validateChainUserOverridePriority(row)
}

func coreOutboundCompatible(inboundCore, outboundCore, protocol string) bool {
	inCore := strings.ToLower(strings.TrimSpace(inboundCore))
	if inCore == "" {
		inCore = models.CoreXray
	}
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic", "anytls":
		return inCore == models.CoreSingBox
	}
	return true
}

func (s *Store) routeOutboundOKForUser(nodeUUID, id string, in *models.Inbound) error {
	if err := s.routeOutboundOK(nodeUUID, id); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: outbound required", ErrInvalid)
		}
		return err
	}
	if id == "direct" || id == "block" {
		return nil
	}
	row, err := s.GetOutbound(id)
	if err != nil {
		return err
	}
	if !row.Enabled {
		return fmt.Errorf("%w: outbound disabled", ErrInvalid)
	}
	if in != nil && !coreOutboundCompatible(in.Core, row.Core, row.Protocol) {
		return fmt.Errorf("%w: outbound core mismatch", ErrInvalid)
	}
	return nil
}

func (s *Store) validateUserRouteExit(row *models.Route, in *models.Inbound) error {
	if row == nil || !row.Enabled || !routeHasUserConstraint(row.RuleJSON) {
		return nil
	}
	if settingsFlag(row.RuleJSON, "chain_managed") {
		return nil
	}
	inboundID := routeRuleInboundID(row.RuleJSON)
	if in == nil || strings.TrimSpace(in.ID) != inboundID {
		if inboundID != "" {
			if got, err := s.GetInbound(inboundID); err == nil {
				in = got
			}
		}
	}
	rule := routeRuleMap(row.RuleJSON)
	ids := make([]string, 0, 2)
	if primary := ruleString(rule, "primary_outbound_id"); primary != "" {
		ids = append(ids, primary)
	} else if oid := routeRuleOutboundID(row.RuleJSON); oid != "" {
		ids = append(ids, oid)
	}
	if backup := ruleString(rule, "backup_outbound_id"); backup != "" {
		ids = append(ids, backup)
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: outbound required", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if s.RouteManagedOutbound(id) {
			continue
		}
		if err := s.routeOutboundOKForUser(row.NodeUUID, id, in); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) validateChainUserOverridePriority(row *models.Route) error {
	if row == nil || !row.Enabled {
		return nil
	}
	if !routeHasUserConstraint(row.RuleJSON) || settingsFlag(row.RuleJSON, "chain_managed") {
		return nil
	}
	inboundID := routeRuleInboundID(row.RuleJSON)
	if inboundID == "" || !s.InboundBoundToChain(inboundID) {
		return nil
	}
	fallback, err := s.managedRouteForSource(inboundID)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if !fallback.Enabled {
		return nil
	}
	if row.Priority >= fallback.Priority {
		return fmt.Errorf("%w: chain_user_priority %d", ErrInvalid, fallback.Priority)
	}
	return nil
}

func (s *Store) validateSourceUserOverridesAheadOf(sourceID string, fallbackPriority int) error {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return nil
	}
	var routes []models.Route
	if err := s.db.Find(&routes).Error; err != nil {
		return err
	}
	for _, row := range routes {
		if !row.Enabled || settingsFlag(row.RuleJSON, "chain_managed") {
			continue
		}
		if !routeHasUserConstraint(row.RuleJSON) {
			continue
		}
		if routeRuleInboundID(row.RuleJSON) != sourceID {
			continue
		}
		if row.Priority >= fallbackPriority {
			return fmt.Errorf("%w: chain_user_priority %d", ErrInvalid, fallbackPriority)
		}
	}
	return nil
}

func (s *Store) validateRouteUsers(row *models.Route, userIDs []string) error {
	return s.validateRouteUsersWithInbound(row, userIDs, nil)
}

func (s *Store) validateRouteUsersWithInbound(row *models.Route, userIDs []string, in *models.Inbound) error {
	inboundID := routeRuleInboundID(row.RuleJSON)
	if inboundID == "" {
		return fmt.Errorf("%w: user_ids inbound required", ErrInvalid)
	}
	if in == nil || strings.TrimSpace(in.ID) != inboundID {
		got, err := s.GetInbound(inboundID)
		if err != nil {
			return fmt.Errorf("%w: inbound required", ErrInvalid)
		}
		in = got
	}
	if strings.TrimSpace(in.NodeUUID) != strings.TrimSpace(row.NodeUUID) {
		return fmt.Errorf("%w: inbound required", ErrInvalid)
	}
	if !CoreSupportsUserRoute(in.Core, in.Protocol) {
		return fmt.Errorf("%w: route_user_unsupported", ErrInvalid)
	}
	for _, userID := range userIDs {
		if _, err := s.GetUser(userID); err != nil {
			if isNotFound(err) {
				return fmt.Errorf("%w: user not found", ErrInvalid)
			}
			return err
		}
		ok, err := s.userGrantedOn(userID, inboundID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: user not granted", ErrInvalid)
		}
	}
	return nil
}

func (s *Store) userGrantedOn(userID, inboundID string) (bool, error) {
	var n int64
	err := s.db.Model(&models.Grant{}).Where("user_id = ? AND inbound_id = ?", userID, inboundID).Count(&n).Error
	return n > 0, err
}

func inboundCoreOf(core string) string {
	core = strings.ToLower(strings.TrimSpace(core))
	if core == "" {
		return models.CoreXray
	}
	return core
}

func inboundProtocolOf(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func inboundUserRouteCompatChanged(prev, next *models.Inbound) bool {
	if prev == nil || next == nil {
		return false
	}
	return inboundCoreOf(prev.Core) != inboundCoreOf(next.Core) || inboundProtocolOf(prev.Protocol) != inboundProtocolOf(next.Protocol)
}

func (s *Store) userRouteExitIDs(row *models.Route) []string {
	if row == nil {
		return nil
	}
	rule := routeRuleMap(row.RuleJSON)
	ids := make([]string, 0, 2)
	if primary := ruleString(rule, "primary_outbound_id"); primary != "" {
		ids = append(ids, primary)
	} else if oid := routeRuleOutboundID(row.RuleJSON); oid != "" {
		ids = append(ids, oid)
	}
	if backup := ruleString(rule, "backup_outbound_id"); backup != "" {
		ids = append(ids, backup)
	}
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if s.RouteManagedOutbound(id) {
			ob, err := s.GetOutbound(id)
			if err != nil {
				continue
			}
			for _, member := range settingsStringList(ob.SettingsJSON, "member_ids") {
				add(member)
			}
			continue
		}
		add(id)
	}
	return out
}

func (s *Store) validateUserRouteOutboundCore(row *models.Route, in *models.Inbound) error {
	if row == nil || in == nil || settingsFlag(row.RuleJSON, "chain_managed") {
		return nil
	}
	for _, id := range s.userRouteExitIDs(row) {
		if id == "direct" || id == "block" {
			continue
		}
		ob, err := s.GetOutbound(id)
		if err != nil {
			continue
		}
		if !coreOutboundCompatible(in.Core, ob.Core, ob.Protocol) {
			return fmt.Errorf("%w: outbound core mismatch", ErrInvalid)
		}
	}
	return nil
}

func (s *Store) validateUserRoutesAgainstInbound(in *models.Inbound) error {
	if in == nil || strings.TrimSpace(in.ID) == "" {
		return nil
	}
	existing, err := s.GetInbound(in.ID)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if !inboundUserRouteCompatChanged(existing, in) {
		return nil
	}
	routes, err := s.ListRoutes(in.NodeUUID)
	if err != nil {
		return err
	}
	coreChanged := inboundCoreOf(existing.Core) != inboundCoreOf(in.Core)
	supported := CoreSupportsUserRoute(in.Core, in.Protocol)
	for i := range routes {
		row := routes[i]
		if !row.Enabled || routeRuleInboundID(row.RuleJSON) != in.ID {
			continue
		}
		if !routeHasUserConstraint(row.RuleJSON) {
			continue
		}
		if !supported {
			return fmt.Errorf("%w: route_user_unsupported", ErrInvalid)
		}
		if coreChanged {
			if err := s.validateUserRouteOutboundCore(&row, in); err != nil {
				return err
			}
		}
	}
	return nil
}
