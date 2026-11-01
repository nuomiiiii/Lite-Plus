package firewall

import (
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/database/clients"
	fwstore "github.com/nuomiiiii/lite/database/firewall"
	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	nodemgtmodels "github.com/nuomiiiii/lite/nodemgt/models"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func ListenHoles(_ string, intent v2.FirewallIntent) []v2.FirewallHole {
	if !intent.DefaultDeny4 && !intent.DefaultDeny6 {
		return nil
	}
	// Inbound-linked allows are already in intent.Rules. A second listen hole
	// for the same port made Plus write two identical ACCEPT rules when
	// 同时放行该端口 is checked.
	return nil
}

type InboundFirewallOp int

const (
	InboundFirewallNone InboundFirewallOp = iota
	InboundFirewallLink
	InboundFirewallUnlink
)

func PlannedInboundFirewallOp(wasLinked bool, wantAllow *bool, prev *nodemgtmodels.Inbound, next nodemgtmodels.Inbound, nextCfg inboundcfg.Settings) InboundFirewallOp {
	if wantAllow == nil {
		return InboundFirewallNone
	}
	if *wantAllow {
		if !wasLinked || prev == nil || inboundFirewallSpecChanged(*prev, next, nextCfg) {
			return InboundFirewallLink
		}
		return InboundFirewallNone
	}
	if wasLinked {
		return InboundFirewallUnlink
	}
	return InboundFirewallNone
}

func inboundFirewallSpecChanged(prev, next nodemgtmodels.Inbound, nextCfg inboundcfg.Settings) bool {
	if prev.Enabled != next.Enabled || prev.Port != next.Port {
		return true
	}
	if !strings.EqualFold(prev.Protocol, next.Protocol) {
		return true
	}
	prevCfg := inboundcfg.Parse(prev.SettingsJSON)
	if !strings.EqualFold(strings.TrimSpace(prevCfg.Stack), strings.TrimSpace(nextCfg.Stack)) {
		return true
	}
	if strings.EqualFold(next.Protocol, "shadowsocks") {
		if inboundcfg.EffectiveSSNetwork(prevCfg) != inboundcfg.EffectiveSSNetwork(nextCfg) {
			return true
		}
		if strings.TrimSpace(prevCfg.SSNetwork) == "" && strings.TrimSpace(nextCfg.SSNetwork) != "" {
			return true
		}
	} else if !strings.EqualFold(strings.TrimSpace(prevCfg.Transport), strings.TrimSpace(nextCfg.Transport)) {
		return true
	}
	return false
}

func LinkInbound(nodeUUID string, inbound nodemgtmodels.Inbound) error {
	cfg := inboundcfg.Parse(inbound.SettingsJSON)
	return replaceInboundRules(nodeUUID, inbound, cfg, true)
}

func UnlinkInbound(nodeUUID, inboundID string) error {
	return replaceInboundRules(nodeUUID, nodemgtmodels.Inbound{ID: inboundID, NodeUUID: nodeUUID}, inboundcfg.Settings{}, false)
}

func clientExists(nodeUUID string) bool {
	_, err := clients.GetClientByUUID(nodeUUID)
	return err == nil
}

func replaceInboundRules(nodeUUID string, inbound nodemgtmodels.Inbound, cfg inboundcfg.Settings, add bool) error {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" || strings.TrimSpace(inbound.ID) == "" {
		return nil
	}
	if !clientExists(nodeUUID) {
		if add {
			return nil
		}
		return dropInboundRulesLocal(nodeUUID, inbound.ID)
	}
	row, err := fwstore.EnsureRow(nodeUUID)
	if err != nil {
		return err
	}
	intent, err := NormalizeIntent(fwstore.IntentFromRow(row))
	if err != nil {
		intent = fwstore.IntentFromRow(row)
	}
	had := false
	kept := make([]v2.FirewallRule, 0, len(intent.Rules))
	for _, rule := range intent.Rules {
		if rule.Origin == v2.FirewallOriginInbound && rule.InboundID == inbound.ID {
			had = true
			continue
		}
		kept = append(kept, rule)
	}
	intent.Rules = kept
	if add && inbound.Port > 0 {
		listenNet := cfg.Transport
		if strings.EqualFold(inbound.Protocol, "shadowsocks") {
			listenNet = inboundcfg.EffectiveSSNetwork(cfg)
		}
		proto := ProtocolForInbound(inbound.Protocol, listenNet)
		priority := nextPriority(intent.Rules)
		for _, stack := range StacksForInbound(cfg.Stack) {
			base := v2.FirewallRule{
				Enabled:   inbound.Enabled,
				Action:    v2.FirewallActionAllow,
				Protocol:  proto,
				Port:      fmt.Sprintf("%d", inbound.Port),
				Stack:     stack,
				Origin:    v2.FirewallOriginInbound,
				Priority:  priority,
				InboundID: inbound.ID,
			}
			for _, expanded := range ExpandProtocols(base) {
				expanded.Comment = InboundComment(inbound.Name, inbound.Protocol, expanded.Protocol, stack, inbound.Port)
				rule, err := NormalizeRule(expanded)
				if err != nil {
					return err
				}
				before := len(intent.Rules)
				intent.Rules = UpsertRuleByIdentity(intent.Rules, rule)
				if len(intent.Rules) > before {
					priority++
				}
			}
		}
	} else if !had {
		return nil
	}
	saved, err := fwstore.SaveIntent(nodeUUID, intent)
	if err != nil {
		return err
	}
	applied := fwstore.IntentFromRow(saved)
	return waitApply(nodeUUID, applied, ListenHoles(nodeUUID, applied))
}

func dropInboundRulesLocal(nodeUUID, inboundID string) error {
	row, err := fwstore.Get(nodeUUID)
	if err != nil || row == nil {
		return err
	}
	intent := fwstore.IntentFromRow(row)
	kept := make([]v2.FirewallRule, 0, len(intent.Rules))
	removed := false
	for _, rule := range intent.Rules {
		if rule.Origin == v2.FirewallOriginInbound && rule.InboundID == inboundID {
			removed = true
			continue
		}
		kept = append(kept, rule)
	}
	if !removed {
		return nil
	}
	intent.Rules = kept
	_, err = fwstore.SaveIntent(nodeUUID, intent)
	return err
}

func waitApply(nodeUUID string, intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	if !clientExists(nodeUUID) {
		return nil
	}
	result, got := DispatchApply(nodeUUID, intent, holes)
	if got && result.Status != "" && result.Status != v2.FirewallStatusOK {
		if msg := strings.TrimSpace(result.Error); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("firewall apply failed")
	}
	row, err := fwstore.Get(nodeUUID)
	if err != nil {
		return err
	}
	if row != nil && row.DeliveryStatus == fwstore.DeliveryFailed {
		if msg := strings.TrimSpace(row.DeliveryError); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("firewall apply failed")
	}
	if !got {
		if row != nil && row.DeliveryStatus == fwstore.DeliveryQueued {
			return nil
		}
		return fmt.Errorf("firewall command timed out")
	}
	return nil
}

func nextPriority(rules []v2.FirewallRule) int {
	max := DefaultPrio
	for _, rule := range rules {
		if rule.Priority > max {
			max = rule.Priority
		}
	}
	next := max + 1
	if next > MaxPriority {
		return MaxPriority
	}
	return next
}

func InboundLinked(nodeUUID, inboundID string) bool {
	row, err := fwstore.Get(nodeUUID)
	if err != nil || row == nil {
		return false
	}
	for _, rule := range fwstore.IntentFromRow(row).Rules {
		if rule.Origin == v2.FirewallOriginInbound && rule.InboundID == inboundID {
			return true
		}
	}
	return false
}
