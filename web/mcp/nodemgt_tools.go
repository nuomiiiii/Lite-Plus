package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nuomiiiii/lite/database/auditlog"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/nodemgt/control"
	nmmodels "github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/ops"
	"github.com/nuomiiiii/lite/nodemgt/store"
)

const (
	mcpMaskedSecret               = "********"
	maxConcurrentMCPChainHopProbes = 8
)

func isMCPSecretKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "password", "ss_password", "pass", "private_key", "reality_private_key", "key_pem", "token", "secret", "cf_api_token":
		return true
	default:
		return false
	}
}

func maskMCPJSONValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, val := range typed {
			if isMCPSecretKey(k) {
				if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
					out[k] = mcpMaskedSecret
				} else {
					out[k] = val
				}
				continue
			}
			out[k] = maskMCPJSONValue(val)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = maskMCPJSONValue(item)
		}
		return out
	default:
		return v
	}
}

func maskMCPJSONString(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return raw
	}
	masked := maskMCPJSONValue(parsed)
	encoded, err := json.Marshal(masked)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func redactMCPInbound(row nmmodels.Inbound) nmmodels.Inbound {
	row.SettingsJSON = maskMCPJSONString(row.SettingsJSON)
	row.StreamJSON = maskMCPJSONString(row.StreamJSON)
	return row
}

func redactMCPOutbound(row nmmodels.Outbound) nmmodels.Outbound {
	row.SettingsJSON = maskMCPJSONString(row.SettingsJSON)
	return row
}

func redactMCPCert(row nmmodels.Certificate) nmmodels.Certificate {
	row.ChainPEM = ""
	return row
}

func redactMCPSubscription(row nmmodels.Subscription) nmmodels.Subscription {
	if strings.TrimSpace(row.Token) != "" {
		row.Token = mcpMaskedSecret
	}
	return row
}

func redactMCPDelivery(cmds []nmmodels.ControlCommand) []gin.H {
	out := make([]gin.H, 0, len(cmds))
	for _, cmd := range cmds {
		out = append(out, gin.H{
			"operation_id": cmd.OperationID,
			"node_uuid":    cmd.NodeUUID,
			"kind":         cmd.Kind,
			"status":       cmd.Status,
			"attempts":     cmd.Attempts,
			"last_error":   cmd.LastError,
			"acked_at":     cmd.AckedAt,
			"created_at":   cmd.CreatedAt,
			"updated_at":   cmd.UpdatedAt,
		})
	}
	return out
}

func nodemgtToolDescriptors() []gin.H {
	action := func(desc string) gin.H { return schema(desc, "string", true) }
	nodeUUID := schema("Target node UUID (must be authorized by this MCP lease)", "string", false)
	id := schema("Resource ID", "string", false)
	return []gin.H{
		tool("nodemgt_overview", "Read nodemgt summary (inbounds, outbounds, routes, chains, certs, delivery status) for authorized nodes", objectSchema(gin.H{
			"node_uuid": nodeUUID,
		}, nil)),
		tool("nodemgt_inbounds", "Manage nodemgt inbounds on authorized nodes (list, upsert, delete)", objectSchema(gin.H{
			"action":        action("list | upsert | delete"),
			"id":            id,
			"node_uuid":     nodeUUID,
			"core":          schema("xray | sing-box", "string", false),
			"name":          schema("Inbound name", "string", false),
			"protocol":      schema("Protocol (vless, vmess, trojan, shadowsocks, hysteria2, tuic, anytls, socks, http)", "string", false),
			"listen":        schema("Listen address (default 0.0.0.0)", "string", false),
			"port":          schema("Listen port (1-65535)", "integer", false),
			"settings_json": schema("JSON string of inbound settings", "string", false),
			"stream_json":   schema("JSON string of stream/transport settings", "string", false),
			"enabled":       schema("Whether the inbound is enabled", "boolean", false),
		}, []string{"action"})),
		tool("nodemgt_outbounds", "Manage nodemgt outbounds on authorized nodes (list, upsert, delete, test)", objectSchema(gin.H{
			"action":        action("list | upsert | delete | test"),
			"id":            id,
			"node_uuid":     nodeUUID,
			"core":          schema("xray | sing-box (optional for generic protocols)", "string", false),
			"name":          schema("Outbound tag/name", "string", false),
			"protocol":      schema("Protocol (freedom, blackhole, vless, vmess, trojan, shadowsocks, hysteria2, tuic, anytls, socks, http)", "string", false),
			"settings_json": schema("JSON string of outbound settings", "string", false),
			"enabled":       schema("Whether the outbound is enabled", "boolean", false),
		}, []string{"action"})),
		tool("nodemgt_routes", "Manage nodemgt routing rules on authorized nodes (list, upsert, delete)", objectSchema(gin.H{
			"action":    action("list | upsert | delete"),
			"id":        id,
			"node_uuid": nodeUUID,
			"name":      schema("Route name", "string", false),
			"priority":  schema("Route priority (lower runs first)", "integer", false),
			"rule_json": schema("JSON string of route match/target rule", "string", false),
			"enabled":   schema("Whether the route is enabled", "boolean", false),
		}, []string{"action"})),
		tool("nodemgt_chains", "Manage nodemgt forwarding chains across authorized nodes (list, upsert, delete, test)", objectSchema(gin.H{
			"action":              action("list | upsert | delete | test"),
			"id":                  id,
			"node_uuid":           nodeUUID,
			"name":                schema("Chain name", "string", false),
			"strategy":            schema("none | failover | urltest", "string", false),
			"backup_direct":       schema("Use direct as backup for failover", "boolean", false),
			"fallback_direct":     schema("Fallback to direct when all landings fail", "boolean", false),
			"source_inbound_ids":  gin.H{"type": "array", "items": gin.H{"type": "string"}, "description": "Source inbound IDs"},
			"landing_inbound_ids": gin.H{"type": "array", "items": gin.H{"type": "string"}, "description": "Landing inbound IDs"},
			"enabled":             schema("Whether the chain is enabled", "boolean", false),
		}, []string{"action"})),
		tool("nodemgt_users", "Manage global nodemgt users (list, upsert, delete, set_status, clear_ips; requires all-nodes MCP lease)", objectSchema(gin.H{
			"action":         action("list | upsert | delete | set_status | clear_ips"),
			"id":             id,
			"node_uuid":      nodeUUID,
			"username":       schema("Username", "string", false),
			"display_name":   schema("Display name", "string", false),
			"status":         schema("active | disabled | expired", "string", false),
			"quota_bytes":    schema("Traffic quota in bytes (0 = unlimited)", "integer", false),
			"rate_limit_bps": schema("Rate limit in bytes/sec (0 = unlimited)", "integer", false),
			"device_limit":   schema("Max unique online IPs (0 = unlimited)", "integer", false),
		}, []string{"action"})),
		tool("nodemgt_plans", "Manage nodemgt plans (list, upsert, delete; requires all-nodes MCP lease)", objectSchema(gin.H{
			"action":         action("list | upsert | delete"),
			"id":             id,
			"name":           schema("Plan name", "string", false),
			"traffic_bytes":  schema("Traffic allowance in bytes", "integer", false),
			"duration_days":  schema("Duration in days", "integer", false),
			"rate_limit_bps": schema("Rate limit in bytes/sec", "integer", false),
			"device_limit":   schema("Max unique online IPs", "integer", false),
		}, []string{"action"})),
		tool("nodemgt_subscriptions", "Manage nodemgt subscriptions (list, upsert, delete; requires all-nodes MCP lease)", objectSchema(gin.H{
			"action":      action("list | upsert | delete"),
			"id":          id,
			"user_id":     schema("Node user ID", "string", false),
			"format":      schema("Subscription format (xray, sing-box, clash, v2ray)", "string", false),
			"auto_detect": schema("Auto-detect client format from User-Agent", "boolean", false),
			"enabled":     schema("Whether the subscription is enabled", "boolean", false),
		}, []string{"action"})),
		tool("nodemgt_certs", "List or delete nodemgt certificates on authorized nodes (list, delete)", objectSchema(gin.H{
			"action":    action("list | delete"),
			"id":        id,
			"node_uuid": nodeUUID,
		}, []string{"action"})),
		tool("nodemgt_sync", "Push pending nodemgt config to authorized nodes or inspect latest delivery status", objectSchema(gin.H{
			"action":    schema("sync | status (default sync)", "string", false),
			"node_uuid": nodeUUID,
		}, nil)),
	}
}

func isNodemgtTool(name string) bool {
	return strings.HasPrefix(name, "nodemgt_")
}

var (
	mcpNodemgtDB    = dbcore.GetDBInstance
	mcpNodemgtLogFn = auditlog.Event
)

func callNodemgtTool(c *gin.Context, lease models.MCPLease, name string, args map[string]any) (any, error) {
	ctx := context.Background()
	if c != nil && c.Request != nil {
		ctx = c.Request.Context()
	}
	st := store.New(mcpNodemgtDB())
	switch name {
	case "nodemgt_overview":
		return mcpNodemgtOverview(lease, st, stringArg(args, "node_uuid"))
	case "nodemgt_inbounds":
		return mcpNodemgtInbounds(c, lease, st, args)
	case "nodemgt_outbounds":
		return mcpNodemgtOutbounds(ctx, c, lease, st, args)
	case "nodemgt_routes":
		return mcpNodemgtRoutes(c, lease, st, args)
	case "nodemgt_chains":
		return mcpNodemgtChains(ctx, c, lease, st, args)
	case "nodemgt_users":
		return mcpNodemgtUsers(c, lease, st, args)
	case "nodemgt_plans":
		return mcpNodemgtPlans(c, lease, st, args)
	case "nodemgt_subscriptions":
		return mcpNodemgtSubscriptions(c, lease, st, args)
	case "nodemgt_certs":
		return mcpNodemgtCerts(c, lease, st, args)
	case "nodemgt_sync":
		return mcpNodemgtSync(c, lease, st, args)
	default:
		return nil, errTool("unknown tool")
	}
}

func mcpNodemgtActor(lease models.MCPLease) string {
	return "mcp:" + strings.TrimSpace(lease.ID)
}

func mcpNodemgtAudit(c *gin.Context, lease models.MCPLease, action, target, detail string) {
	ip := ""
	if c != nil {
		ip = c.ClientIP()
	}
	key, params := store.NodemgtAuditPayload(action, target, detail)
	if mcpNodemgtLogFn != nil {
		mcpNodemgtLogFn(ip, mcpNodemgtActor(lease), "nodemgt", key, params)
	}
}

func mcpAuthorizedNodeSet(lease models.MCPLease) map[string]struct{} {
	if lease.AllNodes {
		return nil
	}
	ids := parseTargetUUIDs(lease.TargetUUIDs)
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func mcpNodeAllowed(lease models.MCPLease, allowed map[string]struct{}, nodeUUID string) bool {
	if lease.AllNodes {
		return true
	}
	_, ok := allowed[strings.TrimSpace(nodeUUID)]
	return ok
}

func mcpRequireNode(lease models.MCPLease, nodeUUID string) error {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return errTool("node_uuid is required")
	}
	_, err := lookupAuthorizedNode(lease, nodeUUID)
	return err
}

func mcpRequireAllNodes(lease models.MCPLease) error {
	if !lease.AllNodes {
		return errTool("this nodemgt operation requires an all-nodes MCP authorization")
	}
	return nil
}

func mcpPushNodeConfig(st *store.Store, nodeUUID string) (string, error) {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return "", nil
	}
	opID, err := control.EnqueueApplyConfigOp(st, nodeUUID)
	if err != nil {
		return "", err
	}
	_ = control.PushPending(st, nodeUUID)
	return opID, nil
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func boolPtrArg(args map[string]any, key string) *bool {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	if b, ok := raw.(bool); ok {
		return &b
	}
	return nil
}

func int64Arg(args map[string]any, key string) int64 {
	raw, ok := args[key]
	if !ok || raw == nil {
		return 0
	}
	switch v := raw.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

func mcpNodemgtOverview(lease models.MCPLease, st *store.Store, nodeUUID string) (any, error) {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID != "" {
		if err := mcpRequireNode(lease, nodeUUID); err != nil {
			return nil, err
		}
	}
	allowed := mcpAuthorizedNodeSet(lease)

	inbounds, err := st.ListInbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	outbounds, err := st.ListOutbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	routes, err := st.ListRoutes(nodeUUID)
	if err != nil {
		return nil, err
	}
	chains, err := st.ListChainViews(nodeUUID)
	if err != nil {
		return nil, err
	}
	certs, err := st.ListCerts(nodeUUID)
	if err != nil {
		return nil, err
	}
	cmds, err := st.LatestCommands()
	if err != nil {
		return nil, err
	}

	filteredInbounds := make([]nmmodels.Inbound, 0, len(inbounds))
	for _, row := range inbounds {
		if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
			filteredInbounds = append(filteredInbounds, redactMCPInbound(row))
		}
	}
	filteredOutbounds := make([]nmmodels.Outbound, 0, len(outbounds))
	for _, row := range outbounds {
		if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
			filteredOutbounds = append(filteredOutbounds, redactMCPOutbound(row))
		}
	}
	filteredRoutes := make([]nmmodels.Route, 0, len(routes))
	for _, row := range routes {
		if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
			filteredRoutes = append(filteredRoutes, row)
		}
	}
	filteredChains := make([]store.ChainView, 0, len(chains))
	for _, ch := range chains {
		if mcpChainAuthorized(lease, allowed, ch) {
			filteredChains = append(filteredChains, ch)
		}
	}
	filteredCerts := make([]nmmodels.Certificate, 0, len(certs))
	for _, row := range certs {
		if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
			filteredCerts = append(filteredCerts, redactMCPCert(row))
		}
	}
	filteredCmds := make([]nmmodels.ControlCommand, 0, len(cmds))
	for _, row := range cmds {
		if (nodeUUID == "" || row.NodeUUID == nodeUUID) && mcpNodeAllowed(lease, allowed, row.NodeUUID) {
			filteredCmds = append(filteredCmds, row)
		}
	}

	return gin.H{
		"inbounds":  filteredInbounds,
		"outbounds": filteredOutbounds,
		"routes":    filteredRoutes,
		"chains":    filteredChains,
		"certs":     filteredCerts,
		"delivery":  redactMCPDelivery(filteredCmds),
	}, nil
}

func mcpNodemgtInbounds(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
		if nodeUUID != "" {
			if err := mcpRequireNode(lease, nodeUUID); err != nil {
				return nil, err
			}
		}
		rows, err := st.ListInbounds(nodeUUID)
		if err != nil {
			return nil, err
		}
		allowed := mcpAuthorizedNodeSet(lease)
		out := make([]nmmodels.Inbound, 0, len(rows))
		for _, row := range rows {
			if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
				out = append(out, redactMCPInbound(row))
			}
		}
		return gin.H{"inbounds": out}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.Inbound
		if id != "" {
			existing, err := st.GetInbound(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
				return nil, err
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "node_uuid")); v != "" {
			if err := mcpRequireNode(lease, v); err != nil {
				return nil, err
			}
			row.NodeUUID = v
		}
		if row.NodeUUID == "" {
			return nil, errTool("node_uuid is required")
		}
		if v := strings.TrimSpace(stringArg(args, "core")); v != "" {
			row.Core = v
		}
		if v := strings.TrimSpace(stringArg(args, "name")); v != "" {
			row.Name = v
		}
		if v := strings.TrimSpace(stringArg(args, "protocol")); v != "" {
			row.Protocol = v
		}
		if v := strings.TrimSpace(stringArg(args, "listen")); v != "" {
			row.Listen = v
		}
		if row.Listen == "" {
			row.Listen = "0.0.0.0"
		}
		if port := int(int64Arg(args, "port")); port > 0 {
			row.Port = port
		}
		if v, ok := args["settings_json"].(string); ok {
			row.SettingsJSON = v
		}
		if v, ok := args["stream_json"].(string); ok {
			row.StreamJSON = v
		}
		if b := boolPtrArg(args, "enabled"); b != nil {
			row.Enabled = *b
		} else if id == "" {
			row.Enabled = true
		}
		if err := st.UpsertInbound(&row); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, row.NodeUUID)
		mcpNodemgtAudit(c, lease, "inbound.upsert", row.Name, row.NodeUUID)
		return gin.H{"inbound": redactMCPInbound(row), "operation_id": opID}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetInbound(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
			return nil, err
		}
		if err := st.DeleteInbound(id); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, existing.NodeUUID)
		mcpNodemgtAudit(c, lease, "inbound.delete", existing.Name, existing.NodeUUID)
		return gin.H{"deleted": true, "id": id, "operation_id": opID}, nil
	default:
		return nil, errTool("action must be list, upsert, or delete")
	}
}

func mcpNodemgtOutbounds(ctx context.Context, c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
		if nodeUUID != "" {
			if err := mcpRequireNode(lease, nodeUUID); err != nil {
				return nil, err
			}
		}
		rows, err := st.ListOutbounds(nodeUUID)
		if err != nil {
			return nil, err
		}
		allowed := mcpAuthorizedNodeSet(lease)
		out := make([]nmmodels.Outbound, 0, len(rows))
		for _, row := range rows {
			if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
				out = append(out, redactMCPOutbound(row))
			}
		}
		return gin.H{"outbounds": out}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.Outbound
		if id != "" {
			existing, err := st.GetOutbound(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
				return nil, err
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "node_uuid")); v != "" {
			if err := mcpRequireNode(lease, v); err != nil {
				return nil, err
			}
			row.NodeUUID = v
		}
		if row.NodeUUID == "" {
			return nil, errTool("node_uuid is required")
		}
		if v := strings.TrimSpace(stringArg(args, "core")); v != "" {
			row.Core = v
		}
		if v := strings.TrimSpace(stringArg(args, "name")); v != "" {
			row.Name = v
		}
		if v := strings.TrimSpace(stringArg(args, "protocol")); v != "" {
			row.Protocol = v
		}
		if v, ok := args["settings_json"].(string); ok {
			row.SettingsJSON = v
		}
		if b := boolPtrArg(args, "enabled"); b != nil {
			row.Enabled = *b
		} else if id == "" {
			row.Enabled = true
		}
		if err := st.UpsertOutbound(&row); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, row.NodeUUID)
		mcpNodemgtAudit(c, lease, "outbound.upsert", row.Name, row.NodeUUID)
		return gin.H{"outbound": redactMCPOutbound(row), "operation_id": opID}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetOutbound(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
			return nil, err
		}
		if err := st.DeleteOutbound(id); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, existing.NodeUUID)
		mcpNodemgtAudit(c, lease, "outbound.delete", existing.Name, existing.NodeUUID)
		return gin.H{"deleted": true, "id": id, "operation_id": opID}, nil
	case "test":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		out, err := st.GetOutbound(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if err := mcpRequireNode(lease, out.NodeUUID); err != nil {
			return nil, err
		}
		tag := strings.TrimSpace(out.Name)
		if tag == "" {
			tag = out.ID
		}
		if !out.Enabled {
			return gin.H{"ok": false, "error": "outbound is disabled", "outbound_id": out.ID, "node_uuid": out.NodeUUID, "tag": tag}, nil
		}
		res := control.ProbeOutbound(ctx, out.NodeUUID, out.Core, tag, 9*time.Second)
		return gin.H{
			"ok":          res.OK,
			"latency_ms":  res.LatencyMS,
			"status_code": res.StatusCode,
			"error":       res.Error,
			"outbound_id": out.ID,
			"node_uuid":   out.NodeUUID,
			"core":        out.Core,
			"tag":         tag,
		}, nil
	default:
		return nil, errTool("action must be list, upsert, delete, or test")
	}
}

func mcpNodemgtRoutes(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
		if nodeUUID != "" {
			if err := mcpRequireNode(lease, nodeUUID); err != nil {
				return nil, err
			}
		}
		rows, err := st.ListRoutes(nodeUUID)
		if err != nil {
			return nil, err
		}
		allowed := mcpAuthorizedNodeSet(lease)
		out := make([]nmmodels.Route, 0, len(rows))
		for _, row := range rows {
			if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
				out = append(out, row)
			}
		}
		return gin.H{"routes": out}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.Route
		if id != "" {
			existing, err := st.GetRoute(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
				return nil, err
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "node_uuid")); v != "" {
			if err := mcpRequireNode(lease, v); err != nil {
				return nil, err
			}
			row.NodeUUID = v
		}
		if row.NodeUUID == "" {
			return nil, errTool("node_uuid is required")
		}
		if v := strings.TrimSpace(stringArg(args, "name")); v != "" {
			row.Name = v
		}
		if _, has := args["priority"]; has {
			row.Priority = int(int64Arg(args, "priority"))
		}
		if v, ok := args["rule_json"].(string); ok {
			row.RuleJSON = v
		}
		if b := boolPtrArg(args, "enabled"); b != nil {
			row.Enabled = *b
		} else if id == "" {
			row.Enabled = true
		}
		if err := st.UpsertRoute(&row); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, row.NodeUUID)
		mcpNodemgtAudit(c, lease, "route.upsert", row.Name, row.NodeUUID)
		return gin.H{"route": row, "operation_id": opID}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetRoute(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
			return nil, err
		}
		if err := st.DeleteRoute(id); err != nil {
			return nil, errTool(err.Error())
		}
		opID, _ := mcpPushNodeConfig(st, existing.NodeUUID)
		mcpNodemgtAudit(c, lease, "route.delete", existing.Name, existing.NodeUUID)
		return gin.H{"deleted": true, "id": id, "operation_id": opID}, nil
	default:
		return nil, errTool("action must be list, upsert, or delete")
	}
}

func mcpChainAuthorized(lease models.MCPLease, allowed map[string]struct{}, view store.ChainView) bool {
	if lease.AllNodes {
		return true
	}
	for _, s := range view.Sources {
		if !mcpNodeAllowed(lease, allowed, s.SourceNodeUUID) {
			return false
		}
	}
	for _, l := range view.Landings {
		if !mcpNodeAllowed(lease, allowed, l.LandingNodeUUID) {
			return false
		}
	}
	return len(view.Sources) > 0 || len(view.Landings) > 0
}

func mcpNodemgtChains(ctx context.Context, c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	allowed := mcpAuthorizedNodeSet(lease)
	switch action {
	case "list":
		nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
		if nodeUUID != "" {
			if err := mcpRequireNode(lease, nodeUUID); err != nil {
				return nil, err
			}
		}
		views, err := st.ListChainViews(nodeUUID)
		if err != nil {
			return nil, err
		}
		out := make([]store.ChainView, 0, len(views))
		for _, v := range views {
			if mcpChainAuthorized(lease, allowed, v) {
				out = append(out, v)
			}
		}
		return gin.H{"chains": out}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id != "" {
			existing, err := st.GetChainView(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			if !mcpChainAuthorized(lease, allowed, *existing) {
				return nil, errTool("chain touches unauthorized nodes")
			}
		}
		sourceIDs := stringSliceArg(args, "source_inbound_ids")
		landingIDs := stringSliceArg(args, "landing_inbound_ids")
		for _, inID := range append(append([]string{}, sourceIDs...), landingIDs...) {
			in, err := st.GetInbound(inID)
			if err != nil {
				return nil, errTool(err.Error())
			}
			if err := mcpRequireNode(lease, in.NodeUUID); err != nil {
				return nil, err
			}
		}
		view, affectedNodes, err := st.UpsertChain(store.ChainUpsert{
			ID:                id,
			Name:              strings.TrimSpace(stringArg(args, "name")),
			Strategy:          strings.TrimSpace(stringArg(args, "strategy")),
			BackupDirect:      boolPtrArg(args, "backup_direct"),
			FallbackDirect:    boolPtrArg(args, "fallback_direct"),
			SourceInboundIDs:  sourceIDs,
			LandingInboundIDs: landingIDs,
			Enabled:           boolPtrArg(args, "enabled"),
		})
		if err != nil {
			return nil, errTool(err.Error())
		}
		for _, n := range affectedNodes {
			_, _ = mcpPushNodeConfig(st, n)
		}
		mcpNodemgtAudit(c, lease, "chain.upsert", view.Name, view.ID)
		return gin.H{"chain": view, "affected_nodes": affectedNodes}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetChainView(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if !mcpChainAuthorized(lease, allowed, *existing) {
			return nil, errTool("chain touches unauthorized nodes")
		}
		affectedNodes, err := st.DeleteChain(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		for _, n := range affectedNodes {
			_, _ = mcpPushNodeConfig(st, n)
		}
		mcpNodemgtAudit(c, lease, "chain.delete", existing.Name, id)
		return gin.H{"deleted": true, "id": id, "affected_nodes": affectedNodes}, nil
	case "test":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		view, err := st.GetChainView(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if !mcpChainAuthorized(lease, allowed, *view) {
			return nil, errTool("chain touches unauthorized nodes")
		}
		if !view.Enabled {
			return gin.H{"ok": false, "error": "chain is disabled", "chain_id": view.ID, "results": []any{}}, nil
		}
		type hopTarget struct {
			outbound *nmmodels.Outbound
			tag      string
		}
		seen := map[string]struct{}{}
		var targets []hopTarget
		for _, src := range view.Sources {
			if strings.TrimSpace(src.OutboundID) == "" {
				continue
			}
			rootOut, err := st.GetOutbound(src.OutboundID)
			if err != nil || rootOut == nil {
				continue
			}
			hops := []*nmmodels.Outbound{rootOut}
			proto := strings.ToLower(strings.TrimSpace(rootOut.Protocol))
			if proto == "urltest" || proto == "failover" {
				var s struct {
					MemberIDs []string `json:"member_ids"`
				}
				_ = json.Unmarshal([]byte(rootOut.SettingsJSON), &s)
				var members []*nmmodels.Outbound
				for _, mID := range s.MemberIDs {
					if m, err := st.GetOutbound(strings.TrimSpace(mID)); err == nil && m != nil {
						members = append(members, m)
					}
				}
				if len(members) > 0 {
					hops = members
				}
			}
			for _, h := range hops {
				key := h.NodeUUID + "::" + h.ID
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				tag := strings.TrimSpace(h.Name)
				if tag == "" {
					tag = h.ID
				}
				targets = append(targets, hopTarget{outbound: h, tag: tag})
			}
		}
		results := make([]gin.H, len(targets))
		sem := make(chan struct{}, maxConcurrentMCPChainHopProbes)
		var wg sync.WaitGroup
		for i, target := range targets {
			i, target := i, target
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				var res control.OutboundProbeResult
				if !target.outbound.Enabled {
					res = control.OutboundProbeResult{OK: false, Error: "outbound is disabled"}
				} else {
					res = control.ProbeOutbound(ctx, target.outbound.NodeUUID, target.outbound.Core, target.tag, 9*time.Second)
				}
				results[i] = gin.H{
					"node_uuid":   target.outbound.NodeUUID,
					"outbound_id": target.outbound.ID,
					"tag":         target.tag,
					"ok":          res.OK,
					"latency_ms":  res.LatencyMS,
					"status_code": res.StatusCode,
					"error":       res.Error,
				}
			}()
		}
		wg.Wait()
		passed := 0
		var minLatency int64
		nodeAnyOK := map[string]bool{}
		for _, r := range results {
			nodeUUID, _ := r["node_uuid"].(string)
			if _, seen := nodeAnyOK[nodeUUID]; !seen {
				nodeAnyOK[nodeUUID] = false
			}
			if ok, _ := r["ok"].(bool); ok {
				passed++
				nodeAnyOK[nodeUUID] = true
				if lat, _ := r["latency_ms"].(int64); lat > 0 && (minLatency == 0 || lat < minLatency) {
					minLatency = lat
				}
			}
		}
		overallOK := len(results) > 0 && passed == len(results)
		strategy := strings.ToLower(strings.TrimSpace(view.Strategy))
		if strategy == "failover" || strategy == "urltest" {
			overallOK = len(nodeAnyOK) > 0
			for _, ok := range nodeAnyOK {
				if !ok {
					overallOK = false
					break
				}
			}
		}
		return gin.H{
			"ok":             overallOK,
			"chain_id":       view.ID,
			"passed_count":   passed,
			"total_count":    len(results),
			"min_latency_ms": minLatency,
			"results":        results,
		}, nil
	default:
		return nil, errTool("action must be list, upsert, delete, or test")
	}
}

func mcpNodemgtUsers(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	if err := mcpRequireAllNodes(lease); err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		rows, err := st.ListUserViews(strings.TrimSpace(stringArg(args, "node_uuid")))
		if err != nil {
			return nil, err
		}
		return gin.H{"users": rows}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.NodeUser
		if id != "" {
			existing, err := st.GetUser(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "node_uuid")); v != "" {
			row.NodeUUID = v
		}
		if v := strings.TrimSpace(stringArg(args, "username")); v != "" {
			row.Username = v
		}
		if v := strings.TrimSpace(stringArg(args, "display_name")); v != "" {
			row.DisplayName = v
		}
		if v := strings.TrimSpace(stringArg(args, "status")); v != "" {
			row.Status = v
		} else if id == "" {
			row.Status = nmmodels.UserActive
		}
		if _, ok := args["quota_bytes"]; ok {
			row.QuotaBytes = int64Arg(args, "quota_bytes")
		}
		if _, ok := args["rate_limit_bps"]; ok {
			row.RateLimitBps = int64Arg(args, "rate_limit_bps")
		}
		if _, ok := args["device_limit"]; ok {
			row.DeviceLimit = int(int64Arg(args, "device_limit"))
		}
		if err := st.UpsertUser(&row); err != nil {
			return nil, errTool(err.Error())
		}
		nodes, _ := st.NodeUUIDsForUser(row.ID)
		if row.NodeUUID != "" {
			nodes = append(nodes, row.NodeUUID)
		}
		seenNodes := map[string]struct{}{}
		for _, n := range nodes {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, ok := seenNodes[n]; ok {
				continue
			}
			seenNodes[n] = struct{}{}
			_, _ = mcpPushNodeConfig(st, n)
		}
		mcpNodemgtAudit(c, lease, "user.upsert", row.Username, row.ID)
		return gin.H{"user": row}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetUser(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		nodes, _ := st.NodeUUIDsForUser(id)
		if existing.NodeUUID != "" {
			nodes = append(nodes, existing.NodeUUID)
		}
		if err := st.DeleteUser(id); err != nil {
			return nil, errTool(err.Error())
		}
		seenNodes := map[string]struct{}{}
		for _, n := range nodes {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, ok := seenNodes[n]; ok {
				continue
			}
			seenNodes[n] = struct{}{}
			_, _ = mcpPushNodeConfig(st, n)
		}
		mcpNodemgtAudit(c, lease, "user.delete", existing.Username, id)
		return gin.H{"deleted": true, "id": id}, nil
	case "set_status":
		id := strings.TrimSpace(stringArg(args, "id"))
		status := strings.TrimSpace(stringArg(args, "status"))
		if id == "" || status == "" {
			return nil, errTool("id and status are required")
		}
		if status == nmmodels.UserDisabled {
			if err := ops.New(st).Disable(mcpNodemgtActor(lease), id, ""); err != nil {
				return nil, errTool(err.Error())
			}
		} else if err := st.SetUserStatus(id, status); err != nil {
			return nil, errTool(err.Error())
		} else {
			nodes, _ := st.NodeUUIDsForUser(id)
			for _, n := range nodes {
				_, _ = mcpPushNodeConfig(st, n)
			}
		}
		existing, err := st.GetUser(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "user.set_status", existing.Username, status)
		return gin.H{"user": existing}, nil
	case "clear_ips":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		if _, err := st.GetUser(id); err != nil {
			return nil, errTool(err.Error())
		}
		if err := st.ClearUserIPs(id); err != nil {
			return nil, errTool(err.Error())
		}
		nodes, _ := st.NodeUUIDsForUser(id)
		if len(nodes) > 0 {
			payload, _ := json.Marshal(map[string]any{"user_ids": []string{id}})
			for _, nodeUUID := range nodes {
				nodeUUID = strings.TrimSpace(nodeUUID)
				if nodeUUID == "" {
					continue
				}
				cmd := &nmmodels.ControlCommand{
					NodeUUID:    nodeUUID,
					Kind:        "clearUserIPs",
					PayloadJSON: string(payload),
					Status:      nmmodels.CmdPending,
				}
				if err := st.EnqueueCommand(cmd); err == nil {
					_ = control.PushPending(st, nodeUUID)
				}
			}
		}
		mcpNodemgtAudit(c, lease, "user.clear_ips", id, "")
		return gin.H{"cleared": true, "id": id}, nil
	default:
		return nil, errTool("action must be list, upsert, delete, set_status, or clear_ips")
	}
}

func mcpNodemgtPlans(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	if err := mcpRequireAllNodes(lease); err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		rows, err := st.ListPlans()
		if err != nil {
			return nil, err
		}
		return gin.H{"plans": rows}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.Plan
		if id != "" {
			existing, err := st.GetPlan(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "name")); v != "" {
			row.Name = v
		}
		if _, ok := args["traffic_bytes"]; ok {
			row.TrafficBytes = int64Arg(args, "traffic_bytes")
		}
		if _, ok := args["duration_days"]; ok {
			row.DurationDays = int(int64Arg(args, "duration_days"))
		}
		if _, ok := args["rate_limit_bps"]; ok {
			row.RateLimitBps = int64Arg(args, "rate_limit_bps")
		}
		if _, ok := args["device_limit"]; ok {
			row.DeviceLimit = int(int64Arg(args, "device_limit"))
		}
		if err := st.UpsertPlan(&row); err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "plan.upsert", row.Name, row.ID)
		return gin.H{"plan": row}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		if err := st.DeletePlan(id); err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "plan.delete", id, "")
		return gin.H{"deleted": true, "id": id}, nil
	default:
		return nil, errTool("action must be list, upsert, or delete")
	}
}

func mcpNodemgtSubscriptions(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	if err := mcpRequireAllNodes(lease); err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		rows, err := st.ListSubscriptions()
		if err != nil {
			return nil, err
		}
		out := make([]nmmodels.Subscription, 0, len(rows))
		for _, row := range rows {
			out = append(out, redactMCPSubscription(row))
		}
		return gin.H{"subscriptions": out}, nil
	case "upsert":
		id := strings.TrimSpace(stringArg(args, "id"))
		var row nmmodels.Subscription
		if id != "" {
			existing, err := st.GetSubscription(id)
			if err != nil {
				return nil, errTool(err.Error())
			}
			row = *existing
		}
		if v := strings.TrimSpace(stringArg(args, "user_id")); v != "" {
			row.UserID = v
		}
		if v := strings.TrimSpace(stringArg(args, "format")); v != "" {
			row.Format = v
		}
		if b := boolPtrArg(args, "auto_detect"); b != nil {
			row.AutoDetect = *b
		}
		if b := boolPtrArg(args, "enabled"); b != nil {
			row.Enabled = *b
		} else if id == "" {
			row.Enabled = true
		}
		if err := st.UpsertSubscription(&row); err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "subscription.upsert", row.UserID, row.ID)
		return gin.H{"subscription": redactMCPSubscription(row)}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		if err := st.DeleteSubscription(id); err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "subscription.delete", id, "")
		return gin.H{"deleted": true, "id": id}, nil
	default:
		return nil, errTool("action must be list, upsert, or delete")
	}
}

func mcpNodemgtCerts(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	switch action {
	case "list":
		nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
		if nodeUUID != "" {
			if err := mcpRequireNode(lease, nodeUUID); err != nil {
				return nil, err
			}
		}
		rows, err := st.ListCerts(nodeUUID)
		if err != nil {
			return nil, err
		}
		allowed := mcpAuthorizedNodeSet(lease)
		out := make([]nmmodels.Certificate, 0, len(rows))
		for _, row := range rows {
			if mcpNodeAllowed(lease, allowed, row.NodeUUID) {
				out = append(out, redactMCPCert(row))
			}
		}
		return gin.H{"certs": out}, nil
	case "delete":
		id := strings.TrimSpace(stringArg(args, "id"))
		if id == "" {
			return nil, errTool("id is required")
		}
		existing, err := st.GetCert(id)
		if err != nil {
			return nil, errTool(err.Error())
		}
		if err := mcpRequireNode(lease, existing.NodeUUID); err != nil {
			return nil, err
		}
		if err := st.DeleteCert(id); err != nil {
			return nil, errTool(err.Error())
		}
		mcpNodemgtAudit(c, lease, "cert.delete", existing.Domain, existing.NodeUUID)
		return gin.H{"deleted": true, "id": id}, nil
	default:
		return nil, errTool("action must be list or delete")
	}
}

func mcpNodemgtSync(c *gin.Context, lease models.MCPLease, st *store.Store, args map[string]any) (any, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	if action == "" {
		action = "sync"
	}
	nodeUUID := strings.TrimSpace(stringArg(args, "node_uuid"))
	if nodeUUID != "" {
		if err := mcpRequireNode(lease, nodeUUID); err != nil {
			return nil, err
		}
	}
	if action == "sync" {
		if nodeUUID != "" {
			opID, err := mcpPushNodeConfig(st, nodeUUID)
			if err != nil {
				return nil, errTool(err.Error())
			}
			mcpNodemgtAudit(c, lease, "control.sync", nodeUUID, opID)
			return gin.H{"synced": []string{nodeUUID}, "operation_id": opID}, nil
		}
		allowed := mcpAuthorizedNodeSet(lease)
		inbounds, err := st.ListInbounds("")
		if err != nil {
			return nil, err
		}
		nodeSet := map[string]struct{}{}
		for _, in := range inbounds {
			if mcpNodeAllowed(lease, allowed, in.NodeUUID) {
				nodeSet[in.NodeUUID] = struct{}{}
			}
		}
		synced := make([]string, 0, len(nodeSet))
		for n := range nodeSet {
			if _, err := mcpPushNodeConfig(st, n); err == nil {
				synced = append(synced, n)
			}
		}
		mcpNodemgtAudit(c, lease, "control.sync", "authorized", "")
		return gin.H{"synced": synced}, nil
	}
	if action == "status" {
		cmds, err := st.LatestCommands()
		if err != nil {
			return nil, err
		}
		allowed := mcpAuthorizedNodeSet(lease)
		out := make([]nmmodels.ControlCommand, 0, len(cmds))
		for _, cmd := range cmds {
			if (nodeUUID == "" || cmd.NodeUUID == nodeUUID) && mcpNodeAllowed(lease, allowed, cmd.NodeUUID) {
				out = append(out, cmd)
			}
		}
		return gin.H{"delivery": redactMCPDelivery(out)}, nil
	}
	return nil, errTool("action must be sync or status")
}
