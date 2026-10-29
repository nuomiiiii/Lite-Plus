package jsonrpc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/database/auditlog"
	"github.com/nuomiiiii/lite/database/clients"
	fwstore "github.com/nuomiiiii/lite/database/firewall"
	"github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/pkg/rpc"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/web/api/remote"
	"github.com/nuomiiiii/lite/web/firewall"
)

func init() {
	reg("getFirewall", adminGetFirewall, "Get per-node firewall intent")
	reg("saveFirewall", adminSaveFirewall, "Save and apply per-node firewall intent")
	reg("snapshotFirewall", adminSnapshotFirewall, "Scan host firewall rules")
	reg("adoptFirewall", adminAdoptFirewall, "Adopt host firewall rules into Plus")
	reg("installFirewall", adminInstallFirewall, "Install nftables on a node with no host firewall")
}

type firewallSaveBody struct {
	UUID         string            `json:"uuid"`
	BlockPing4   bool              `json:"block_ping_v4"`
	BlockPing6   bool              `json:"block_ping_v6"`
	DefaultDeny4 bool              `json:"default_deny_v4"`
	DefaultDeny6 bool              `json:"default_deny_v6"`
	SshPort      string            `json:"ssh_port"`
	OmitKeep     []string          `json:"omit_keep"`
	Rules        []v2.FirewallRule `json:"rules"`
	Grant        string            `json:"grant"`
	PageID       string            `json:"page_id"`
}

func adminGetFirewall(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := denyAPIKey(ctx); err != nil {
		return nil, err
	}
	if !remote.RemoteManagementEnabled() {
		return nil, rpc.MakeError(rpc.PermissionDenied, "站点未启用远程管理", nil)
	}
	var params struct {
		UUID string `json:"uuid"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, rpcErr := loadFirewallClient(params.UUID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	row, err := fwstore.EnsureRow(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	row = reconcileOrphanInbound(client.UUID, row)
	return firewallView(client, row, fwstore.SnapshotFromRow(row), false), nil
}

func adminSnapshotFirewall(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := denyAPIKey(ctx); err != nil {
		return nil, err
	}
	if !remote.RemoteManagementEnabled() {
		return nil, rpc.MakeError(rpc.PermissionDenied, "站点未启用远程管理", nil)
	}
	var params struct {
		UUID string `json:"uuid"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, rpcErr := loadFirewallClient(params.UUID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	row, err := fwstore.EnsureRow(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if reason := firewall.UnavailableReason(client); reason != "" {
		return firewallView(client, row, fwstore.SnapshotFromRow(row), false), nil
	}
	result, got, err := firewall.DispatchSnapshot(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if got {
		_ = firewall.SaveCleanSnapshot(client.UUID, result)
		row, _ = fwstore.Get(client.UUID)
		return firewallView(client, row, &result, true), nil
	}
	return firewallView(client, row, fwstore.SnapshotFromRow(row), false), nil
}

func adminSaveFirewall(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params firewallSaveBody
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, rpcErr := loadFirewallClient(params.UUID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if err := remote.AgentRemoteAllowed(client); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	if err := firewall.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	intent, err := firewall.NormalizeIntent(v2.FirewallIntent{
		BlockPing4:   params.BlockPing4,
		BlockPing6:   params.BlockPing6,
		DefaultDeny4: params.DefaultDeny4,
		DefaultDeny6: params.DefaultDeny6,
		SshPort:      params.SshPort,
		OmitKeep:     params.OmitKeep,
		Rules:        params.Rules,
	})
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if live, ok := liveInboundIDs(client.UUID); ok {
		intent.Rules = firewall.DropOrphanInboundRules(intent.Rules, live)
	}
	row, err := fwstore.Get(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	prevSSH := ""
	if row != nil {
		prevSSH = strings.TrimSpace(row.SshPort)
	}
	if err := firewall.GuardDefaultDeny(client.UUID, fwstore.IntentFromRow(row), intent); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	saved, err := fwstore.SaveIntent(client.UUID, intent)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.firewall_save", map[string]string{"name": client.Name})
	applied := fwstore.IntentFromRow(saved)
	result, got := firewall.DispatchApply(client.UUID, applied, firewall.ListenHoles(client.UUID, applied))
	if got && result.Status != v2.FirewallStatusOK && strings.TrimSpace(intent.SshPort) != prevSSH {
		_ = fwstore.RevertSshPort(client.UUID, prevSSH)
	}
	if got {
		_ = firewall.SaveCleanSnapshot(client.UUID, result)
	}
	saved, _ = fwstore.Get(client.UUID)
	snap := fwstore.SnapshotFromRow(saved)
	if got {
		snap = &result
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, firewallView(client, saved, snap, got)), nil
}

func adminAdoptFirewall(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID           string   `json:"uuid"`
		Keys           []string `json:"keys"`
		DisableOriginal bool    `json:"disable_original"`
		Grant          string   `json:"grant"`
		PageID         string   `json:"page_id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, rpcErr := loadFirewallClient(params.UUID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if err := remote.AgentRemoteAllowed(client); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	if err := firewall.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	row, err := fwstore.EnsureRow(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	snap := fwstore.SnapshotFromRow(row)
	if snap == nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "host rules are not loaded", nil)
	}
	snap.HostRules = firewall.DropOwnedHostNoise(snap.HostRules)
	intent := fwstore.IntentFromRow(row)
	wanted := map[string]struct{}{}
	for _, key := range params.Keys {
		key = strings.TrimSpace(key)
		if key != "" {
			wanted[key] = struct{}{}
		}
	}
	priority := 100
	for _, rule := range intent.Rules {
		if rule.Priority >= priority {
			priority = rule.Priority + 1
		}
	}
	adopted := 0
	for _, host := range snap.HostRules {
		if _, ok := wanted[host.Key]; !ok || !host.Adoptable {
			continue
		}
		rule, err := firewall.NormalizeRule(v2.FirewallRule{
			Enabled:  true,
			Action:   host.Action,
			Protocol: host.Protocol,
			Port:     host.Port,
			Source:   host.Source,
			Stack:    host.Stack,
			Comment:  host.Comment,
			Origin:   v2.FirewallOriginImported,
			Priority: priority,
			HostKey:  host.Key,
		})
		if err != nil {
			continue
		}
		intent.Rules = append(intent.Rules, rule)
		priority++
		adopted++
	}
	if adopted == 0 {
		return nil, rpc.MakeError(rpc.InvalidParams, "no adoptable rules selected", nil)
	}
	intent, err = firewall.NormalizeIntent(intent)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	saved, err := fwstore.SaveIntent(client.UUID, intent)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.firewall_adopt", map[string]string{"name": client.Name})
	applied := fwstore.IntentFromRow(saved)
	result, got := firewall.DispatchApply(client.UUID, applied, firewall.ListenHoles(client.UUID, applied))
	appliedOK := got && result.Status == v2.FirewallStatusOK
	disableOriginal := ""
	disableOriginalError := ""
	if params.DisableOriginal && appliedOK && len(params.Keys) > 0 {
		adoptResult, adoptGot := firewall.DispatchAdopt(client.UUID, params.Keys)
		switch {
		case !adoptGot:
			disableOriginal = "timeout"
		case adoptResult.Status != "" && adoptResult.Status != v2.FirewallStatusOK:
			disableOriginal = "failed"
			disableOriginalError = strings.TrimSpace(adoptResult.Error)
			result = adoptResult
			got = true
		default:
			result = adoptResult
			got = true
		}
	}
	if got {
		_ = firewall.SaveCleanSnapshot(client.UUID, result)
	}
	saved, _ = fwstore.Get(client.UUID)
	outSnap := fwstore.SnapshotFromRow(saved)
	if got {
		outSnap = &result
	}
	view := firewallView(client, saved, outSnap, got)
	if disableOriginal != "" {
		view["disable_original"] = disableOriginal
		if disableOriginalError != "" {
			view["disable_original_error"] = disableOriginalError
		}
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func adminInstallFirewall(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID   string `json:"uuid"`
		Grant  string `json:"grant"`
		PageID string `json:"page_id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, rpcErr := loadFirewallClient(params.UUID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if err := remote.AgentRemoteAllowed(client); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	if err := firewall.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.firewall_install", map[string]string{"name": client.Name})
	result, got, err := firewall.DispatchInstall(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	row, _ := fwstore.Get(client.UUID)
	snap := fwstore.SnapshotFromRow(row)
	if got {
		_ = firewall.SaveCleanSnapshot(client.UUID, result)
		snap = &result
	}
	view := firewallView(client, row, snap, got)
	if got && result.Status != "" && result.Status != v2.FirewallStatusOK {
		view["delivery_status"] = "failed"
		view["delivery_error"] = strings.TrimSpace(result.Error)
	}
	if !got {
		view["delivery_status"] = "queued"
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func liveInboundIDs(nodeUUID string) (map[string]struct{}, bool) {
	list, err := nodemgtST().ListInbounds(nodeUUID)
	if err != nil {
		return nil, false
	}
	out := make(map[string]struct{}, len(list))
	for _, in := range list {
		if id := strings.TrimSpace(in.ID); id != "" {
			out[id] = struct{}{}
		}
	}
	return out, true
}

func reconcileOrphanInbound(nodeUUID string, row *models.ClientFirewallIntent) *models.ClientFirewallIntent {
	if row == nil {
		return row
	}
	live, ok := liveInboundIDs(nodeUUID)
	if !ok {
		return row
	}
	intent := fwstore.IntentFromRow(row)
	cleaned := firewall.DropOrphanInboundRules(intent.Rules, live)
	if len(cleaned) == len(intent.Rules) {
		return row
	}
	intent.Rules = cleaned
	saved, err := fwstore.SaveIntent(nodeUUID, intent)
	if err != nil {
		return row
	}
	applied := fwstore.IntentFromRow(saved)
	result, got := firewall.DispatchApply(nodeUUID, applied, firewall.ListenHoles(nodeUUID, applied))
	if got {
		_ = firewall.SaveCleanSnapshot(nodeUUID, result)
		if next, err := fwstore.Get(nodeUUID); err == nil && next != nil {
			return next
		}
	}
	return saved
}

func loadFirewallClient(uuid string) (models.Client, *rpc.JsonRpcError) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return models.Client{}, rpc.MakeError(rpc.InvalidParams, "uuid required", nil)
	}
	client, err := clients.GetClientByUUID(uuid)
	if err != nil {
		return models.Client{}, rpc.MakeError(rpc.NotFound, "client not found", nil)
	}
	return client, nil
}

func firewallView(client models.Client, row *models.ClientFirewallIntent, snap *v2.FirewallResultParams, live bool) map[string]any {
	blocked := snap != nil && (snap.DefaultDenyBlocked || firewall.DefaultDenyConflict(snap.Backend, snap.OuterManagers))
	intent := firewall.ApplyDefaultDenyView(fwstore.IntentFromRow(row), row != nil && row.Revision > 0, blocked)
	keep := []v2.FirewallRule{}
	stackV4, stackV6 := true, true
	if snap != nil {
		keep = append(keep, snap.KeepRules...)
		if snap.HasStacks {
			stackV4, stackV6 = snap.StackV4, snap.StackV6
		}
	}
	status := ""
	errText := ""
	applied := uint64(0)
	var snapshotAt *time.Time
	if row != nil {
		status = row.DeliveryStatus
		errText = row.DeliveryError
		applied = row.AppliedRevision
		snapshotAt = row.SnapshotAt
	}
	appliedLive := row != nil && status == fwstore.DeliveryApplied && applied >= row.Revision
	snapPort := ""
	if snap != nil {
		snapPort = snap.SshPort
	}
	sshPort := firewall.DisplaySshPort(intent.SshPort, snapPort, appliedLive)
	keep = firewall.RewriteKeepSSH(keep, sshPort, stackV4, stackV6)
	keep = firewall.DropOmittedKeep(keep, intent.OmitKeep)
	intent = firewall.AttachKeepRules(intent, keep)
	out := map[string]any{
		"uuid":             client.UUID,
		"name":             client.Name,
		"intent":           intent,
		"delivery_status":  status,
		"delivery_error":   errText,
		"applied_revision": applied,
		"live":             live,
		"supported":        firewall.NodeSupports(client),
		"unavailable":      firewall.UnavailableReason(client),
		"online":           false,
	}
	if snapshotAt != nil {
		out["snapshot_at"] = snapshotAt.UTC()
	}
	if snap != nil {
		raw, _ := json.Marshal(snap)
		var cloned v2.FirewallResultParams
		_ = json.Unmarshal(raw, &cloned)
		cloned.KeepRules = keep
		cloned.HostRules = firewall.DropOwnedHostNoise(cloned.HostRules)
		if sshPort != "" {
			cloned.SshPort = sshPort
		}
		out["snapshot"] = cloned
	}
	return out
}
