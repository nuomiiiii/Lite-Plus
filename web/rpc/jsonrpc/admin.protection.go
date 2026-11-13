package jsonrpc

import (
	"context"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/database/auditlog"
	protstore "github.com/nuomiiiii/lite/database/protection"
	"github.com/nuomiiiii/lite/pkg/rpc"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/web/api/remote"
	"github.com/nuomiiiii/lite/web/protection"
)

func init() {
	reg("getProtection", adminGetProtection, "Get per-node service protection state")
	reg("precheckProtection", adminPrecheckProtection, "Precheck nftables protection upgrade")
	reg("upgradeProtection", adminUpgradeProtection, "Install or enable nftables protection runtime")
	reg("saveProtection", adminSaveProtection, "Save service protection config")
	reg("previewProtection", adminPreviewProtection, "Preview parsed access log fields")
	reg("unbanProtection", adminUnbanProtection, "Unban an IP locally or in a group")
	reg("listProtectionGroups", adminListProtectionGroups, "List protection groups")
	reg("saveProtectionGroup", adminSaveProtectionGroup, "Create or update a protection group")
	reg("deleteProtectionGroup", adminDeleteProtectionGroup, "Delete a protection group")
}

func adminGetProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
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
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return view, nil
}

func adminPrecheckProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
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
	if reason := protection.UnavailableReason(client); reason != "" {
		view, _ := protection.View(client)
		return view, nil
	}
	result, got, err := protection.DispatchPrecheck(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if got && result.Capability != nil {
		_ = protstore.SaveCapability(client.UUID, *result.Capability)
	}
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if got {
		view["precheck"] = result
	}
	return view, nil
}

func adminUpgradeProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
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
	if err := protection.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.protection_upgrade", map[string]string{"name": client.Name})
	_, _, _, err := protection.StartUpgrade(client.UUID)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func adminSaveProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID   string              `json:"uuid"`
		Grant  string              `json:"grant"`
		PageID string              `json:"page_id"`
		Config v2.ProtectionConfig `json:"config"`
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
	if err := protection.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	if _, err := protection.NormalizeConfig(params.Config); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if _, err := protection.SaveConfig(client.UUID, params.Config); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.protection_save", map[string]string{"name": client.Name})
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func adminPreviewProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID     string `json:"uuid"`
		Grant    string `json:"grant"`
		PageID   string `json:"page_id"`
		SourceID string `json:"source_id"`
		Path     string `json:"path"`
		Format   string `json:"format"`
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
	if err := protection.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	result, got, err := protection.DispatchPreview(client.UUID, v2.ProtectionPreviewParams{
		SourceID: params.SourceID,
		Path:     params.Path,
		Format:   params.Format,
	})
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if got {
		view["preview"] = result.Preview
		if result.Error != "" {
			view["preview_error"] = result.Error
		}
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func adminUnbanProtection(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID    string `json:"uuid"`
		Grant   string `json:"grant"`
		PageID  string `json:"page_id"`
		IP      string `json:"ip"`
		GroupID string `json:"group_id"`
		Local   bool   `json:"local"`
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
	if err := protection.EnsureApplyAllowed(client.UUID); err != nil {
		return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if err := protection.Unban(client.UUID, params.IP, params.GroupID, params.Local); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.protection_unban", map[string]string{"name": client.Name})
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, params.PageID, expires, grantEpoch, view), nil
}

func adminListProtectionGroups(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := denyAPIKey(ctx); err != nil {
		return nil, err
	}
	if !remote.RemoteManagementEnabled() {
		return nil, rpc.MakeError(rpc.PermissionDenied, "站点未启用远程管理", nil)
	}
	groups, err := protstore.ListGroups()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return map[string]any{"groups": groups}, nil
}

func adminSaveProtectionGroup(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID    string   `json:"uuid"`
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Enabled *bool    `json:"enabled"`
		Members []string `json:"members"`
		Grant   string   `json:"grant"`
		PageID  string   `json:"page_id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var err error
	if strings.TrimSpace(params.ID) == "" {
		_, err = protection.CreateGroup(params.Name, params.Members)
	} else {
		enabled := true
		if params.Enabled != nil {
			enabled = *params.Enabled
		}
		_, err = protection.UpdateGroup(params.ID, params.Name, enabled, params.Members)
	}
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.protection_group", map[string]string{"name": params.Name})
	return protectionGrantedView(meta, params.UUID, params.PageID, expires, grantEpoch)
}

func adminDeleteProtectionGroup(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	meta, rpcErr := scheduledExecActor(ctx)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var params struct {
		UUID   string `json:"uuid"`
		ID     string `json:"id"`
		Grant  string `json:"grant"`
		PageID string `json:"page_id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	expires, grantEpoch, rpcErr := consumeScheduledExecGrant(meta, params.Grant, params.PageID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	group, err := protstore.GetGroup(params.ID)
	if err != nil || group == nil {
		return nil, rpc.MakeError(rpc.NotFound, "联动组不存在", nil)
	}
	if _, err := protection.UpdateGroup(params.ID, group.Name, false, nil); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	if err := protstore.DeleteGroup(params.ID); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Event(ip, actor, "info", "audit.protection_group_delete", map[string]string{"name": group.Name})
	return protectionGrantedView(meta, params.UUID, params.PageID, expires, grantEpoch)
}

func protectionGrantedView(meta *rpc.ContextMeta, uuid, pageID string, expires time.Time, epoch uint64) (any, *rpc.JsonRpcError) {
	if strings.TrimSpace(uuid) == "" {
		groups, _ := protstore.ListGroups()
		return grantPayload(meta.Principal.UserUUID, meta.SessionToken, pageID, expires, epoch, map[string]any{"groups": groups}), nil
	}
	client, rpcErr := loadFirewallClient(uuid)
	if rpcErr != nil {
		return nil, rpcErr
	}
	view, err := protection.View(client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return grantPayload(meta.Principal.UserUUID, meta.SessionToken, pageID, expires, epoch, view), nil
}
