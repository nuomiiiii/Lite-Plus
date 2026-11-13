package protection

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/database/clients"
	"github.com/nuomiiiii/lite/database/models"
	protstore "github.com/nuomiiiii/lite/database/protection"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/utils"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
	"github.com/nuomiiiii/lite/web/api/remote"
	"github.com/nuomiiiii/lite/web/firewall"
)

const (
	precheckWait   = 60 * time.Second
	upgradeWait    = 4 * time.Minute
	applyWait      = 60 * time.Second
	previewWait    = 20 * time.Second
	applyRetrySkew = 10 * time.Second
)

var errQueueFull = errors.New("远程事件队列已满，请稍后重试")

type pendingWaiter struct {
	ch chan v2.ProtectionResultParams
}

var (
	waitMu  sync.Mutex
	waiters = map[string]*pendingWaiter{}
)

func newRequestID() string {
	id := utils.GenerateRandomString(16)
	if id == "" {
		return time.Now().UTC().Format("150405.000000")
	}
	return id
}

func startWait(requestID string) {
	waitMu.Lock()
	waiters[requestID] = &pendingWaiter{ch: make(chan v2.ProtectionResultParams, 1)}
	waitMu.Unlock()
}

func stopWait(requestID string) {
	waitMu.Lock()
	delete(waiters, requestID)
	waitMu.Unlock()
}

func waitFor(requestID string, timeout time.Duration) (v2.ProtectionResultParams, bool) {
	waitMu.Lock()
	waiter := waiters[requestID]
	waitMu.Unlock()
	if waiter == nil {
		return v2.ProtectionResultParams{}, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-waiter.ch:
		return result, true
	case <-timer.C:
		return v2.ProtectionResultParams{}, false
	}
}

func CompleteResult(uuid string, result v2.ProtectionResultParams) {
	if result.Capability != nil {
		_ = protstore.SaveCapability(uuid, *result.Capability)
		if result.Capability.RuntimeReady && result.Capability.RuntimeEnabled {
			_ = protstore.MarkRuntimeWanted(uuid, true)
		}
	}
	switch result.Kind {
	case v2.ProtectionKindApplyConfig:
		status := protstore.DeliveryApplied
		if result.Status != v2.ProtectionStatusOK {
			status = protstore.DeliveryFailed
			if result.Status == v2.ProtectionStatusUnsupported {
				status = protstore.DeliveryUnsupported
			}
		}
		_ = protstore.MarkDelivery(uuid, status, result.Error, result.Revision)
		if len(result.SourceStats) > 0 {
			_ = protstore.SaveReport(uuid, v2.ProtectionReportParams{SourceStats: result.SourceStats, ConfigRev: result.Revision})
		}
	case v2.ProtectionKindUpgrade:
		finishUpgrade(uuid, result)
	case v2.ProtectionKindBan, v2.ProtectionKindUnban, v2.ProtectionKindGroupSnapshot:
		if result.GroupID != "" {
			status := protstore.DeliveryApplied
			if result.Status != v2.ProtectionStatusOK {
				status = protstore.DeliveryFailed
			}
			_ = protstore.MarkMember(result.GroupID, uuid, status, result.Error, result.GroupRevision)
			if result.Kind == v2.ProtectionKindGroupSnapshot {
				if result.Status == v2.ProtectionStatusOK {
					_ = protstore.ClearLeave(result.GroupID, uuid)
				} else {
					_ = protstore.MarkLeave(result.GroupID, uuid, protstore.DeliveryFailed, result.Error)
				}
			}
		}
	}
	waitMu.Lock()
	waiter := waiters[result.RequestID]
	waitMu.Unlock()
	if waiter != nil {
		select {
		case waiter.ch <- result:
		default:
		}
	}
}

func CompleteReport(uuid string, report v2.ProtectionReportParams) {
	if report.Capability != nil {
		_ = protstore.SaveCapability(uuid, *report.Capability)
	}
	_ = protstore.SaveReport(uuid, report)
	if strings.TrimSpace(report.Error) != "" {
		return
	}
	cfgRow, _ := protstore.GetConfig(uuid)
	cfg := protstore.ConfigFromRow(cfgRow)
	if report.ConfigRev > 0 && cfg.Revision > 0 && report.ConfigRev < cfg.Revision {
		return
	}
	for _, hit := range report.Executions {
		_ = ingestLocalHit(uuid, hit, report)
	}
}

func NodeSupports(client models.Client) bool {
	return client.RemoteProtocol == 2 && client.RemoteControlEnabled && client.ServiceProtection && client.ServiceProtectionVersion >= v2.ServiceProtectionVersion
}

func UnavailableReason(client models.Client) string {
	if client.RemoteProtocol != 2 {
		return "agent_old"
	}
	if !client.RemoteControlEnabled {
		return "remote_off"
	}
	if !client.ServiceProtection || client.ServiceProtectionVersion < v2.ServiceProtectionVersion {
		return "agent_old"
	}
	return ""
}

func EnsureApplyAllowed(uuid string) error {
	if err := firewall.EnsureApplyAllowed(uuid); err != nil {
		return err
	}
	client, err := clients.GetClientByUUID(uuid)
	if err != nil {
		return err
	}
	if !NodeSupports(client) {
		return errors.New("当前 Agent 不支持服务防护，请先升级 Agent")
	}
	return nil
}

func DispatchPrecheck(uuid string) (v2.ProtectionResultParams, bool, error) {
	id := newRequestID()
	startWait(id)
	defer stopWait(id)
	if err := send(uuid, v2.MethodAgentProtectionPrecheck, v2.ProtectionRequest{RequestID: id}); err != nil {
		return v2.ProtectionResultParams{}, false, err
	}
	result, got := waitFor(id, precheckWait)
	return result, got, nil
}

func DispatchUpgrade(uuid, opID string) (v2.ProtectionResultParams, bool, error) {
	id := newRequestID()
	startWait(id)
	defer stopWait(id)
	if err := send(uuid, v2.MethodAgentProtectionUpgrade, v2.ProtectionUpgradeParams{RequestID: id, OpID: opID}); err != nil {
		return v2.ProtectionResultParams{}, false, err
	}
	result, got := waitFor(id, upgradeWait)
	return result, got, nil
}

func DispatchApply(uuid string, cfg v2.ProtectionConfig, wait bool) error {
	id := newRequestID()
	if wait {
		startWait(id)
		defer stopWait(id)
	}
	if err := send(uuid, v2.MethodAgentProtectionApplyConfig, v2.ProtectionApplyConfigParams{RequestID: id, Config: cfg}); err != nil {
		return err
	}
	if wait {
		_, _ = waitFor(id, applyWait)
	}
	return nil
}

func DispatchPreview(uuid string, params v2.ProtectionPreviewParams) (v2.ProtectionResultParams, bool, error) {
	params.RequestID = newRequestID()
	startWait(params.RequestID)
	defer stopWait(params.RequestID)
	if err := send(uuid, v2.MethodAgentProtectionPreview, params); err != nil {
		return v2.ProtectionResultParams{}, false, err
	}
	result, got := waitFor(params.RequestID, previewWait)
	return result, got, nil
}

func DispatchBan(uuid string, reason v2.ProtectionBanReason, observed uint64) error {
	id := newRequestID()
	err := send(uuid, v2.MethodAgentProtectionBan, v2.ProtectionBanParams{RequestID: id, Reason: reason, ObservedRevision: observed})
	if err == errQueueFull && reason.GroupID != "" {
		return dispatchGroupSnapshotFallback(uuid, reason.GroupID)
	}
	return err
}

func DispatchUnban(uuid string, params v2.ProtectionUnbanParams) error {
	params.RequestID = newRequestID()
	err := send(uuid, v2.MethodAgentProtectionUnban, params)
	if err == errQueueFull && params.GroupID != "" {
		return dispatchGroupSnapshotFallback(uuid, params.GroupID)
	}
	return err
}

func DispatchGroupSnapshot(uuid string, snap v2.ProtectionGroupSnapshot) error {
	id := newRequestID()
	return send(uuid, v2.MethodAgentProtectionGroupSnapshot, v2.ProtectionGroupSnapshotParams{RequestID: id, Snapshot: snap})
}

func dispatchGroupSnapshotFallback(uuid, groupID string) error {
	group, err := protstore.GetGroup(groupID)
	if err != nil || group == nil {
		return errQueueFull
	}
	snap, err := groupSnapshot(group)
	if err != nil {
		return errQueueFull
	}
	return DispatchGroupSnapshot(uuid, snap)
}

func send(uuid, method string, params any) error {
	queued := false
	allowed := agent_runtime.GuardRemoteDelivery(remote.RemoteManagementEnabled, func() {
		queued = agent_runtime.DispatchV2Event(uuid, method, params)
	})
	if !allowed {
		return errors.New("站点未启用远程管理")
	}
	if !queued {
		return errQueueFull
	}
	return nil
}

func SyncOnConnect(uuid string) {
	syncProtection(uuid, true)
}

func PushPending(uuid string) {
	syncProtection(uuid, false)
}

func syncProtection(uuid string, force bool) {
	row, err := protstore.GetConfig(uuid)
	if err != nil || row == nil {
		return
	}
	client, err := clients.GetClientByUUID(uuid)
	if err != nil || !NodeSupports(client) {
		return
	}
	cfg := protstore.ConfigFromRow(row)
	if row.Revision > 0 && (force || needsProtectionApply(*row)) {
		if err := DispatchApply(uuid, cfg, false); err != nil {
			log.Printf("protection sync apply %s: %v", uuid, err)
			status := protstore.DeliveryQueued
			if err == errQueueFull {
				status = protstore.DeliveryFailed
			}
			_ = protstore.MarkDelivery(uuid, status, err.Error(), 0)
		} else {
			_ = protstore.MarkDelivery(uuid, protstore.DeliverySent, "", 0)
		}
	}
	leaves, _ := protstore.ListPendingLeaves(uuid)
	for _, leave := range leaves {
		if !force && !needsLeaveApply(leave) {
			continue
		}
		if err := DispatchGroupSnapshot(uuid, emptyGroupSnapshot(leave.GroupID, leave.Revision)); err != nil {
			log.Printf("protection sync leave %s %s: %v", uuid, leave.GroupID, err)
			markLeaveDelivery(leave.GroupID, uuid, err)
		} else {
			_ = protstore.MarkLeave(leave.GroupID, uuid, protstore.DeliverySent, "")
		}
	}
	members, _ := protstore.ListMemberships(uuid)
	for _, member := range members {
		group, err := protstore.GetGroup(member.GroupID)
		if err != nil || group == nil {
			continue
		}
		if !force && !needsGroupApply(member, group.Revision) {
			continue
		}
		if !group.Enabled {
			if err := DispatchGroupSnapshot(uuid, emptyGroupSnapshot(group.ID, group.Revision)); err != nil {
				log.Printf("protection sync disabled group %s %s: %v", uuid, group.ID, err)
				markGroupDelivery(group.ID, uuid, err)
			} else {
				_ = protstore.MarkMember(group.ID, uuid, protstore.DeliverySent, "", 0)
			}
			continue
		}
		snap, err := groupSnapshot(group)
		if err != nil {
			continue
		}
		if err := DispatchGroupSnapshot(uuid, snap); err != nil {
			log.Printf("protection sync group %s %s: %v", uuid, group.ID, err)
			markGroupDelivery(group.ID, uuid, err)
		} else {
			_ = protstore.MarkMember(group.ID, uuid, protstore.DeliverySent, "", 0)
		}
	}
}

func needsProtectionApply(row models.ClientProtectionConfig) bool {
	if protectionDeliveryWaiting(row) {
		return false
	}
	if row.AppliedRevision < row.Revision {
		return true
	}
	switch row.DeliveryStatus {
	case protstore.DeliveryFailed, protstore.DeliveryPending, "":
		return true
	}
	return false
}

func protectionDeliveryWaiting(row models.ClientProtectionConfig) bool {
	if row.DeliveryUpdatedAt == nil {
		return false
	}
	age := time.Since(*row.DeliveryUpdatedAt)
	switch row.DeliveryStatus {
	case protstore.DeliverySent, protstore.DeliveryQueued:
		return age < applyWait+applyRetrySkew
	case protstore.DeliveryFailed:
		return age < applyWait
	default:
		return false
	}
}

func needsGroupApply(member models.ProtectionGroupMember, revision uint64) bool {
	if groupDeliveryWaiting(member) {
		return false
	}
	if member.AppliedRevision < revision {
		return true
	}
	switch member.DeliveryStatus {
	case protstore.DeliveryFailed, protstore.DeliveryPending, "":
		return true
	}
	return false
}

func groupDeliveryWaiting(member models.ProtectionGroupMember) bool {
	if member.UpdatedAt.IsZero() {
		return false
	}
	age := time.Since(member.UpdatedAt)
	switch member.DeliveryStatus {
	case protstore.DeliverySent, protstore.DeliveryQueued:
		return age < applyWait+applyRetrySkew
	case protstore.DeliveryFailed:
		return age < applyWait
	default:
		return false
	}
}

func markGroupDelivery(groupID, uuid string, err error) {
	status := protstore.DeliveryQueued
	msg := ""
	if err != nil {
		msg = err.Error()
		if err == errQueueFull {
			status = protstore.DeliveryFailed
		}
	}
	_ = protstore.MarkMember(groupID, uuid, status, msg, 0)
}

func needsLeaveApply(leave models.ProtectionGroupLeave) bool {
	return !leaveDeliveryWaiting(leave)
}

func leaveDeliveryWaiting(leave models.ProtectionGroupLeave) bool {
	if leave.DeliveryUpdatedAt == nil {
		return false
	}
	age := time.Since(*leave.DeliveryUpdatedAt)
	switch leave.DeliveryStatus {
	case protstore.DeliverySent, protstore.DeliveryQueued:
		return age < applyWait+applyRetrySkew
	case protstore.DeliveryFailed:
		return age < applyWait
	default:
		return false
	}
}

func markLeaveDelivery(groupID, uuid string, err error) {
	status := protstore.DeliveryQueued
	msg := ""
	if err != nil {
		msg = err.Error()
		if err == errQueueFull {
			status = protstore.DeliveryFailed
		}
	}
	_ = protstore.MarkLeave(groupID, uuid, status, msg)
}

func finishUpgrade(uuid string, result v2.ProtectionResultParams) {
	op, _ := protstore.ActiveUpgradeOp(uuid)
	if op == nil && result.OpID != "" {
		op, _ = protstore.LatestUpgradeOp(uuid)
	}
	if op == nil {
		return
	}
	now := time.Now().UTC()
	op.Phase = result.Phase
	op.Result = result.Status
	op.Error = result.Error
	if result.Phase == v2.ProtectionUpgradePhaseReady || result.Phase == v2.ProtectionUpgradePhaseFailed || result.Status != v2.ProtectionStatusOK {
		op.FinishedAt = &now
	}
	_ = protstore.SaveUpgradeOp(op)
}

func ingestLocalHit(uuid string, hit v2.ProtectionBanReason, report v2.ProtectionReportParams) error {
	ip, ok := v2.NormalizeProtectionIP(hit.IP)
	if !ok {
		return nil
	}
	hit.IP = ip
	hit.SourceNode = uuid
	exp, err := time.Parse(time.RFC3339Nano, hit.ExpiresAt)
	if err != nil {
		exp, err = time.Parse(time.RFC3339, hit.ExpiresAt)
	}
	if err != nil || !exp.After(time.Now().UTC()) {
		return nil
	}
	created, err := time.Parse(time.RFC3339Nano, hit.CreatedAt)
	if err != nil {
		created, _ = time.Parse(time.RFC3339, hit.CreatedAt)
	}
	if created.IsZero() {
		created = time.Now().UTC()
	}
	row := models.ProtectionBan{
		BanID:      hit.BanID,
		EventID:    hit.EventID,
		IP:         ip,
		SourceNode: uuid,
		PolicyID:   hit.PolicyID,
		ReasonType: hit.ReasonType,
		CreatedAt:  created.UTC(),
		ExpiresAt:  exp.UTC(),
		GroupID:    hit.GroupID,
		Status:     v2.ProtectionBanActive,
	}
	if row.BanID == "" {
		row.BanID = row.EventID
	}
	cfgRow, _ := protstore.GetConfig(uuid)
	cfg := protstore.ConfigFromRow(cfgRow)
	policy := findProtectionPolicy(cfg, hit.PolicyID)
	if hit.GroupID != "" && (policy == nil || policy.GroupID != hit.GroupID) {
		row.GroupID = ""
		hit.GroupID = ""
	}
	if hit.GroupID != "" && !protstore.IsMember(hit.GroupID, uuid) {
		row.GroupID = ""
		hit.GroupID = ""
	}
	if hit.GroupID != "" {
		group, err := protstore.GetGroup(hit.GroupID)
		if err != nil || group == nil || !group.Enabled {
			row.GroupID = ""
			hit.GroupID = ""
		}
	}
	inserted, err := protstore.UpsertBan(row)
	if err != nil {
		return err
	}
	if !inserted {
		return nil
	}
	if !hitEligibleForFanout(uuid, hit, cfg, policy, ip, report) {
		return nil
	}
	return fanoutSharedBan(uuid, hit)
}

func findProtectionPolicy(cfg v2.ProtectionConfig, id string) *v2.ProtectionPolicy {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range cfg.Policies {
		if cfg.Policies[i].ID == id {
			return &cfg.Policies[i]
		}
	}
	return nil
}

func hitEligibleForFanout(uuid string, hit v2.ProtectionBanReason, cfg v2.ProtectionConfig, policy *v2.ProtectionPolicy, ip string, report v2.ProtectionReportParams) bool {
	if hit.GroupID == "" || policy == nil {
		return false
	}
	if report.ConfigRev > 0 && cfg.Revision > 0 && report.ConfigRev < cfg.Revision {
		return false
	}
	if hit.GroupID != "" {
		if revokes, err := protstore.ListRevokes(hit.GroupID); err == nil {
			if rev, exists := revokes[ip]; exists && hitSuperseded(parseProtectionTime(hit.CreatedAt), rev.ResetAt) {
				return false
			}
		}
	}
	if !cfg.Enabled || !policy.Enabled || policy.Mode != v2.ProtectionModeEnforce {
		return false
	}
	if policy.GroupID != hit.GroupID {
		return false
	}
	for _, item := range cfg.Whitelist {
		if item == ip {
			return false
		}
	}
	client, err := clients.GetClientByUUID(uuid)
	if err != nil || !NodeSupports(client) {
		return false
	}
	return true
}

func parseProtectionTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return time.Time{}
	}
	return ts.UTC()
}

func hitSuperseded(created time.Time, resetAt string) bool {
	reset := parseProtectionTime(resetAt)
	if reset.IsZero() || created.IsZero() {
		return true
	}
	return !created.After(reset)
}
