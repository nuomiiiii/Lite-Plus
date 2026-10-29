package firewall

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/database/clients"
	fwstore "github.com/nuomiiiii/lite/database/firewall"
	"github.com/nuomiiiii/lite/database/models"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/utils"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
	"github.com/nuomiiiii/lite/web/api/remote"
)

var errQueueFull = errors.New("远程事件队列已满，请稍后重试")

const (
	snapshotWait   = 20 * time.Second
	applyWait      = 60 * time.Second
	installWait    = 4 * time.Minute
	applyRetrySkew = 15 * time.Second
)

type pendingWaiter struct {
	ch chan v2.FirewallResultParams
}

var (
	waitMu sync.Mutex
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
	waiters[requestID] = &pendingWaiter{ch: make(chan v2.FirewallResultParams, 1)}
	waitMu.Unlock()
}

func stopWait(requestID string) {
	waitMu.Lock()
	delete(waiters, requestID)
	waitMu.Unlock()
}

func waitFor(requestID string, timeout time.Duration) (v2.FirewallResultParams, bool) {
	waitMu.Lock()
	waiter := waiters[requestID]
	waitMu.Unlock()
	if waiter == nil {
		return v2.FirewallResultParams{}, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-waiter.ch:
		return result, true
	case <-timer.C:
		return v2.FirewallResultParams{}, false
	}
}

func SaveCleanSnapshot(clientUUID string, snapshot v2.FirewallResultParams) error {
	snapshot.HostRules = DropOwnedHostNoise(snapshot.HostRules)
	return fwstore.SaveSnapshot(clientUUID, snapshot)
}

func CompleteResult(uuid string, result v2.FirewallResultParams) {
	if result.Kind == v2.FirewallKindApply {
		status := fwstore.DeliveryFailed
		errText := result.Error
		applied := uint64(0)
		switch result.Status {
		case v2.FirewallStatusOK:
			status = fwstore.DeliveryApplied
			errText = ""
			applied = result.Revision
		case v2.FirewallStatusUnsupported:
			status = fwstore.DeliveryUnsupported
		case v2.FirewallStatusRolledBack:
			status = fwstore.DeliveryFailed
		}
		_ = fwstore.MarkDelivery(uuid, status, errText, applied)
		if defaultDenyRejected(result) {
			_ = fwstore.DisableDefaultDeny(uuid)
		}
	}
	_ = SaveCleanSnapshot(uuid, result)
	waitMu.Lock()
	waiter := waiters[result.RequestID]
	waitMu.Unlock()
	if waiter == nil {
		return
	}
	select {
	case waiter.ch <- result:
	default:
	}
}

func DispatchSnapshot(uuid string) (v2.FirewallResultParams, bool, error) {
	requestID := newRequestID()
	startWait(requestID)
	defer stopWait(requestID)
	params := v2.FirewallSnapshotParams{RequestID: requestID}
	ok := false
	agent_runtime.GuardRemoteDelivery(func() bool {
		return remote.RemoteManagementEnabled()
	}, func() {
		ok = agent_runtime.DispatchV2Event(uuid, v2.MethodAgentFirewallSnapshot, params)
	})
	if !ok {
		return v2.FirewallResultParams{}, false, errQueueFull
	}
	if agent_runtime.GetConnectedClient(uuid) == nil && !agent_runtime.IsAgentOnline(uuid) {
		return v2.FirewallResultParams{}, false, nil
	}
	result, got := waitFor(requestID, snapshotWait)
	return result, got, nil
}

func DispatchApply(uuid string, intent v2.FirewallIntent, holes []v2.FirewallHole) (v2.FirewallResultParams, bool) {
	return dispatchApply(uuid, intent, holes, true)
}

func dispatchApply(uuid string, intent v2.FirewallIntent, holes []v2.FirewallHole, wait bool) (v2.FirewallResultParams, bool) {
	requestID := newRequestID()
	if wait {
		startWait(requestID)
		defer stopWait(requestID)
	}
	params := v2.FirewallApplyParams{RequestID: requestID, Intent: intent, ListenHoles: holes}
	queued := false
	agent_runtime.GuardRemoteDelivery(func() bool {
		return remote.RemoteManagementEnabled()
	}, func() {
		queued = agent_runtime.DispatchV2Event(uuid, v2.MethodAgentFirewallApply, params)
	})
	if !queued {
		_ = fwstore.MarkDelivery(uuid, fwstore.DeliveryFailed, "远程事件队列已满，请稍后重试", 0)
		return v2.FirewallResultParams{}, false
	}
	if agent_runtime.GetConnectedClient(uuid) == nil && !agent_runtime.IsAgentOnline(uuid) {
		_ = fwstore.MarkDelivery(uuid, fwstore.DeliveryQueued, "", 0)
		return v2.FirewallResultParams{}, false
	}
	_ = fwstore.MarkDelivery(uuid, fwstore.DeliverySent, "", 0)
	if !wait {
		return v2.FirewallResultParams{}, false
	}
	result, got := waitFor(requestID, applyWait)
	return result, got
}

func ClearNode(uuid string) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return
	}
	row, err := fwstore.Get(uuid)
	if err != nil || row == nil {
		return
	}
	intent := fwstore.IntentFromRow(row)
	if intent.Revision == 0 && !intent.BlockPing4 && !intent.BlockPing6 && !intent.DefaultDeny4 && !intent.DefaultDeny6 && strings.TrimSpace(intent.SshPort) == "" && len(intent.Rules) == 0 {
		return
	}
	if agent_runtime.GetConnectedClient(uuid) == nil && !agent_runtime.IsAgentOnline(uuid) {
		return
	}
	empty := v2.FirewallIntent{Revision: intent.Revision + 1, Rules: []v2.FirewallRule{}}
	dispatchApply(uuid, empty, nil, false)
}

func DispatchAdopt(uuid string, keys []string) (v2.FirewallResultParams, bool) {
	requestID := newRequestID()
	startWait(requestID)
	defer stopWait(requestID)
	params := v2.FirewallAdoptParams{RequestID: requestID, Keys: keys}
	ok := false
	agent_runtime.GuardRemoteDelivery(func() bool {
		return remote.RemoteManagementEnabled()
	}, func() {
		ok = agent_runtime.DispatchV2Event(uuid, v2.MethodAgentFirewallAdopt, params)
	})
	if !ok || (agent_runtime.GetConnectedClient(uuid) == nil && !agent_runtime.IsAgentOnline(uuid)) {
		return v2.FirewallResultParams{}, false
	}
	result, got := waitFor(requestID, applyWait)
	return result, got
}

func DispatchInstall(uuid string) (v2.FirewallResultParams, bool, error) {
	requestID := newRequestID()
	startWait(requestID)
	defer stopWait(requestID)
	params := v2.FirewallInstallParams{RequestID: requestID}
	ok := false
	agent_runtime.GuardRemoteDelivery(func() bool {
		return remote.RemoteManagementEnabled()
	}, func() {
		ok = agent_runtime.DispatchV2Event(uuid, v2.MethodAgentFirewallInstall, params)
	})
	if !ok {
		return v2.FirewallResultParams{}, false, errQueueFull
	}
	if agent_runtime.GetConnectedClient(uuid) == nil && !agent_runtime.IsAgentOnline(uuid) {
		return v2.FirewallResultParams{}, false, nil
	}
	result, got := waitFor(requestID, installWait)
	return result, got, nil
}

func PushPending(uuid string) {
	if uuid == "" {
		rows, err := fwstore.DueApplies()
		if err != nil {
			return
		}
		for _, row := range rows {
			pushRow(row, false)
		}
		return
	}
	row, err := fwstore.Get(uuid)
	if err != nil || row == nil {
		return
	}
	pushRow(*row, false)
}

func SyncOnConnect(uuid string) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return
	}
	row, err := fwstore.Get(uuid)
	if err != nil || row == nil {
		return
	}
	pushRow(*row, true)
}

func pushRow(row models.ClientFirewallIntent, force bool) {
	if !remote.RemoteManagementEnabled() {
		return
	}
	if row.Revision == 0 {
		return
	}
	if !force && row.AppliedRevision >= row.Revision {
		return
	}
	if !force && applyInFlight(row) {
		return
	}
	client, err := clients.GetClientByUUID(row.Client)
	if err != nil {
		return
	}
	if remote.AgentRemoteAllowed(client) != nil {
		return
	}
	if !client.Firewall || client.FirewallVersion < v2.FirewallVersion {
		return
	}
	intent := fwstore.IntentFromRow(&row)
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		if snap := fwstore.SnapshotFromRow(&row); snap != nil && defaultDenyRejected(*snap) {
			_ = fwstore.DisableDefaultDeny(row.Client)
			intent.DefaultDeny4 = false
			intent.DefaultDeny6 = false
		}
	}
	dispatchApply(row.Client, intent, ListenHoles(row.Client, intent), false)
}

func applyInFlight(row models.ClientFirewallIntent) bool {
	if row.DeliveryStatus != fwstore.DeliverySent || row.DeliveryUpdatedAt == nil {
		return false
	}
	return time.Since(*row.DeliveryUpdatedAt) < applyWait+applyRetrySkew
}

func GuardDefaultDeny(uuid string, prev, intent v2.FirewallIntent) error {
	if !intent.DefaultDeny4 && !intent.DefaultDeny6 {
		return nil
	}
	enabling := (!prev.DefaultDeny4 && intent.DefaultDeny4) || (!prev.DefaultDeny6 && intent.DefaultDeny6)
	row, _ := fwstore.Get(uuid)
	snap := fwstore.SnapshotFromRow(row)
	if enabling || snap == nil {
		result, got, err := DispatchSnapshot(uuid)
		if err != nil && enabling {
			return err
		}
		if got {
			snap = &result
			_ = SaveCleanSnapshot(uuid, result)
		}
	}
	if snap != nil {
		if defaultDenyRejected(*snap) || DefaultDenyConflict(snap.Backend, snap.OuterManagers) {
			return ErrDefaultDenyConflict
		}
		return nil
	}
	if enabling {
		return ErrDefaultDenyNeedScan
	}
	return nil
}

func defaultDenyRejected(result v2.FirewallResultParams) bool {
	if result.DefaultDenyBlocked {
		return true
	}
	return strings.Contains(strings.ToLower(result.Error), "default deny conflicts")
}

var (
	ErrSiteRemoteOff        = errors.New("站点未启用远程管理")
	ErrAgentTooOld          = errors.New("Agent 版本过旧，请升级")
	ErrAgentRemoteOff       = errors.New("节点未启用远程控制")
	ErrFirewallUnsupported  = errors.New("当前 Agent 不支持防火墙，请升级")
)

func EnsureApplyAllowed(uuid string) error {
	if !remote.RemoteManagementEnabled() {
		return ErrSiteRemoteOff
	}
	client, err := clients.GetClientByUUID(uuid)
	if err != nil {
		return err
	}
	switch UnavailableReason(client) {
	case "agent_old":
		if client.RemoteProtocol == 2 && (!client.Firewall || client.FirewallVersion < v2.FirewallVersion) {
			return ErrFirewallUnsupported
		}
		return ErrAgentTooOld
	case "remote_off":
		return ErrAgentRemoteOff
	}
	return nil
}

func NodeSupports(client models.Client) bool {
	return client.RemoteProtocol == 2 && client.RemoteControlEnabled && client.Firewall && client.FirewallVersion >= v2.FirewallVersion
}

func UnavailableReason(client models.Client) string {
	if client.RemoteProtocol != 2 {
		return "agent_old"
	}
	if !client.RemoteControlEnabled {
		return "remote_off"
	}
	if !client.Firewall || client.FirewallVersion < v2.FirewallVersion {
		return "agent_old"
	}
	return ""
}
