package protection

import (
	"fmt"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/database/clients"
	"github.com/nuomiiiii/lite/database/models"
	protstore "github.com/nuomiiiii/lite/database/protection"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/utils"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
)

func View(client models.Client) (map[string]any, error) {
	row, err := protstore.EnsureConfig(client.UUID)
	if err != nil {
		return nil, err
	}
	cfg := protstore.ConfigFromRow(row)
	cap := protstore.CapabilityFromRow(row)
	op, _ := protstore.LatestUpgradeOp(client.UUID)
	bans, _ := protstore.ListRecentBans(client.UUID, 0)
	groups, _ := protstore.ListGroups()
	memberships, _ := protstore.ListMemberships(client.UUID)
	memberSet := map[string]models.ProtectionGroupMember{}
	for _, m := range memberships {
		memberSet[m.GroupID] = m
	}
	var groupViews []map[string]any
	for _, group := range groups {
		item := map[string]any{
			"id":       group.ID,
			"name":     group.Name,
			"enabled":  group.Enabled,
			"revision": group.Revision,
		}
		if m, ok := memberSet[group.ID]; ok {
			item["member"] = true
			item["applied_revision"] = m.AppliedRevision
			item["delivery_status"] = m.DeliveryStatus
			item["delivery_error"] = m.DeliveryError
		}
		members, _ := protstore.ListMembers(group.ID)
		item["members"] = memberViews(members)
		groupViews = append(groupViews, item)
	}
	out := map[string]any{
		"uuid":             client.UUID,
		"name":             client.Name,
		"config":           cfg,
		"delivery_status":  row.DeliveryStatus,
		"delivery_error":   row.DeliveryError,
		"applied_revision": row.AppliedRevision,
		"capability":       cap,
		"supported":        NodeSupports(client),
		"unavailable":      UnavailableReason(client),
		"linux":            clientLooksLinux(client, cap),
		"bans":             banViews(bans),
		"groups":           groupViews,
		"scope_note":       "封禁精确源 IP，切断该源全部入站（含已建立连接）；本机主动连出去的回包不封。Docker / 桥接 DNAT 经 FORWARD 的流量不在首版范围内。",
	}
	if report := protstore.ReportFromRow(row); report != nil {
		if len(report.SourceStats) > 0 {
			out["source_stats"] = report.SourceStats
		}
		if len(report.Hits) > 0 {
			out["observe_hits"] = report.Hits
		}
		if len(report.Nflog) > 0 {
			out["nflog"] = report.Nflog
		}
	}
	if op != nil {
		out["upgrade"] = op
	}
	return out, nil
}

func SaveConfig(uuid string, cfg v2.ProtectionConfig) (*models.ClientProtectionConfig, error) {
	normalized, err := NormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if !normalized.Enabled {
		normalized.RuntimeEnabled = false
	}
	row, err := protstore.SaveConfig(uuid, normalized)
	if err != nil {
		return nil, err
	}
	normalized.Revision = row.Revision
	_ = protstore.RevokeWhitelisted(uuid, normalized.Whitelist)
	unbanWhitelisted(uuid, normalized.Whitelist)
	if err := DispatchApply(uuid, normalized, false); err != nil {
		_ = protstore.MarkDelivery(uuid, protstore.DeliveryQueued, "", 0)
		if err == errQueueFull {
			_ = protstore.MarkDelivery(uuid, protstore.DeliveryFailed, err.Error(), 0)
			return row, err
		}
	} else if !agentOnline(uuid) {
		_ = protstore.MarkDelivery(uuid, protstore.DeliveryQueued, "", 0)
	} else {
		_ = protstore.MarkDelivery(uuid, protstore.DeliverySent, "", 0)
	}
	return row, nil
}

func StartUpgrade(uuid string) (*models.ProtectionUpgradeOp, v2.ProtectionResultParams, bool, error) {
	if active, err := protstore.ActiveUpgradeOp(uuid); err != nil {
		return nil, v2.ProtectionResultParams{}, false, err
	} else if active != nil {
		return active, v2.ProtectionResultParams{}, false, fmt.Errorf("该节点已有进行中的防护升级")
	}
	now := time.Now().UTC()
	op := &models.ProtectionUpgradeOp{
		ID:        utils.GenerateRandomString(16),
		Client:    uuid,
		Phase:     v2.ProtectionUpgradePhasePrecheck,
		StartedAt: now,
	}
	if err := protstore.SaveUpgradeOp(op); err != nil {
		return nil, v2.ProtectionResultParams{}, false, err
	}
	result, got, err := DispatchUpgrade(uuid, op.ID)
	if err != nil {
		op.Phase = v2.ProtectionUpgradePhaseFailed
		op.Result = v2.ProtectionStatusError
		op.Error = err.Error()
		op.FinishedAt = &now
		_ = protstore.SaveUpgradeOp(op)
		return op, result, false, err
	}
	if got {
		finishUpgrade(uuid, result)
		op, _ = protstore.LatestUpgradeOp(uuid)
	} else {
		op.Phase = v2.ProtectionUpgradePhaseInstall
		_ = protstore.SaveUpgradeOp(op)
	}
	return op, result, got, nil
}

func CreateGroup(name string, memberUUIDs []string) (*models.ProtectionGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("请填写联动组名称")
	}
	ready, err := filterReadyMembers(memberUUIDs)
	if err != nil {
		return nil, err
	}
	row := &models.ProtectionGroup{
		ID:       utils.GenerateRandomString(16),
		Name:     name,
		Enabled:  true,
		Revision: 1,
	}
	if err := protstore.SaveGroup(row); err != nil {
		return nil, err
	}
	if err := protstore.ReplaceMembers(row.ID, ready); err != nil {
		return nil, err
	}
	return row, nil
}

func UpdateGroup(id, name string, enabled bool, memberUUIDs []string) (*models.ProtectionGroup, error) {
	row, err := protstore.GetGroup(id)
	if err != nil || row == nil {
		return nil, fmt.Errorf("联动组不存在")
	}
	if strings.TrimSpace(name) != "" {
		row.Name = strings.TrimSpace(name)
	}
	row.Enabled = enabled
	ready, err := filterReadyMembers(memberUUIDs)
	if err != nil {
		return nil, err
	}
	prev, _ := protstore.ListMembers(id)
	prevSet := map[string]struct{}{}
	for _, m := range prev {
		prevSet[m.Client] = struct{}{}
	}
	if err := protstore.ReplaceMembers(id, ready); err != nil {
		return nil, err
	}
	row, err = protstore.UpdateGroupAndBump(id, row.Name, row.Enabled)
	if err != nil || row == nil {
		return nil, err
	}
	rev := row.Revision
	readySet := map[string]struct{}{}
	for _, uuid := range ready {
		readySet[uuid] = struct{}{}
	}
	empty := emptyGroupSnapshot(id, rev)
	for uuid := range prevSet {
		if _, ok := readySet[uuid]; !ok {
			_ = protstore.RecordLeave(id, uuid, rev)
			_ = DispatchGroupSnapshot(uuid, empty)
		}
	}
	if !row.Enabled {
		for _, uuid := range ready {
			_ = DispatchGroupSnapshot(uuid, empty)
		}
		return row, nil
	}
	if snap, err := groupSnapshot(row); err == nil {
		for _, uuid := range ready {
			_ = DispatchGroupSnapshot(uuid, snap)
		}
	}
	return row, nil
}

func Unban(uuid, ip, groupID string, local bool) error {
	norm, ok := v2.NormalizeProtectionIP(ip)
	if !ok {
		return fmt.Errorf("无效 IP")
	}
	now := time.Now().UTC()
	if groupID != "" {
		rev, err := protstore.RevokeGroupIP(groupID, norm, now)
		if err != nil {
			return err
		}
		members, err := protstore.ListMembers(groupID)
		if err != nil {
			return err
		}
		params := v2.ProtectionUnbanParams{IP: norm, GroupID: groupID, Revision: rev, ResetAt: now.Format(time.RFC3339Nano)}
		origins := protstore.LocalAutoSourceNodes(groupID, norm)
		for _, member := range members {
			item := params
			item.Local = origins[member.Client]
			_ = DispatchUnban(member.Client, item)
		}
		return nil
	}
	n, err := protstore.RevokeLocalIP(uuid, norm)
	if err != nil {
		return err
	}
	if n == 0 && protstore.HasGroupedBan(uuid, norm) {
		return fmt.Errorf("该记录属于联动组，请使用组内解除")
	}
	return DispatchUnban(uuid, v2.ProtectionUnbanParams{IP: norm, Local: local || true, ResetAt: now.Format(time.RFC3339Nano)})
}

func filterReadyMembers(uuids []string) ([]string, error) {
	var ready []string
	for _, uuid := range uuids {
		uuid = strings.TrimSpace(uuid)
		if uuid == "" {
			continue
		}
		client, err := clients.GetClientByUUID(uuid)
		if err != nil {
			return nil, fmt.Errorf("节点不存在")
		}
		if !NodeSupports(client) {
			continue
		}
		row, _ := protstore.GetConfig(uuid)
		cap := protstore.CapabilityFromRow(row)
		if !clientLooksLinux(client, cap) {
			continue
		}
		if cap == nil || !cap.RuntimeReady {
			continue
		}
		ready = append(ready, uuid)
	}
	return ready, nil
}

func memberViews(members []models.ProtectionGroupMember) []map[string]any {
	out := make([]map[string]any, 0, len(members))
	for _, member := range members {
		client, err := clients.GetClientByUUID(member.Client)
		item := map[string]any{
			"uuid":             member.Client,
			"applied_revision": member.AppliedRevision,
			"delivery_status":  member.DeliveryStatus,
			"delivery_error":   member.DeliveryError,
			"ready":            false,
		}
		if err == nil {
			item["name"] = client.Name
			item["online"] = agentOnline(client.UUID)
			item["supported"] = NodeSupports(client)
			row, _ := protstore.GetConfig(client.UUID)
			if cap := protstore.CapabilityFromRow(row); cap != nil {
				item["ready"] = cap.RuntimeReady
				item["capability"] = cap
			}
		}
		out = append(out, item)
	}
	return out
}

func banViews(rows []models.ProtectionBan) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"ban_id":      row.BanID,
			"event_id":    row.EventID,
			"ip":          row.IP,
			"source_node": row.SourceNode,
			"policy_id":   row.PolicyID,
			"reason_type": row.ReasonType,
			"created_at":  row.CreatedAt.UTC(),
			"expires_at":  row.ExpiresAt.UTC(),
			"group_id":    row.GroupID,
			"status":      row.Status,
			"scope":       "all inbound",
		})
	}
	return out
}

func emptyGroupSnapshot(groupID string, revision uint64) v2.ProtectionGroupSnapshot {
	return v2.ProtectionGroupSnapshot{Group: groupID, Revision: revision}
}

func unbanWhitelisted(uuid string, ips []string) {
	if len(ips) == 0 {
		return
	}
	now := time.Now().UTC()
	memberships, _ := protstore.ListMemberships(uuid)
	for _, ip := range ips {
		_ = DispatchUnban(uuid, v2.ProtectionUnbanParams{
			IP:      ip,
			Local:   true,
			ResetAt: now.Format(time.RFC3339Nano),
		})
		seen := map[string]struct{}{}
		for _, member := range memberships {
			if _, ok := seen[member.GroupID]; ok {
				continue
			}
			seen[member.GroupID] = struct{}{}
			_ = Unban(uuid, ip, member.GroupID, true)
		}
	}
}

func groupSnapshot(group *models.ProtectionGroup) (v2.ProtectionGroupSnapshot, error) {
	if group == nil {
		return v2.ProtectionGroupSnapshot{}, fmt.Errorf("group missing")
	}
	revision, bans, revoked, err := protstore.LoadGroupSnapshot(group.ID)
	if err != nil {
		return v2.ProtectionGroupSnapshot{}, err
	}
	snap := v2.ProtectionGroupSnapshot{Group: group.ID, Revision: revision, Revoked: revoked}
	for _, ban := range bans {
		snap.Bans = append(snap.Bans, v2.ProtectionBanReason{
			BanID:      ban.BanID,
			EventID:    ban.EventID,
			IP:         ban.IP,
			SourceNode: ban.SourceNode,
			PolicyID:   ban.PolicyID,
			ReasonType: v2.ProtectionReasonShared,
			CreatedAt:  ban.CreatedAt.UTC().Format(time.RFC3339Nano),
			ExpiresAt:  ban.ExpiresAt.UTC().Format(time.RFC3339Nano),
			GroupID:    ban.GroupID,
			Status:     ban.Status,
		})
	}
	return snap, nil
}

func fanoutSharedBan(source string, hit v2.ProtectionBanReason) error {
	if hit.GroupID == "" {
		return nil
	}
	created := parseHitTime(hit.CreatedAt)
	rev, ok, err := protstore.ClaimSharedFanout(hit.GroupID, source, hit.IP, hit.EventID, created)
	if err != nil || !ok {
		return err
	}
	members, err := protstore.ListMembers(hit.GroupID)
	if err != nil {
		return err
	}
	shared := hit
	shared.ReasonType = v2.ProtectionReasonShared
	shared.SourceNode = source
	for _, member := range members {
		if member.Client == source {
			continue
		}
		client, err := clients.GetClientByUUID(member.Client)
		if err != nil || !NodeSupports(client) {
			_ = protstore.MarkMember(hit.GroupID, member.Client, protstore.DeliveryUnsupported, "节点未就绪", 0)
			continue
		}
		if err := DispatchBan(member.Client, shared, rev); err != nil {
			_ = protstore.MarkMember(hit.GroupID, member.Client, protstore.DeliveryFailed, err.Error(), 0)
			continue
		}
		_ = protstore.MarkMember(hit.GroupID, member.Client, protstore.DeliverySent, "", 0)
	}
	return nil
}

func parseHitTime(raw string) time.Time {
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

func agentOnline(uuid string) bool {
	return agent_runtime.IsAgentOnline(uuid)
}

func clientLooksLinux(client models.Client, cap *v2.ProtectionCapability) bool {
	if cap != nil {
		return cap.Linux
	}
	osName := strings.ToLower(client.OS)
	if osName == "" {
		return false
	}
	if strings.Contains(osName, "windows") || strings.Contains(osName, "darwin") || strings.Contains(osName, "macos") {
		return false
	}
	return true
}
