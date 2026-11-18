package protection

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/cmd/flags"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/utils/instancekey"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func TestMain(m *testing.M) {
	cleanup := instancekey.SetupTempFileForTest()
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:protection_store_test?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func TestBumpGroupRevisionIsAtomicAndFieldLocal(t *testing.T) {
	raw, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	bump := extractStoreFunc(text, "func BumpGroupRevision")
	if bump == "" {
		t.Fatal("BumpGroupRevision missing")
	}
	if strings.Contains(bump, "SaveGroup") || strings.Contains(bump, "UpdateAll") {
		t.Fatal("revision bump must not rewrite the whole group row")
	}
	if !strings.Contains(bump, "revision + 1") {
		t.Fatal("revision bump must be assigned by the database")
	}
	upsert := extractStoreFunc(text, "func upsertBanRow")
	if !strings.Contains(upsert, "ProtectionBanRevoked") {
		t.Fatal("the same event id may be reused only to revive a revoked row")
	}
	if !strings.Contains(upsert, "return false, nil") {
		t.Fatal("an already active event must not look like a new insert")
	}
	groupWrite := extractStoreFunc(text, "func upsertGroupBan")
	if !strings.Contains(groupWrite, "Transaction") || !strings.Contains(groupWrite, "ProtectionRevoke") || !strings.Contains(groupWrite, "eventBeforeReset") {
		t.Fatal("grouped hits must check the current revoke inside the group write transaction")
	}
	update := extractStoreFunc(text, "func UpdateGroupAndBump")
	if update == "" || strings.Contains(update, "UpdateAll") || strings.Contains(update, "SaveGroup") {
		t.Fatal("group field changes must bump revision without rewriting an old object")
	}
	if !strings.Contains(update, "revision + 1") {
		t.Fatal("group updates must assign the next revision in the same statement")
	}
	revoke := extractStoreFunc(text, "func RevokeGroupIP")
	if !strings.Contains(revoke, "Transaction") || !strings.Contains(revoke, "revision + 1") || !strings.Contains(revoke, "ProtectionRevoke") {
		t.Fatal("group unban must bump revision and write the revoke in one transaction")
	}
	snap := extractStoreFunc(text, "func LoadGroupSnapshot")
	if snap == "" {
		t.Fatal("snapshots must read revision, bans and revokes together")
	}
	if !strings.Contains(snap, "eventBeforeReset") {
		t.Fatal("snapshots must drop hits formed before the IP reset")
	}
	claim := extractStoreFunc(text, "func ClaimSharedFanout")
	if !strings.Contains(claim, "Transaction") || !strings.Contains(claim, "revision + 1") {
		t.Fatal("shared fan-out must assign the next revision inside the group transaction")
	}
	if !strings.Contains(claim, "ProtectionRevoke") || !strings.Contains(claim, "ProtectionBanRevoked") {
		t.Fatal("shared fan-out must refuse revoked IPs and revoked events before bumping")
	}
	if !strings.Contains(claim, "ProtectionGroupMember") {
		t.Fatal("shared fan-out must still require current membership")
	}
}

func TestProtectionActivityStaleKeepsLiveAndRecentRecords(t *testing.T) {
	now := time.Date(2026, 11, 13, 1, 30, 0, 0, time.UTC)
	cutoff := now.Add(-7 * 24 * time.Hour)
	liveExp := now.Add(10 * time.Minute)
	if protectionActivityStale(v2.ProtectionBanActive, now.Add(-time.Minute), liveExp, now) {
		t.Fatal("an active ban must stay until it ends")
	}
	if protectionActivityStale(v2.ProtectionBanActive, cutoff.Add(-24*time.Hour), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), now) {
		t.Fatal("a permanent ban must stay while it is still enforcing")
	}
	if protectionActivityStale(v2.ProtectionBanActive, now.Add(-24*time.Hour), now.Add(-time.Hour), now) {
		t.Fatal("an expired ban must stay for seven days after it ends")
	}
	if !protectionActivityStale(v2.ProtectionBanActive, cutoff.Add(-time.Hour), cutoff.Add(-time.Minute), now) {
		t.Fatal("an expired ban older than seven days must be dropped")
	}
	if protectionActivityStale(v2.ProtectionBanRevoked, now.Add(-time.Hour), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), now) {
		t.Fatal("a recently revoked permanent ban must stay for seven days")
	}
	if !protectionActivityStale(v2.ProtectionBanRevoked, cutoff.Add(-time.Hour), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), now) {
		t.Fatal("a revoked permanent ban older than seven days must be dropped")
	}
}

func TestListRecentBansKeepsExpiredRows(t *testing.T) {
	raw, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	recent := extractStoreFunc(string(raw), "func ListRecentBans")
	if recent == "" {
		t.Fatal("ListRecentBans missing")
	}
	if !strings.Contains(recent, "created_at DESC") {
		t.Fatal("activity must keep recent bans newest first")
	}
	if strings.Contains(recent, "expires_at >") {
		t.Fatal("recent bans must not drop expired rows")
	}
	if !strings.Contains(recent, "maxStoredActivityBans") {
		t.Fatal("recent bans must cap the activity window")
	}
	prune := extractStoreFunc(string(raw), "func pruneExpiredActivity")
	if prune == "" {
		t.Fatal("expired activity must be pruned")
	}
	if !strings.Contains(string(raw), "activityRetention     = 7 * 24 * time.Hour") {
		t.Fatal("protection activity must expire after seven days")
	}
	if !strings.Contains(prune, "activityCutoff") || !strings.Contains(prune, "ProtectionBanRevoked") {
		t.Fatal("prune must keep a seven-day window and still drop revoked rows")
	}
	save := extractStoreFunc(string(raw), "func SaveReport")
	if !strings.Contains(save, "pruneReportHits") {
		t.Fatal("observe hits must use the same seven-day window")
	}
}

func TestDeleteGroupAndPruneExpiredActivityInSQLite(t *testing.T) {
	db := dbcore.GetDBInstance()
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	groupID := "grp-" + uuid.NewString()[:8]
	nodeUUID := "node-" + uuid.NewString()[:8]

	if err := db.Create(&models.ProtectionGroup{
		ID:        groupID,
		Name:      "Shared Group",
		Enabled:   true,
		Revision:  3,
		CreatedAt: now,
		UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ProtectionGroupMember{
		GroupID:   groupID,
		Client:    nodeUUID,
		UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ProtectionGroupLeave{
		Client:    nodeUUID,
		GroupID:   groupID,
		CreatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ProtectionRevoke{
		GroupID:  groupID,
		IP:       "198.51.100.1",
		Revision: 3,
		ResetAt:  now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := SaveConfig(nodeUUID, v2.ProtectionConfig{
		Enabled: true,
		Policies: []v2.ProtectionPolicy{
			{ID: "p1", Name: "ssh", GroupID: groupID},
			{ID: "p2", Name: "local", GroupID: ""},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Test PruneExpiredActivity on stale (>30d) revokes & finished upgrade ops while preserving fresh/active rows.
	otherGroup := "grp-keep-" + uuid.NewString()[:8]
	staleAt := now.Add(-31 * 24 * time.Hour)
	freshAt := now.Add(-5 * 24 * time.Hour)
	if err := db.Create(&models.ProtectionRevoke{GroupID: otherGroup, IP: "203.0.113.1", Revision: 1, ResetAt: staleAt}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ProtectionRevoke{GroupID: otherGroup, IP: "203.0.113.2", Revision: 2, ResetAt: freshAt}).Error; err != nil {
		t.Fatal(err)
	}
	staleOpID := "op-stale-" + uuid.NewString()[:8]
	activeOpID := "op-active-" + uuid.NewString()[:8]
	if err := SaveUpgradeOp(&models.ProtectionUpgradeOp{ID: staleOpID, Client: nodeUUID, Phase: "done", StartedAt: staleAt, FinishedAt: &staleAt}); err != nil {
		t.Fatal(err)
	}
	if err := SaveUpgradeOp(&models.ProtectionUpgradeOp{ID: activeOpID, Client: nodeUUID, Phase: "running", StartedAt: staleAt, FinishedAt: nil}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = DeleteClient(nodeUUID)
		_ = db.Where("group_id = ?", otherGroup).Delete(&models.ProtectionRevoke{}).Error
		_ = db.Where("id IN ?", []string{staleOpID, activeOpID}).Delete(&models.ProtectionUpgradeOp{}).Error
	})

	if err := PruneExpiredActivity(now); err != nil {
		t.Fatalf("PruneExpiredActivity: %v", err)
	}
	var staleRevokeCount, freshRevokeCount int64
	db.Model(&models.ProtectionRevoke{}).Where("group_id = ? AND ip = ?", otherGroup, "203.0.113.1").Count(&staleRevokeCount)
	db.Model(&models.ProtectionRevoke{}).Where("group_id = ? AND ip = ?", otherGroup, "203.0.113.2").Count(&freshRevokeCount)
	if staleRevokeCount != 0 || freshRevokeCount != 1 {
		t.Fatalf("prune revokes: stale=%d (want 0), fresh=%d (want 1)", staleRevokeCount, freshRevokeCount)
	}
	var staleOpCount, activeOpCount int64
	db.Model(&models.ProtectionUpgradeOp{}).Where("id = ?", staleOpID).Count(&staleOpCount)
	db.Model(&models.ProtectionUpgradeOp{}).Where("id = ?", activeOpID).Count(&activeOpCount)
	if staleOpCount != 0 || activeOpCount != 1 {
		t.Fatalf("prune upgrade ops: stale=%d (want 0), active=%d (want 1)", staleOpCount, activeOpCount)
	}

	// Test DeleteGroup cleans members, leaves, revokes, group row, and clears GroupID in client policy JSON.
	if err := DeleteGroup(groupID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	var memberCount, leaveCount, groupRevokeCount, groupCount int64
	db.Model(&models.ProtectionGroupMember{}).Where("group_id = ?", groupID).Count(&memberCount)
	db.Model(&models.ProtectionGroupLeave{}).Where("group_id = ?", groupID).Count(&leaveCount)
	db.Model(&models.ProtectionRevoke{}).Where("group_id = ?", groupID).Count(&groupRevokeCount)
	db.Model(&models.ProtectionGroup{}).Where("id = ?", groupID).Count(&groupCount)
	if memberCount != 0 || leaveCount != 0 || groupRevokeCount != 0 || groupCount != 0 {
		t.Fatalf("DeleteGroup left orphan rows: members=%d leaves=%d revokes=%d groups=%d",
			memberCount, leaveCount, groupRevokeCount, groupCount)
	}
	cfgRow, err := GetConfig(nodeUUID)
	if err != nil || cfgRow == nil {
		t.Fatalf("GetConfig after DeleteGroup: row=%v err=%v", cfgRow, err)
	}
	parsedCfg := ConfigFromRow(cfgRow)
	if len(parsedCfg.Policies) != 2 || parsedCfg.Policies[0].GroupID != "" {
		t.Fatalf("DeleteGroup did not clear policy GroupID: %+v", parsedCfg.Policies)
	}
}

func TestEventBeforeResetTreatsOldHitsAsSuperseded(t *testing.T) {
	created := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	reset := created.Add(time.Minute)
	if !eventBeforeReset(created, reset) {
		t.Fatal("a hit formed before unban must not fan out")
	}
	if eventBeforeReset(reset.Add(time.Second), reset) {
		t.Fatal("a hit formed after unban must still fan out")
	}
	if !eventBeforeReset(created, time.Time{}) {
		t.Fatal("a revoke without reset time must not resurrect the old hit")
	}
}

func extractStoreFunc(src, signature string) string {
	start := strings.Index(src, signature)
	if start < 0 {
		return ""
	}
	rest := src[start:]
	depth := 0
	for i, r := range rest {
		if r == '{' {
			depth++
		}
		if r == '}' {
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
