package protection

import (
	"os"
	"strings"
	"testing"
	"time"

	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

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
