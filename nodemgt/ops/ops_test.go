package ops

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/utils/instancekey"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	cleanup := instancekey.SetupTempFileForTest()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func testSvc(t *testing.T) *Service {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	st := store.New(db)
	require.NoError(t, st.Migrate())
	return New(st)
}

func TestAssignRenewTopupIdempotent(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "bob"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30, RateLimitBps: 128000, DeviceLimit: 2}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	a1, err := svc.Assign("admin", user.ID, plan.ID, "op-assign", now)
	require.NoError(t, err)
	a2, err := svc.Assign("admin", user.ID, plan.ID, "op-assign", now)
	require.NoError(t, err)
	require.Equal(t, a1.ID, a2.ID)
	r1, err := svc.Renew("admin", user.ID, "op-renew", now)
	require.NoError(t, err)
	r2, err := svc.Renew("admin", user.ID, "op-renew", now)
	require.NoError(t, err)
	require.Equal(t, r1.ID, r2.ID)
	require.NoError(t, svc.Topup("admin", user.ID, "op-topup", 500))
	require.NoError(t, svc.Topup("admin", user.ID, "op-topup", 500))
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1500), got.QuotaBytes)
	require.NoError(t, svc.RecordUsage(user.ID, 100))
	got, err = svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(100), got.UsedBytes)
	require.NoError(t, svc.RecordUsage(user.ID, 3000))
	got, err = svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3100), got.UsedBytes)
	require.NoError(t, svc.Disable("admin", user.ID, "op-off"))
	require.NoError(t, svc.RecordUsage(user.ID, 1))
	got, err = svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3101), got.UsedBytes)
}

func TestRenewDoesNotAddQuotaOrClearUsage(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "cara"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", user.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	require.NoError(t, svc.RecordUsage(user.ID, 100))
	_, err = svc.Renew("admin", user.ID, "op-r", now)
	require.NoError(t, err)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1000), got.QuotaBytes)
	require.Equal(t, int64(100), got.UsedBytes)
	require.NotNil(t, got.ExpiresAt)
	require.True(t, got.ExpiresAt.After(now.Add(40*24*time.Hour)))
	require.NoError(t, svc.Disable("admin", user.ID, "op-off"))
	_, err = svc.Renew("admin", user.ID, "op-r2", now)
	require.NoError(t, err)
	got, err = svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, models.UserDisabled, got.Status)
	require.Equal(t, int64(100), got.UsedBytes)
	require.Equal(t, int64(1000), got.QuotaBytes)
}

func TestUnassignClearsPlan(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "dana"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", user.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	require.NoError(t, svc.Unassign("admin", user.ID, "op-off-plan"))
	asg, err := svc.Store.ListAssignments(user.ID)
	require.NoError(t, err)
	require.Len(t, asg, 0)
	pending, err := svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	views, err := svc.Store.ListUserViews("")
	require.NoError(t, err)
	require.Equal(t, "", views[0].PlanID)
	require.Equal(t, int64(0), views[0].QuotaBytes)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.QuotaBytes)
}

func TestUnassignPlanClearsQuotaThenDeletesNothingElse(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "erin"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 4000, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", user.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	affected, err := svc.UnassignPlan("admin", plan.ID, "op-off-plan")
	require.NoError(t, err)
	require.Equal(t, []string{user.ID}, affected)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.QuotaBytes)
	asg, err := svc.Store.ListAssignments(user.ID)
	require.NoError(t, err)
	require.Len(t, asg, 0)
}

func TestAssignPlanChangeKeepsUsageAndDisable(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "dana"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", user.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	require.NoError(t, svc.RecordUsage(user.ID, 200))
	require.NoError(t, svc.Disable("admin", user.ID, "op-off"))
	next := &models.Plan{Name: "nodemgt", TrafficBytes: 5000, DurationDays: 7}
	require.NoError(t, svc.Store.UpsertPlan(next))
	_, err = svc.Assign("admin", user.ID, next.ID, "op-b", now)
	require.NoError(t, err)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(5000), got.QuotaBytes)
	require.Equal(t, int64(200), got.UsedBytes)
	require.Equal(t, models.UserDisabled, got.Status)
}

func TestRecordPresenceFromNodeMarksOnline(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, svc.Store.UpsertUser(user))
	require.NoError(t, svc.RecordPresenceFromNode("n1", []store.UserPresence{{
		UserID: user.ID,
		Online: true,
		IPs:    []store.UserIPView{{IP: "198.51.100.10"}},
	}}))
	views, err := svc.Store.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Equal(t, "198.51.100.10", views[0].OnlineIPs[0].IP)
}

func TestRecordPresenceFromNodeOfflineClearsIPs(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, svc.Store.UpsertUser(user))
	require.NoError(t, svc.RecordPresenceFromNode("n1", []store.UserPresence{{
		UserID: user.ID,
		Online: true,
		IPs:    []store.UserIPView{{IP: "198.51.100.10"}},
	}}))
	require.NoError(t, svc.RecordPresenceFromNode("n1", []store.UserPresence{{
		UserID: user.ID,
		Online: false,
		IPs:    []store.UserIPView{{IP: "198.51.100.10"}},
	}}))
	views, err := svc.Store.ListUserViews("")
	require.NoError(t, err)
	require.False(t, views[0].Online)
	require.Empty(t, views[0].OnlineIPs)
}

func TestRecordPresenceFromNodeSameIPKeepsOtherNode(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "node-a", Username: "audit-presence"}
	require.NoError(t, svc.Store.UpsertUser(user))
	a := &models.Inbound{NodeUUID: "node-a", Name: "a", Protocol: "vless", Port: 10001, Enabled: true}
	b := &models.Inbound{NodeUUID: "node-b", Name: "b", Protocol: "vless", Port: 10002, Enabled: true}
	require.NoError(t, svc.Store.UpsertInbound(a))
	require.NoError(t, svc.Store.UpsertInbound(b))
	require.NoError(t, svc.Store.ReplaceGrants(user.ID, []string{a.ID, b.ID}))
	ip := []store.UserIPView{{IP: "203.0.113.10"}}
	require.NoError(t, svc.RecordPresenceFromNode("node-a", []store.UserPresence{{UserID: user.ID, Online: true, IPs: ip}}))
	require.NoError(t, svc.RecordPresenceFromNode("node-b", []store.UserPresence{{UserID: user.ID, Online: true, IPs: ip}}))
	require.NoError(t, svc.RecordPresenceFromNode("node-b", []store.UserPresence{{UserID: user.ID, Online: false}}))
	views, err := svc.Store.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.10", views[0].OnlineIPs[0].IP)
}

func TestRecordUsageSameBatchKeepsBothUsers(t *testing.T) {
	svc := testSvc(t)
	a := &models.NodeUser{NodeUUID: "n1", Username: "audit-a"}
	b := &models.NodeUser{NodeUUID: "n1", Username: "audit-b"}
	require.NoError(t, svc.Store.UpsertUser(a))
	require.NoError(t, svc.Store.UpsertUser(b))
	require.NoError(t, svc.RecordUsageFromNode("n1", a.ID, 100, "same-agent-batch"))
	require.NoError(t, svc.RecordUsageFromNode("n1", b.ID, 200, "same-agent-batch"))
	require.NoError(t, svc.RecordUsageFromNode("n1", a.ID, 100, "same-agent-batch"))
	require.NoError(t, svc.RecordUsageFromNode("n1", b.ID, 200, "same-agent-batch"))
	gotA, err := svc.Store.GetUser(a.ID)
	require.NoError(t, err)
	gotB, err := svc.Store.GetUser(b.ID)
	require.NoError(t, err)
	require.Equal(t, int64(100), gotA.UsedBytes)
	require.Equal(t, int64(200), gotB.UsedBytes)
	var usageRows int64
	require.NoError(t, svc.Store.DB().Model(&models.QuotaLedger{}).Where("reason = ?", "usage").Count(&usageRows).Error)
	require.Zero(t, usageRows)
}

func TestSyncDueTrafficResetsEnqueuesQuotaSync(t *testing.T) {
	svc := testSvc(t)
	at := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	user := &models.NodeUser{
		NodeUUID: "n1", Username: "reset-me", QuotaBytes: 32, UsedBytes: 32,
		TrafficResetDay: 1, TrafficResetCycle: "2026-09-01",
	}
	require.NoError(t, svc.Store.UpsertUser(user))
	ids, err := svc.SyncDueTrafficResets(at)
	require.NoError(t, err)
	require.Equal(t, []string{user.ID}, ids)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.UsedBytes)
	require.Equal(t, "2026-10-01", got.TrafficResetCycle)
	pending, err := svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	require.Equal(t, "syncQuota", pending[0].Kind)
	again, err := svc.SyncDueTrafficResets(at)
	require.NoError(t, err)
	require.Empty(t, again)
	pending2, err := svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending2, len(pending))
}

func TestSyncDueTrafficResetsRollsBackWhenOutboxInsertFails(t *testing.T) {
	svc := testSvc(t)
	at := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	u1 := &models.NodeUser{
		NodeUUID: "n1", Username: "fail-1", QuotaBytes: 32, UsedBytes: 32,
		TrafficResetDay: 1, TrafficResetCycle: "2026-09-01",
	}
	u2 := &models.NodeUser{
		NodeUUID: "n2", Username: "fail-2", QuotaBytes: 32, UsedBytes: 32,
		TrafficResetDay: 1, TrafficResetCycle: "2026-09-01",
	}
	require.NoError(t, svc.Store.UpsertUser(u1))
	require.NoError(t, svc.Store.UpsertUser(u2))
	fail := true
	db := svc.Store.DB()
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("audit:outbox-once", func(tx *gorm.DB) {
		if fail && tx.Statement.Schema != nil && tx.Statement.Schema.Table == "nodemgt_control_commands" {
			fail = false
			tx.AddError(fmt.Errorf("audit one-off outbox insert failure"))
		}
	}))
	ids, err := svc.SyncDueTrafficResets(at)
	require.Error(t, err)
	require.Contains(t, err.Error(), "audit one-off outbox insert failure")
	require.Empty(t, ids)
	got1, err := svc.Store.GetUser(u1.ID)
	require.NoError(t, err)
	got2, err := svc.Store.GetUser(u2.ID)
	require.NoError(t, err)
	require.Equal(t, int64(32), got1.UsedBytes)
	require.Equal(t, int64(32), got2.UsedBytes)
	require.Equal(t, "2026-09-01", got1.TrafficResetCycle)
	require.Equal(t, "2026-09-01", got2.TrafficResetCycle)
	pending1, err := svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	pending2, err := svc.Store.PendingCommands("n2")
	require.NoError(t, err)
	require.Empty(t, pending1)
	require.Empty(t, pending2)
	require.NoError(t, db.Callback().Create().Remove("audit:outbox-once"))
	ids, err = svc.SyncDueTrafficResets(at)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{u1.ID, u2.ID}, ids)
	got1, err = svc.Store.GetUser(u1.ID)
	require.NoError(t, err)
	got2, err = svc.Store.GetUser(u2.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got1.UsedBytes)
	require.Equal(t, int64(0), got2.UsedBytes)
	require.Equal(t, "2026-10-01", got1.TrafficResetCycle)
	require.Equal(t, "2026-10-01", got2.TrafficResetCycle)
	pending1, err = svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	pending2, err = svc.Store.PendingCommands("n2")
	require.NoError(t, err)
	require.Len(t, pending1, 1)
	require.Len(t, pending2, 1)
	require.Equal(t, "syncQuota", pending1[0].Kind)
	require.Equal(t, "syncQuota", pending2[0].Kind)
}

func TestRecordUsageResetEnqueuesQuotaSync(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{
		NodeUUID: "n1", Username: "usage-reset", QuotaBytes: 32, UsedBytes: 32,
		TrafficResetDay: 1, TrafficResetCycle: "2020-01-01",
	}
	require.NoError(t, svc.Store.UpsertUser(user))
	require.NoError(t, svc.RecordUsageFromNode("n1", user.ID, 1, "monthly-usage"))
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), got.UsedBytes)
	pending, err := svc.Store.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	require.Equal(t, "syncQuota", pending[0].Kind)
}

func TestAssignFillsEmptyOperationID(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "edd"}
	require.NoError(t, svc.Store.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	a1, err := svc.Assign("admin", user.ID, plan.ID, "", time.Now().UTC())
	require.NoError(t, err)
	require.NotEmpty(t, a1.OperationID)
	a2, err := svc.Assign("admin", user.ID, plan.ID, "", time.Now().UTC())
	require.NoError(t, err)
	require.NotEqual(t, a1.OperationID, a2.OperationID)
}

func TestApplyPlanToAssigneesUpdatesLiveUsers(t *testing.T) {
	svc := testSvc(t)
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30, RateLimitBps: 128000, DeviceLimit: 2}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	other := &models.Plan{Name: "other", TrafficBytes: 9, DurationDays: 30}
	require.NoError(t, svc.Store.UpsertPlan(other))
	alice := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	bob := &models.NodeUser{NodeUUID: "n1", Username: "bob"}
	cara := &models.NodeUser{NodeUUID: "n1", Username: "cara"}
	require.NoError(t, svc.Store.UpsertUser(alice))
	require.NoError(t, svc.Store.UpsertUser(bob))
	require.NoError(t, svc.Store.UpsertUser(cara))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", alice.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	_, err = svc.Assign("admin", bob.ID, plan.ID, "op-b", now)
	require.NoError(t, err)
	_, err = svc.Assign("admin", cara.ID, other.ID, "op-c", now)
	require.NoError(t, err)
	require.NoError(t, svc.RecordUsage(alice.ID, 111))
	plan.TrafficBytes = 5000
	plan.DurationDays = 7
	plan.RateLimitBps = 256000
	plan.DeviceLimit = 5
	require.NoError(t, svc.Store.UpsertPlan(plan))
	affected, err := svc.ApplyPlanToAssignees("admin", plan.ID, "op-apply", now, 30)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{alice.ID, bob.ID}, affected)
	gotAlice, err := svc.Store.GetUser(alice.ID)
	require.NoError(t, err)
	require.Equal(t, int64(5000), gotAlice.QuotaBytes)
	require.Equal(t, int64(111), gotAlice.UsedBytes)
	require.Equal(t, int64(256000), gotAlice.RateLimitBps)
	require.Equal(t, 5, gotAlice.DeviceLimit)
	require.NotNil(t, gotAlice.ExpiresAt)
	require.Equal(t, now.Add(7*24*time.Hour), gotAlice.ExpiresAt.UTC())
	gotBob, err := svc.Store.GetUser(bob.ID)
	require.NoError(t, err)
	require.Equal(t, int64(5000), gotBob.QuotaBytes)
	gotCara, err := svc.Store.GetUser(cara.ID)
	require.NoError(t, err)
	require.Equal(t, int64(9), gotCara.QuotaBytes)
}

func TestApplyPlanToAssigneesKeepsRenewedExpiryWhenDurationUnchanged(t *testing.T) {
	svc := testSvc(t)
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30, RateLimitBps: 128000, DeviceLimit: 2}
	require.NoError(t, svc.Store.UpsertPlan(plan))
	user := &models.NodeUser{NodeUUID: "n1", Username: "erin"}
	require.NoError(t, svc.Store.UpsertUser(user))
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	_, err := svc.Assign("admin", user.ID, plan.ID, "op-a", now)
	require.NoError(t, err)
	_, err = svc.Renew("admin", user.ID, "op-r", now)
	require.NoError(t, err)
	plan.TrafficBytes = 8000
	require.NoError(t, svc.Store.UpsertPlan(plan))
	_, err = svc.ApplyPlanToAssignees("admin", plan.ID, "op-apply", now, 30)
	require.NoError(t, err)
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(8000), got.QuotaBytes)
	require.NotNil(t, got.ExpiresAt)
	require.Equal(t, now.Add(60*24*time.Hour), got.ExpiresAt.UTC())
}

func TestModifyClearsDeviceLimit(t *testing.T) {
	svc := testSvc(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "limit", DeviceLimit: 3}
	require.NoError(t, svc.Store.UpsertUser(user))
	zero := 0
	require.NoError(t, svc.Modify("admin", user.ID, "op-zero", nil, nil, &zero, nil))
	got, err := svc.Store.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, 0, got.DeviceLimit)
	neg := -1
	require.ErrorIs(t, svc.Modify("admin", user.ID, "op-neg", nil, nil, &neg, nil), store.ErrInvalid)
}
