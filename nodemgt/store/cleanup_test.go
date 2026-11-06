package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
	dbmodels "github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/stretchr/testify/require"
)

func TestCleanupExpiredKeepsUsedBytes(t *testing.T) {
	st := testDB(t)
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	user := &models.NodeUser{NodeUUID: "n1", Username: "keep-used", QuotaBytes: 1000, UsedBytes: 12345}
	require.NoError(t, st.UpsertUser(user))
	insertLedger(t, st, user.ID, "usage", "usage-1", 12, now.Add(-time.Minute))
	insertLedger(t, st, user.ID, "assign", "assign-keep", 1000, now.Add(-time.Hour))

	require.NoError(t, st.CleanupExpired(now))

	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(12345), got.UsedBytes)
	require.Equal(t, int64(1000), got.QuotaBytes)
	var usage int64
	require.NoError(t, st.DB().Model(&models.QuotaLedger{}).Where("reason = ?", "usage").Count(&usage).Error)
	require.Zero(t, usage)
	var kept int64
	require.NoError(t, st.DB().Model(&models.QuotaLedger{}).Where("reason IN ?", []string{"assign", "topup"}).Count(&kept).Error)
	require.Equal(t, int64(1), kept)
}

func TestCleanupUsageLedgerDropsUsageKeepsAssignAndTopup(t *testing.T) {
	st := testDB(t)
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	user := "user-keep"
	insertLedger(t, st, user, "usage", "recent", 12, now.Add(-time.Minute))
	insertLedger(t, st, user, "usage", "old", 10, now.Add(-72*time.Hour))
	assign := insertLedger(t, st, user, "assign", "assign-1", 1000, now.Add(-80*time.Hour))
	topup := insertLedger(t, st, user, "topup", "topup-1", 500, now.Add(-80*time.Hour))

	require.NoError(t, st.CleanupExpired(now))

	require.ElementsMatch(t, []string{assign, topup}, ledgerIDs(t, st))
}

func TestCleanupFinishedCommandsStripsPayloadAndDropsOld(t *testing.T) {
	st := testDB(t)
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	oldApplied := insertCommand(t, st, "op-old-applied", models.CmdApplied, `{"big":true}`, now.Add(-8*24*time.Hour))
	recentApplied := insertCommand(t, st, "op-recent-applied", models.CmdApplied, `{"big":true}`, now.Add(-24*time.Hour))
	oldPending := insertCommand(t, st, "op-old-pending", models.CmdPending, `{"keep":true}`, now.Add(-30*24*time.Hour))
	oldSent := insertCommand(t, st, "op-old-sent", models.CmdSent, `{"keep":true}`, now.Add(-30*24*time.Hour))

	require.NoError(t, st.CleanupExpired(now))

	require.False(t, commandExists(t, st, oldApplied))
	require.True(t, commandExists(t, st, recentApplied))
	require.Equal(t, "", commandPayload(t, st, recentApplied))
	require.True(t, commandExists(t, st, oldPending))
	require.Equal(t, `{"keep":true}`, commandPayload(t, st, oldPending))
	require.True(t, commandExists(t, st, oldSent))
	require.Equal(t, `{"keep":true}`, commandPayload(t, st, oldSent))
}

func TestAckCommandClearsPayload(t *testing.T) {
	st := testDB(t)
	cmd := &models.ControlCommand{OperationID: "op-ack", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: `{"secret":true}`}
	require.NoError(t, st.EnqueueCommand(cmd))
	require.NoError(t, st.AckCommand("op-ack", models.CmdApplied, ""))
	got, err := st.GetCommand("op-ack")
	require.NoError(t, err)
	require.Equal(t, models.CmdApplied, got.Status)
	require.Empty(t, got.PayloadJSON)
}

func TestNodemgtAuditPayloadCoversDeleteAndStatus(t *testing.T) {
	planKey, plan := NodemgtAuditPayload("nodemgt.plan.delete", "plan-1", "标准套餐")
	require.Equal(t, "audit.nodemgt_plan_delete", planKey)
	require.Equal(t, "标准套餐", plan["name"])
	subKey, sub := NodemgtAuditPayload("nodemgt.subscription.delete", "sub-1", "alice")
	require.Equal(t, "audit.nodemgt_subscription_delete", subKey)
	require.Equal(t, "alice", sub["name"])
	statusKey, status := NodemgtAuditPayload("nodemgt.user.setStatus", "user-1", "alice")
	require.Equal(t, "audit.nodemgt_user_set_status", statusKey)
	require.Equal(t, "alice", status["name"])
}

func TestAuditWritesAdminLog(t *testing.T) {
	st := testDB(t)
	require.NoError(t, st.DB().AutoMigrate(&dbmodels.Log{}))
	require.NoError(t, st.AuditFrom("203.0.113.10", "user-1", "nodemgt.inbound.upsert", "in-1", "web"))
	var row dbmodels.Log
	require.NoError(t, st.DB().First(&row).Error)
	require.Equal(t, nodemgtLogType, row.MsgType)
	require.Equal(t, "203.0.113.10", row.IP)
	require.Equal(t, "user-1", row.UUID)
	require.Contains(t, row.Message, "audit.nodemgt_inbound_upsert")
	require.Contains(t, row.Message, "web")
}

func TestMigrateAuditEventsToLogsKeepsTime(t *testing.T) {
	st := testDB(t)
	require.NoError(t, st.DB().AutoMigrate(&dbmodels.Log{}))
	when := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	require.NoError(t, st.DB().Create(&models.AuditEvent{
		ID:        uuid.NewString(),
		Actor:     "admin",
		Action:    "nodemgt.settings.set",
		Target:    "nodemgt",
		CreatedAt: when,
	}).Error)
	require.NoError(t, st.migrateAuditEventsToLogs())
	var row dbmodels.Log
	require.NoError(t, st.DB().First(&row).Error)
	require.Equal(t, nodemgtLogType, row.MsgType)
	require.Equal(t, when.Unix(), row.Time.UTC().Unix())
	var leftover int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).Count(&leftover).Error)
	require.Zero(t, leftover)
}

func TestApplyUsageBatchIsIdempotent(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "usage"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.ApplyUsageBatch(user.ID, "u:batch-1", 100))
	require.ErrorIs(t, st.ApplyUsageBatch(user.ID, "u:batch-1", 100), ErrConflict)
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(100), got.UsedBytes)
	require.NoError(t, st.ApplyUsageBatch(user.ID, "u:batch-2", 40))
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(140), got.UsedBytes)
	require.Equal(t, "u:batch-2", got.LastUsageOp)
	require.NoError(t, st.UpsertUser(got))
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, "u:batch-2", got.LastUsageOp)
}

func insertLedger(t *testing.T, st *Store, userID, reason, opID string, delta int64, created time.Time) string {
	t.Helper()
	id := uuid.NewString()
	require.NoError(t, st.DB().Create(&models.QuotaLedger{
		ID:        id,
		UserID:    userID,
		Delta:     delta,
		Reason:    reason,
		OpID:      opID,
		CreatedAt: created.UTC(),
	}).Error)
	return id
}

func ledgerIDs(t *testing.T, st *Store) []string {
	t.Helper()
	var ids []string
	require.NoError(t, st.DB().Model(&models.QuotaLedger{}).Order("created_at ASC").Pluck("id", &ids).Error)
	return ids
}

func insertCommand(t *testing.T, st *Store, opID, status, payload string, updated time.Time) string {
	t.Helper()
	id := uuid.NewString()
	require.NoError(t, st.DB().Create(&models.ControlCommand{
		ID:          id,
		OperationID: opID,
		NodeUUID:    "n1",
		Kind:        "applyConfig",
		PayloadJSON: payload,
		Status:      status,
		CreatedAt:   updated.UTC(),
		UpdatedAt:   updated.UTC(),
	}).Error)
	return id
}

func commandExists(t *testing.T, st *Store, id string) bool {
	t.Helper()
	var count int64
	require.NoError(t, st.DB().Model(&models.ControlCommand{}).Where("id = ?", id).Count(&count).Error)
	return count == 1
}

func commandPayload(t *testing.T, st *Store, id string) string {
	t.Helper()
	var row models.ControlCommand
	require.NoError(t, st.DB().Select("payload_json").First(&row, "id = ?", id).Error)
	return row.PayloadJSON
}
