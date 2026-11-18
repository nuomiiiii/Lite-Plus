package store

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
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

func testDB(t *testing.T) *Store {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{NowFunc: func() time.Time { return time.Now().UTC() }})
	require.NoError(t, err)
	st := New(db)
	require.NoError(t, st.Migrate())
	return st
}

func TestPlusTablesMigrated(t *testing.T) {
	st := testDB(t)
	sqlDB, err := st.DB().DB()
	require.NoError(t, err)
	rows, err := sqlDB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'nodemgt_%' ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		names = append(names, name)
	}
	require.Contains(t, names, "nodemgt_inbounds")
	require.Contains(t, names, "nodemgt_node_users")
	require.Contains(t, names, "nodemgt_credentials")
	require.Contains(t, names, "nodemgt_plans")
	require.Contains(t, names, "nodemgt_quota_ledger")
	require.Contains(t, names, "nodemgt_control_commands")
	require.Contains(t, names, "nodemgt_certs")
	require.Contains(t, names, "nodemgt_root_certs")
	require.Contains(t, names, "nodemgt_subscriptions")
	require.Contains(t, names, "nodemgt_grants")
	require.Contains(t, names, "nodemgt_user_ips")
	require.Contains(t, names, "nodemgt_user_extra_links")
	require.Contains(t, names, "nodemgt_node_profiles")
}

func TestUserPresenceOnlineAndClear(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "203.0.113.10", SeenAt: time.Now().UTC()},
		{IP: "203.0.113.11"},
	}))
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 2)
	require.NoError(t, st.ClearUserIPs(user.ID))
	views, err = st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Empty(t, views[0].OnlineIPs)
}

func TestUserPresenceOfflineReplayAfterClearStaysEmpty(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "offline-history"}
	require.NoError(t, st.UpsertUser(user))
	seenAt := time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC)
	ips := []UserIPView{{IP: "172.18.0.1", SeenAt: seenAt}}
	require.NoError(t, st.RecordUserPresence("n1", user.ID, false, ips))
	before, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Empty(t, before)
	require.NoError(t, st.ClearUserIPs(user.ID))
	cleared, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Empty(t, cleared)
	require.NoError(t, st.RecordUserPresence("n1", user.ID, false, ips))
	after, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Empty(t, after)
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "172.18.0.1", SeenAt: time.Now().UTC().Add(2 * time.Second)},
	}))
	fresh, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Len(t, fresh, 1)
	require.Equal(t, "172.18.0.1", fresh[0].IP)
}

func TestUserPresenceOfflineClearsLiveIPs(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "was-online"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "203.0.113.20"},
	}))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, false, []UserIPView{
		{IP: "203.0.113.20"},
	}))
	stored, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Empty(t, stored)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.False(t, views[0].Online)
	require.Empty(t, views[0].OnlineIPs)
}

func TestUserPresenceKeepsConcurrentIPsOnly(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "swap-ip"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "203.0.113.30"},
		{IP: "203.0.113.31"},
	}))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "203.0.113.31"},
	}))
	stored, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, "203.0.113.31", stored[0].IP)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.31", views[0].OnlineIPs[0].IP)
}

func TestUserPresenceHidesStaleIPsFromViews(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "stale-ip"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "203.0.113.40"},
	}))
	require.NoError(t, st.DB().Model(&models.UserIP{}).Where("user_id = ?", user.ID).Update("seen_at", time.Now().UTC().Add(-time.Hour)).Error)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.True(t, views[0].Online)
	require.Empty(t, views[0].OnlineIPs)
}

func TestUserPresenceSameIPOnTwoNodesKeepsOtherOnline(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "node-a", Username: "shared-ip"}
	require.NoError(t, st.UpsertUser(user))
	a := &models.Inbound{NodeUUID: "node-a", Name: "a", Protocol: "vless", Port: 10001, Enabled: true}
	b := &models.Inbound{NodeUUID: "node-b", Name: "b", Protocol: "vless", Port: 10002, Enabled: true}
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{a.ID, b.ID}))
	ip := []UserIPView{{IP: "203.0.113.10"}}
	require.NoError(t, st.RecordUserPresence("node-a", user.ID, true, ip))
	require.NoError(t, st.RecordUserPresence("node-b", user.ID, true, ip))
	stored, err := st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 2)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.10", views[0].OnlineIPs[0].IP)
	require.NoError(t, st.RecordUserPresence("node-b", user.ID, false, nil))
	views, err = st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.10", views[0].OnlineIPs[0].IP)
	stored, err = st.ListUserIPs(user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, "203.0.113.10", stored[0].IP)
}

func TestUserPresenceDistinctIPsOnTwoNodesOfflineKeepsOther(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "node-a", Username: "distinct-ip"}
	require.NoError(t, st.UpsertUser(user))
	a := &models.Inbound{NodeUUID: "node-a", Name: "a", Protocol: "vless", Port: 10001, Enabled: true}
	b := &models.Inbound{NodeUUID: "node-b", Name: "b", Protocol: "vless", Port: 10002, Enabled: true}
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{a.ID, b.ID}))
	require.NoError(t, st.RecordUserPresence("node-a", user.ID, true, []UserIPView{{IP: "203.0.113.10"}}))
	require.NoError(t, st.RecordUserPresence("node-b", user.ID, true, []UserIPView{{IP: "203.0.113.11"}}))
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 2)
	require.NoError(t, st.RecordUserPresence("node-b", user.ID, false, nil))
	views, err = st.ListUserViews("")
	require.NoError(t, err)
	require.True(t, views[0].Online)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.10", views[0].OnlineIPs[0].IP)
}

func TestUserPresenceSkipsLoopbackIPs(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "bob"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.RecordUserPresence("n1", user.ID, true, []UserIPView{
		{IP: "127.0.0.1"},
		{IP: "::1"},
		{IP: "203.0.113.50"},
	}))
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Len(t, views[0].OnlineIPs, 1)
	require.Equal(t, "203.0.113.50", views[0].OnlineIPs[0].IP)
}

func TestUpsertInboundEmptyListenFollowsStack(t *testing.T) {
	st := testDB(t)
	dual := &models.Inbound{
		NodeUUID:     "n1",
		Name:         "dual",
		Protocol:     "vless",
		Port:         443,
		Core:         models.CoreXray,
		SettingsJSON: `{"stack":"dual"}`,
	}
	require.NoError(t, st.UpsertInbound(dual))
	got, err := st.GetInbound(dual.ID)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0,::", got.Listen)

	ipv4 := &models.Inbound{
		NodeUUID:     "n1",
		Name:         "v4",
		Protocol:     "vless",
		Port:         8443,
		Core:         models.CoreXray,
		SettingsJSON: `{"stack":"ipv4"}`,
	}
	require.NoError(t, st.UpsertInbound(ipv4))
	got, err = st.GetInbound(ipv4.ID)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0", got.Listen)
}

func TestInboundCRUD(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "n1", Name: "in-a", Protocol: "vless", Port: 443, Core: models.CoreXray}
	require.NoError(t, st.UpsertInbound(in))
	list, err := st.ListInbounds("n1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.NoError(t, st.DeleteInbound(in.ID))
	list, err = st.ListInbounds("n1")
	require.NoError(t, err)
	require.Len(t, list, 0)
}

func TestDeleteInboundRemovesGrantsKeepsUser(t *testing.T) {
	st := testDB(t)
	keep := &models.Inbound{NodeUUID: "n1", Name: "keep", Protocol: "vless", Port: 1}
	drop := &models.Inbound{NodeUUID: "n1", Name: "drop", Protocol: "vless", Port: 2}
	require.NoError(t, st.UpsertInbound(keep))
	require.NoError(t, st.UpsertInbound(drop))
	alice := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	bob := &models.NodeUser{NodeUUID: "n1", Username: "bob"}
	require.NoError(t, st.UpsertUser(alice))
	require.NoError(t, st.UpsertUser(bob))
	require.NoError(t, st.ReplaceGrants(alice.ID, []string{keep.ID, drop.ID}))
	require.NoError(t, st.ReplaceGrants(bob.ID, []string{drop.ID}))
	require.NoError(t, st.DeleteInbound(drop.ID))

	users, err := st.ListUsers("n1")
	require.NoError(t, err)
	require.Len(t, users, 2)

	gKeep, err := st.ListGrants(alice.ID)
	require.NoError(t, err)
	require.Len(t, gKeep, 1)
	require.Equal(t, keep.ID, gKeep[0].InboundID)

	gDrop, err := st.ListGrants(bob.ID)
	require.NoError(t, err)
	require.Len(t, gDrop, 0)

	snap, err := st.NodeSnapshot("n1")
	require.NoError(t, err)
	snapUsers := snap["users"].([]snapshotUser)
	byName := map[string]snapshotUser{}
	for _, u := range snapUsers {
		byName[u.Username] = u
	}
	require.Equal(t, []string{keep.ID}, byName["alice"].InboundIDs)
	require.Empty(t, byName["bob"].InboundIDs)
}

func TestPruneOrphanGrantsOnMigrateKeepsUser(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "n1", Name: "in", Protocol: "vless", Port: 1}
	require.NoError(t, st.UpsertInbound(in))
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{in.ID, "dead-inbound"}))
	require.NoError(t, st.Migrate())
	grants, err := st.ListGrants(user.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, in.ID, grants[0].InboundID)
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, "alice", got.Username)
}

func TestDeleteNodeKeepsUserGrantedOnOtherNode(t *testing.T) {
	st := testDB(t)
	goneIn := &models.Inbound{NodeUUID: "gone", Name: "gone-in", Protocol: "vless", Port: 1}
	keepIn := &models.Inbound{NodeUUID: "keep", Name: "keep-in", Protocol: "vless", Port: 2}
	require.NoError(t, st.UpsertInbound(goneIn))
	require.NoError(t, st.UpsertInbound(keepIn))
	shared := &models.NodeUser{NodeUUID: "gone", Username: "alice"}
	onlyGone := &models.NodeUser{NodeUUID: "gone", Username: "bob"}
	require.NoError(t, st.UpsertUser(shared))
	require.NoError(t, st.UpsertUser(onlyGone))
	require.NoError(t, st.ReplaceGrants(shared.ID, []string{goneIn.ID, keepIn.ID}))
	require.NoError(t, st.ReplaceGrants(onlyGone.ID, []string{goneIn.ID}))
	require.NoError(t, st.DeleteNode("gone"))

	_, err := st.GetUser(onlyGone.ID)
	require.ErrorIs(t, err, ErrNotFound)
	got, err := st.GetUser(shared.ID)
	require.NoError(t, err)
	require.Equal(t, "keep", got.NodeUUID)
	grants, err := st.ListGrants(shared.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, keepIn.ID, grants[0].InboundID)
}

func TestDeleteNodeRemovesInboundOutboundUserAndCert(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "gone", Name: "in-a", Protocol: "vless", Port: 443}
	require.NoError(t, st.UpsertInbound(in))
	keep := &models.Inbound{NodeUUID: "keep", Name: "keep", Protocol: "vless", Port: 80}
	require.NoError(t, st.UpsertInbound(keep))
	out := &models.Outbound{NodeUUID: "gone", Name: "exit-a", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(out))
	user := &models.NodeUser{NodeUUID: "gone", Username: "bob"}
	require.NoError(t, st.UpsertUser(user))
	_, _, err := st.IssueCredential(user.ID, "password", "s3cret", nil)
	require.NoError(t, err)
	require.NoError(t, st.UpsertCert(&models.Certificate{NodeUUID: "gone", Domain: "gone.example", Source: models.CertSourceFile, CertPath: "./a.crt", KeyPath: "./a.key"}))
	_, err = st.UpsertNodeProfile("gone", "prefer_ipv4")
	require.NoError(t, err)
	require.NoError(t, st.DeleteNode("gone"))
	goneIn, err := st.ListInbounds("gone")
	require.NoError(t, err)
	require.Len(t, goneIn, 0)
	keepIn, err := st.ListInbounds("keep")
	require.NoError(t, err)
	require.Len(t, keepIn, 1)
	goneOut, err := st.ListOutbounds("gone")
	require.NoError(t, err)
	require.Len(t, goneOut, 0)
	goneUsers, err := st.ListUsers("gone")
	require.NoError(t, err)
	require.Len(t, goneUsers, 0)
	goneCerts, err := st.ListCerts("gone")
	require.NoError(t, err)
	require.Len(t, goneCerts, 0)
	_, err = st.GetNodeProfile("gone")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestPurgeMissingNodesLeavesLiveClients(t *testing.T) {
	st := testDB(t)
	require.NoError(t, st.DB().Exec(`CREATE TABLE clients (uuid TEXT PRIMARY KEY)`).Error)
	require.NoError(t, st.DB().Exec(`INSERT INTO clients (uuid) VALUES ('live')`).Error)
	require.NoError(t, st.UpsertInbound(&models.Inbound{NodeUUID: "live", Name: "ok", Protocol: "vless", Port: 1}))
	require.NoError(t, st.UpsertInbound(&models.Inbound{NodeUUID: "dead", Name: "old", Protocol: "vless", Port: 2}))
	require.NoError(t, st.PurgeMissingNodes())
	live, err := st.ListInbounds("live")
	require.NoError(t, err)
	require.Len(t, live, 1)
	dead, err := st.ListInbounds("dead")
	require.NoError(t, err)
	require.Len(t, dead, 0)
}

func TestCredentialHashIndependentOfAdmin(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	cred, secret, err := st.IssueCredential(user.ID, "password", "s3cret", nil)
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.True(t, MatchSecret(cred.SecretHash, "s3cret"))
	require.False(t, MatchSecret(cred.SecretHash, "wrong"))
	_, rotated, err := st.RotateCredential(cred.ID)
	require.NoError(t, err)
	require.False(t, MatchSecret(cred.SecretHash, rotated))
	require.NoError(t, st.RevokeCredential(cred.ID))
	list, err := st.ListCredentials(user.ID)
	require.NoError(t, err)
	require.False(t, list[0].Enabled)
}

func TestReplaceGrantsAndUserView(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "n1", Name: "vless-443", Protocol: "vless", Port: 443, Core: models.CoreXray}
	require.NoError(t, st.UpsertInbound(in))
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30}
	require.NoError(t, st.UpsertPlan(plan))
	require.NoError(t, st.SaveAssignment(&models.Assignment{UserID: user.ID, PlanID: plan.ID, TrafficBytes: 1000}))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{in.ID, in.ID}))
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, []string{in.ID}, views[0].InboundIDs)
	require.Equal(t, "std", views[0].PlanName)
	require.Equal(t, []string{"vless-443"}, views[0].InboundNames)
}

func TestAssignedPlanRateOverridesUserRate(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "n1", Name: "vless-443", Protocol: "vless", Port: 443, Core: models.CoreXray}
	require.NoError(t, st.UpsertInbound(in))
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice", RateLimitBps: 999}
	require.NoError(t, st.UpsertUser(user))
	plan := &models.Plan{Name: "std", TrafficBytes: 1000, DurationDays: 30, RateLimitBps: 256000}
	require.NoError(t, st.UpsertPlan(plan))
	future := time.Now().UTC().Add(24 * time.Hour)
	require.NoError(t, st.SaveAssignment(&models.Assignment{UserID: user.ID, PlanID: plan.ID, EndsAt: &future, TrafficBytes: 1000, RateLimitBps: 256000, OperationID: "op-active"}))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{in.ID}))

	// Explicit positive user.RateLimitBps overrides plan.RateLimitBps.
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, int64(999), views[0].RateLimitBps)
	snap, err := st.NodeSnapshot("n1")
	require.NoError(t, err)
	users := snap["users"].([]snapshotUser)
	require.Len(t, users, 1)
	require.Equal(t, int64(999), users[0].RateLimitBps)

	// When user.RateLimitBps <= 0, active assignment falls back to plan.RateLimitBps.
	user.RateLimitBps = 0
	require.NoError(t, st.UpsertUser(user))
	views, err = st.ListUserViews("")
	require.NoError(t, err)
	require.Equal(t, int64(256000), views[0].RateLimitBps)
	snap, err = st.NodeSnapshot("n1")
	require.NoError(t, err)
	users = snap["users"].([]snapshotUser)
	require.Equal(t, int64(256000), users[0].RateLimitBps)

	// Expired assignment does not apply plan.RateLimitBps.
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, st.DeleteAssignments(user.ID))
	require.NoError(t, st.SaveAssignment(&models.Assignment{UserID: user.ID, PlanID: plan.ID, EndsAt: &past, TrafficBytes: 1000, RateLimitBps: 256000, OperationID: "op-expired"}))
	views, err = st.ListUserViews("")
	require.NoError(t, err)
	require.Equal(t, int64(0), views[0].RateLimitBps)
	snap, err = st.NodeSnapshot("n1")
	require.NoError(t, err)
	users = snap["users"].([]snapshotUser)
	require.Equal(t, int64(0), users[0].RateLimitBps)
}

func TestNodeSnapshotScopesGrantsAndProtocolSecrets(t *testing.T) {
	st := testDB(t)
	inA := &models.Inbound{NodeUUID: "n1", Name: "a", Protocol: "vless", Port: 1}
	inB := &models.Inbound{NodeUUID: "n1", Name: "b", Protocol: "vless", Port: 2}
	inC := &models.Inbound{NodeUUID: "n2", Name: "c", Protocol: "vless", Port: 3}
	require.NoError(t, st.UpsertInbound(inA))
	require.NoError(t, st.UpsertInbound(inB))
	require.NoError(t, st.UpsertInbound(inC))
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	_, secret, err := st.IssueCredential(user.ID, "uuid", "", nil)
	require.NoError(t, err)
	require.NoError(t, st.ReplaceGrants(user.ID, []string{inA.ID, inC.ID}))
	require.NoError(t, st.AddUserUsage("n1", user.ID, "batch-42", 128))
	snap, err := st.NodeSnapshot("n1")
	require.NoError(t, err)
	require.Equal(t, "n1", snap["node_uuid"])
	require.Contains(t, snap["acked_usage_ops"].([]string), UsageDedupOpID("n1", "batch-42", user.ID))
	users := snap["users"].([]snapshotUser)
	require.Len(t, users, 1)
	require.Equal(t, []string{inA.ID}, users[0].InboundIDs)
	require.Len(t, users[0].Credentials, 1)
	require.Equal(t, secret, users[0].Credentials[0].Secret)
	require.Equal(t, secret, users[0].Credentials[0].UUID)
	snap2, err := st.NodeSnapshot("n2")
	require.NoError(t, err)
	users2 := snap2["users"].([]snapshotUser)
	require.Len(t, users2, 1)
	require.Equal(t, []string{inC.ID}, users2[0].InboundIDs)
	nodes, err := st.NodeIDsForUser(user.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"n1", "n2"}, nodes)
}

func TestNodeSnapshotForcesRealitySniffRouteOnly(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{
		NodeUUID:     "n1",
		Name:         "r",
		Protocol:     "vless",
		Port:         443,
		SettingsJSON: `{"sniffing":true,"security":"reality","flow":"xtls-rprx-vision","dest_override":"http,tls,quic"}`,
	}
	require.NoError(t, st.UpsertInbound(in))
	snap, err := st.NodeSnapshot("n1")
	require.NoError(t, err)
	rows := snap["inbounds"].([]models.Inbound)
	require.Len(t, rows, 1)
	require.Contains(t, rows[0].SettingsJSON, `"route_only":true`)
	stored, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.NotContains(t, stored.SettingsJSON, `"route_only":true`)
}

func TestSaveUserProfileKeepsQuotaUsageExpiry(t *testing.T) {
	st := testDB(t)
	expires := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	user := &models.NodeUser{
		NodeUUID:     "n1",
		Username:     "alice",
		DisplayName:  "Alice",
		QuotaBytes:   1000,
		UsedBytes:    500,
		ExpiresAt:    &expires,
		SharedPoolID: "pool-1",
		Status:       models.UserDisabled,
	}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.SaveUserProfile(&models.NodeUser{
		ID:           user.ID,
		Username:     "alice2",
		DisplayName:  "Alice Two",
		Flow:         "xtls-rprx-vision",
		RateLimitBps: 128000,
		DeviceLimit:  3,
		Status:       models.UserActive,
		NodeUUID:     "n2",
	}))
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, "alice2", got.Username)
	require.Equal(t, "Alice Two", got.DisplayName)
	require.Equal(t, "xtls-rprx-vision", got.Flow)
	require.Equal(t, int64(128000), got.RateLimitBps)
	require.Equal(t, 3, got.DeviceLimit)
	require.Equal(t, models.UserActive, got.Status)
	require.Equal(t, "n2", got.NodeUUID)
	require.Equal(t, int64(1000), got.QuotaBytes)
	require.Equal(t, int64(500), got.UsedBytes)
	require.Equal(t, "pool-1", got.SharedPoolID)
	require.NotNil(t, got.ExpiresAt)
	require.True(t, got.ExpiresAt.Equal(expires))
}

func TestSetUserExpiryAndResetAndMonthlyClear(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice", QuotaBytes: 1000, UsedBytes: 500}
	require.NoError(t, st.UpsertUser(user))
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, st.SetUserExpiryAndReset(user.ID, &expires, 15, now))
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.NotNil(t, got.ExpiresAt)
	require.True(t, got.ExpiresAt.Equal(expires))
	require.Equal(t, 15, got.TrafficResetDay)
	require.Equal(t, int64(500), got.UsedBytes)
	require.Equal(t, "2026-10-15", got.TrafficResetCycle)
	got.TrafficResetCycle = "2026-09-15"
	require.NoError(t, st.DB().Save(got).Error)
	ids, err := st.ApplyDueTrafficResets(now)
	require.NoError(t, err)
	require.Equal(t, []string{user.ID}, ids)
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.UsedBytes)
	require.Equal(t, "2026-10-15", got.TrafficResetCycle)
	require.NoError(t, st.SetUserExpiryAndReset(user.ID, nil, 0, now))
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Nil(t, got.ExpiresAt)
	require.Equal(t, 0, got.TrafficResetDay)
}

func TestSetUserExpiryAndResetKeepsCycleAcrossBoundary(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice", QuotaBytes: 1000, UsedBytes: 500}
	require.NoError(t, st.UpsertUser(user))
	before := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	after := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.SetUserExpiryAndReset(user.ID, nil, 15, before))
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, "2026-09-15", got.TrafficResetCycle)
	require.NoError(t, st.SaveUserProfile(&models.NodeUser{ID: user.ID, Username: "alice2", NodeUUID: "n1"}))
	require.NoError(t, st.SetUserExpiryAndReset(user.ID, nil, 15, after))
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, "alice2", got.Username)
	require.Equal(t, int64(500), got.UsedBytes)
	require.Equal(t, "2026-09-15", got.TrafficResetCycle)
	ok, err := st.ApplyUserTrafficReset(user.ID, after)
	require.NoError(t, err)
	require.True(t, ok)
	got, err = st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.UsedBytes)
	require.Equal(t, "2026-10-15", got.TrafficResetCycle)
	ok, err = st.ApplyUserTrafficReset(user.ID, after)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDeviceLimitZeroMeansUnlimited(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "bob", DeviceLimit: 0}
	require.NoError(t, st.UpsertUser(user))
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, 0, got.DeviceLimit)
	plan := &models.Plan{Name: "open", DeviceLimit: 0}
	require.NoError(t, st.UpsertPlan(plan))
	saved, err := st.GetPlan(plan.ID)
	require.NoError(t, err)
	require.Equal(t, 0, saved.DeviceLimit)
}

func TestInboundSortAndSubscriptionEnsure(t *testing.T) {
	st := testDB(t)
	a := &models.Inbound{NodeUUID: "n1", Name: "a", Protocol: "vless", Port: 1, SortIndex: 2}
	b := &models.Inbound{NodeUUID: "n1", Name: "b", Protocol: "vless", Port: 2, SortIndex: 1}
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	list, err := st.ListInbounds("n1")
	require.NoError(t, err)
	require.Equal(t, []string{"b", "a"}, []string{list[0].Name, list[1].Name})
	require.NoError(t, st.ReorderInbounds("n1", []string{a.ID, b.ID}))
	list, err = st.ListInbounds("n1")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, []string{list[0].Name, list[1].Name})
	user := &models.NodeUser{NodeUUID: "n1", Username: "carol"}
	require.NoError(t, st.UpsertUser(user))
	first, err := st.EnsureSubscription(user.ID)
	require.NoError(t, err)
	again, err := st.EnsureSubscription(user.ID)
	require.NoError(t, err)
	require.Equal(t, first.ID, again.ID)
	require.NotEmpty(t, first.Token)
	require.Equal(t, "xray", first.Format)
}

func TestNextInboundSortIndexAppendsGlobally(t *testing.T) {
	st := testDB(t)
	a := &models.Inbound{NodeUUID: "n1", Name: "a", Protocol: "vless", Port: 1, SortIndex: 1}
	b := &models.Inbound{NodeUUID: "n2", Name: "b", Protocol: "vless", Port: 2, SortIndex: 4}
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	require.Equal(t, 5, st.NextInboundSortIndex(""))
	require.Equal(t, 2, st.NextInboundSortIndex("n1"))
}

func TestReorderInboundsAcrossNodes(t *testing.T) {
	st := testDB(t)
	a := &models.Inbound{NodeUUID: "n1", Name: "a", Protocol: "vless", Port: 1, SortIndex: 1}
	b := &models.Inbound{NodeUUID: "n2", Name: "b", Protocol: "vless", Port: 2, SortIndex: 2}
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	require.NoError(t, st.ReorderInbounds("", []string{b.ID, a.ID}))
	list, err := st.ListInbounds("")
	require.NoError(t, err)
	require.Equal(t, []string{"b", "a"}, []string{list[0].Name, list[1].Name})
	require.Equal(t, 1, list[0].SortIndex)
	require.Equal(t, 2, list[1].SortIndex)
}

func TestUpsertOutboundRejectsDuplicateTagOnSameNode(t *testing.T) {
	st := testDB(t)
	first := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "vless", Enabled: true}
	require.NoError(t, st.UpsertOutbound(first))
	dup := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "vless", Enabled: true}
	require.ErrorIs(t, st.UpsertOutbound(dup), ErrConflict)
	otherNode := &models.Outbound{NodeUUID: "n2", Name: "exit-a", Protocol: "vless", Enabled: true}
	require.NoError(t, st.UpsertOutbound(otherNode))
	first.Protocol = "socks"
	require.NoError(t, st.UpsertOutbound(first))
	require.ErrorIs(t, st.UpsertOutbound(&models.Outbound{NodeUUID: "n1", Name: "direct", Protocol: "freedom"}), ErrInvalid)
	require.ErrorIs(t, st.UpsertOutbound(&models.Outbound{NodeUUID: "n1", Name: "block", Protocol: "blackhole"}), ErrInvalid)
}

func TestDeleteOutboundRemovesReferencingRoutes(t *testing.T) {
	st := testDB(t)
	out := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(out))
	keep := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(keep))
	hit := &models.Route{NodeUUID: "n1", Name: "route-1", Enabled: true, RuleJSON: `{"inbound_id":"in1","outbound_id":"` + out.ID + `"}`}
	other := &models.Route{NodeUUID: "n1", Name: "route-2", Enabled: true, RuleJSON: `{"inbound_id":"in1","outbound_id":"` + keep.ID + `"}`}
	builtin := &models.Route{NodeUUID: "n1", Name: "route-direct", Enabled: true, RuleJSON: `{"inbound_id":"in1","outbound_id":"direct"}`}
	require.NoError(t, st.UpsertRoute(hit))
	require.NoError(t, st.UpsertRoute(other))
	require.NoError(t, st.UpsertRoute(builtin))
	require.NoError(t, st.DeleteOutbound(out.ID))
	_, err := st.GetOutbound(out.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = st.GetRoute(hit.ID)
	require.ErrorIs(t, err, ErrNotFound)
	got, err := st.GetRoute(other.ID)
	require.NoError(t, err)
	require.Equal(t, "route-2", got.Name)
	got, err = st.GetRoute(builtin.ID)
	require.NoError(t, err)
	require.Equal(t, "route-direct", got.Name)
}

func TestControlCommandIdempotent(t *testing.T) {
	st := testDB(t)
	cmd := &models.ControlCommand{OperationID: "op-1", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(cmd))
	require.NoError(t, st.EnqueueCommand(cmd))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, st.AckCommand("op-1", models.CmdApplied, ""))
	pending, err = st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 0)
}

func TestMarkCommandSentAndLatest(t *testing.T) {
	st := testDB(t)
	first := &models.ControlCommand{OperationID: "op-a", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(first))
	require.NoError(t, st.MarkCommandSent("op-a"))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 0)
	second := &models.ControlCommand{OperationID: "op-b", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: `{"rev":2}`}
	require.NoError(t, st.EnqueueCommand(second))
	latest, err := st.LatestCommands()
	require.NoError(t, err)
	require.Len(t, latest, 1)
	require.Equal(t, "op-b", latest[0].OperationID)
	require.Empty(t, latest[0].PayloadJSON)
	require.NoError(t, st.AckCommand("op-a", models.CmdApplied, ""))
	latest, err = st.LatestCommands()
	require.NoError(t, err)
	require.Len(t, latest, 1)
	require.Equal(t, "op-b", latest[0].OperationID)
}

func TestUpsertCertDefaultsAutoRenew(t *testing.T) {
	st := testDB(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "due.example"}
	require.NoError(t, st.UpsertCert(row))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.True(t, got.AutoRenew)
	got.AutoRenew = false
	require.NoError(t, st.UpsertCert(got))
	off, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.False(t, off.AutoRenew)
}

func TestMultipleRootCertificates(t *testing.T) {
	st := testDB(t)
	a := &models.RootCertificate{Domain: "abc.com", Status: models.CertIssued}
	b := &models.RootCertificate{Domain: "xyz.com", Status: models.CertIssued}
	require.NoError(t, st.UpsertRootCert(a))
	require.NoError(t, st.UpsertRootCert(b))
	require.True(t, a.AutoRenew)
	require.True(t, b.AutoRenew)
	rows, err := st.ListRootCerts()
	require.NoError(t, err)
	require.Len(t, rows, 2)
}

func TestUpsertFileCertKeepsEmptyIssuer(t *testing.T) {
	st := testDB(t)
	row := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "panel.example",
		Source:   models.CertSourceFile,
		CertPath: "/opt/1panel/ssl/fullchain.pem",
		KeyPath:  "/opt/1panel/ssl/privkey.pem",
	}
	require.NoError(t, st.UpsertCert(row))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertSourceFile, got.Source)
	require.Equal(t, "/opt/1panel/ssl/fullchain.pem", got.CertPath)
	require.Equal(t, "/opt/1panel/ssl/privkey.pem", got.KeyPath)
	require.Empty(t, got.Issuer)
}

func TestUserExtraLinksReplaceListAndDelete(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.ReplaceUserExtraLinks(user.ID, []models.UserExtraLink{
		{Kind: models.ExtraLinkKindLink, Value: "vless://u@host:443", Remark: "share", Enabled: true},
		{Kind: models.ExtraLinkKindSubscription, Value: "https://provider.example/sub", NamePrefix: "ext-", Enabled: true},
	}))
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Len(t, views[0].ExtraLinks, 2)
	require.Equal(t, models.ExtraLinkKindLink, views[0].ExtraLinks[0].Kind)
	require.Equal(t, "ext-", views[0].ExtraLinks[1].NamePrefix)
	require.NoError(t, st.ReplaceUserExtraLinks(user.ID, []models.UserExtraLink{
		{Kind: models.ExtraLinkKindLink, Value: "ss://abc@host:8388", Enabled: true},
	}))
	rows, err := st.ListUserExtraLinks(user.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "ss://abc@host:8388", rows[0].Value)
	require.NoError(t, st.DeleteUser(user.ID))
	_, err = st.ListUserExtraLinks(user.ID)
	require.NoError(t, err)
	left, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Empty(t, left)
}

func TestUserExtraLinksPersistDisabled(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "bob"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.ReplaceUserExtraLinks(user.ID, []models.UserExtraLink{
		{Kind: models.ExtraLinkKindLink, Value: "vless://off@host:443", Enabled: false},
		{Kind: models.ExtraLinkKindSubscription, Value: "https://provider.example/sub", Enabled: false},
	}))
	rows, err := st.ListUserExtraLinks(user.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.False(t, rows[0].Enabled)
	require.False(t, rows[1].Enabled)
	id := rows[0].ID
	require.NoError(t, st.ReplaceUserExtraLinks(user.ID, []models.UserExtraLink{
		{ID: id, Kind: models.ExtraLinkKindLink, Value: "vless://off@host:443", Enabled: true},
	}))
	rows, err = st.ListUserExtraLinks(user.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.True(t, rows[0].Enabled)
	require.Equal(t, id, rows[0].ID)
	require.NoError(t, st.ReplaceUserExtraLinks(user.ID, []models.UserExtraLink{
		{ID: id, Kind: models.ExtraLinkKindLink, Value: "vless://off@host:443", Enabled: false},
	}))
	rows, err = st.ListUserExtraLinks(user.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.False(t, rows[0].Enabled)
	require.Equal(t, id, rows[0].ID)
}

func TestReplaceGrantsDoesNotAffectOtherUsers(t *testing.T) {
	st := testDB(t)
	inA := &models.Inbound{NodeUUID: "n1", Name: "a", Protocol: "vless", Port: 1}
	inB := &models.Inbound{NodeUUID: "n1", Name: "b", Protocol: "vless", Port: 2}
	require.NoError(t, st.UpsertInbound(inA))
	require.NoError(t, st.UpsertInbound(inB))
	u1 := &models.NodeUser{NodeUUID: "n1", Username: "one"}
	u2 := &models.NodeUser{NodeUUID: "n1", Username: "two"}
	require.NoError(t, st.UpsertUser(u1))
	require.NoError(t, st.UpsertUser(u2))
	require.NoError(t, st.ReplaceGrants(u1.ID, []string{inA.ID}))
	require.NoError(t, st.ReplaceGrants(u2.ID, []string{inB.ID}))
	require.NoError(t, st.ReplaceGrants(u1.ID, []string{inA.ID, inB.ID}))
	g2, err := st.ListGrants(u2.ID)
	require.NoError(t, err)
	require.Len(t, g2, 1)
	require.Equal(t, inB.ID, g2[0].InboundID)
	g1, err := st.ListGrants(u1.ID)
	require.NoError(t, err)
	require.Len(t, g1, 2)
}

func TestGetUserViewMatchesList(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "view-one"}
	require.NoError(t, st.UpsertUser(user))
	in := &models.Inbound{NodeUUID: "n1", Name: "in-a", Protocol: "vless", Listen: "0.0.0.0", Port: 443}
	require.NoError(t, st.UpsertInbound(in))
	require.NoError(t, st.ReplaceGrants(user.ID, []string{in.ID}))
	got, err := st.GetUserView(user.ID)
	require.NoError(t, err)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, views[0].ID, got.ID)
	require.Equal(t, views[0].InboundIDs, got.InboundIDs)
	require.Equal(t, views[0].InboundNames, got.InboundNames)
}

func TestUpsertOutboundAndRouteKeepCreatedAtOrder(t *testing.T) {
	st := testDB(t)
	first := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	second := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(first))
	require.NoError(t, st.UpsertOutbound(second))
	created := first.CreatedAt
	first.Enabled = false
	first.CreatedAt = time.Time{}
	require.NoError(t, st.UpsertOutbound(first))
	list, err := st.ListOutbounds("n1")
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, first.ID, list[0].ID)
	require.False(t, list[0].Enabled)
	require.Equal(t, created.Unix(), list[0].CreatedAt.Unix())
	require.Equal(t, second.ID, list[1].ID)

	r1 := &models.Route{NodeUUID: "n1", Name: "r1", Enabled: true, RuleJSON: `{"outbound_id":"direct"}`}
	r2 := &models.Route{NodeUUID: "n1", Name: "r2", Enabled: true, RuleJSON: `{"outbound_id":"direct"}`}
	require.NoError(t, st.UpsertRoute(r1))
	require.NoError(t, st.UpsertRoute(r2))
	routeCreated := r1.CreatedAt
	r1.Enabled = false
	r1.CreatedAt = time.Time{}
	require.NoError(t, st.UpsertRoute(r1))
	routes, err := st.ListRoutes("n1")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(routes), 2)
	require.Equal(t, r1.ID, routes[0].ID)
	require.False(t, routes[0].Enabled)
	require.Equal(t, routeCreated.Unix(), routes[0].CreatedAt.Unix())
}

func TestUpsertUserKeepsCreatedAt(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	created := user.CreatedAt
	user.Status = models.UserDisabled
	user.CreatedAt = time.Time{}
	require.NoError(t, st.UpsertUser(user))
	got, err := st.GetUser(user.ID)
	require.NoError(t, err)
	require.Equal(t, models.UserDisabled, got.Status)
	require.Equal(t, created.Unix(), got.CreatedAt.Unix())
}

func TestUpsertRouteDoesNotMutateSiblings(t *testing.T) {
	st := testDB(t)
	keep := &models.Route{NodeUUID: "n1", Name: "keep-on", Enabled: true, RuleJSON: `{"inbound_id":"in-a","outbound_id":"direct"}`}
	off := &models.Route{NodeUUID: "n1", Name: "turn-off", Enabled: true, RuleJSON: `{"inbound_id":"in-b","outbound_id":"direct"}`}
	require.NoError(t, st.UpsertRoute(keep))
	require.NoError(t, st.UpsertRoute(off))
	off.Enabled = false
	require.NoError(t, st.UpsertRoute(off))
	savedOff, err := st.GetRoute(off.ID)
	require.NoError(t, err)
	require.False(t, savedOff.Enabled)
	savedKeep, err := st.GetRoute(keep.ID)
	require.NoError(t, err)
	require.True(t, savedKeep.Enabled)
	require.Equal(t, "keep-on", savedKeep.Name)
	require.Contains(t, savedKeep.RuleJSON, "in-a")
}

func TestUpsertInboundKeepsExplicitDisabled(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{NodeUUID: "n1", Name: "off", Protocol: "vless", Port: 443, Enabled: false}
	require.NoError(t, st.UpsertInbound(in))
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)
	in.Enabled = true
	require.NoError(t, st.UpsertInbound(in))
	got, err = st.GetInbound(in.ID)
	require.NoError(t, err)
	require.True(t, got.Enabled)
	in.Enabled = false
	require.NoError(t, st.UpsertInbound(in))
	got, err = st.GetInbound(in.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)
	ob := &models.Outbound{NodeUUID: "n1", Name: "ob-off", Protocol: "freedom", Enabled: false}
	require.NoError(t, st.UpsertOutbound(ob))
	savedOb, err := st.GetOutbound(ob.ID)
	require.NoError(t, err)
	require.False(t, savedOb.Enabled)
	rt := &models.Route{NodeUUID: "n1", Name: "rt-off", Enabled: false}
	require.NoError(t, st.UpsertRoute(rt))
	savedRt, err := st.GetRoute(rt.ID)
	require.NoError(t, err)
	require.False(t, savedRt.Enabled)
}

func TestDeleteCertRejectsInboundReference(t *testing.T) {
	st := testDB(t)
	cert := &models.Certificate{NodeUUID: "n1", Domain: "tls.example", Source: models.CertSourceFile, Status: models.CertIssued, CertPath: "./a.crt", KeyPath: "./a.key"}
	require.NoError(t, st.UpsertCert(cert))
	in := &models.Inbound{NodeUUID: "n1", Name: "tls", Protocol: "vless", Port: 443, SettingsJSON: `{"cert_id":"` + cert.ID + `","security":"tls"}`}
	require.NoError(t, st.UpsertInbound(in))
	err := st.DeleteCert(cert.ID)
	require.ErrorIs(t, err, ErrConflict)
	_, err = st.GetCert(cert.ID)
	require.NoError(t, err)
	require.NoError(t, st.DeleteInbound(in.ID))
	require.NoError(t, st.DeleteCert(cert.ID))
}

func TestNodeDialStackPersistsInSnapshot(t *testing.T) {
	st := testDB(t)
	require.Equal(t, DialStackDual, st.NodeDialStack("n1"))
	row, err := st.UpsertNodeProfile("n1", "prefer_ipv6")
	require.NoError(t, err)
	require.Equal(t, DialStackPreferIPv6, row.DialStack)
	require.Equal(t, DialStackPreferIPv6, st.NodeDialStack("n1"))
	snap, err := st.NodeSnapshot("n1")
	require.NoError(t, err)
	require.Equal(t, DialStackPreferIPv6, snap["dial_stack"])
	require.Equal(t, DialStackDual, st.NodeDialStack("missing"))
}

func TestInboundAndOutboundSecretsEncryptedAtRestAndDeleteUserCleansLedger(t *testing.T) {
	st := testDB(t)
	in := &models.Inbound{
		NodeUUID:     "n1",
		Name:         "secret-in",
		Protocol:     "http",
		Port:         8080,
		SettingsJSON: `{"reality_private_key":"rk-plain","ss_password":"ss-plain","accounts":[{"user":"u1","pass":"p-plain"}]}`,
		StreamJSON:   `{"realitySettings":{"privateKey":"rk-stream-plain"}}`,
	}
	require.NoError(t, st.UpsertInbound(in))

	var rawIn models.Inbound
	require.NoError(t, st.DB().First(&rawIn, "id = ?", in.ID).Error)
	require.NotContains(t, rawIn.SettingsJSON, "rk-plain")
	require.NotContains(t, rawIn.SettingsJSON, "ss-plain")
	require.NotContains(t, rawIn.SettingsJSON, "p-plain")
	require.NotContains(t, rawIn.StreamJSON, "rk-stream-plain")
	require.Contains(t, rawIn.SettingsJSON, "enc:v1:")

	loadedIn, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.Contains(t, loadedIn.SettingsJSON, "rk-plain")
	require.Contains(t, loadedIn.SettingsJSON, "ss-plain")
	require.Contains(t, loadedIn.SettingsJSON, "p-plain")
	require.Contains(t, loadedIn.StreamJSON, "rk-stream-plain")

	ob := &models.Outbound{
		NodeUUID:     "n1",
		Name:         "secret-out",
		Protocol:     "trojan",
		SettingsJSON: `{"address":"1.2.3.4","port":443,"password":"ob-secret-pass"}`,
	}
	require.NoError(t, st.UpsertOutbound(ob))

	var rawOb models.Outbound
	require.NoError(t, st.DB().First(&rawOb, "id = ?", ob.ID).Error)
	require.NotContains(t, rawOb.SettingsJSON, "ob-secret-pass")
	require.Contains(t, rawOb.SettingsJSON, "enc:v1:")

	loadedOb, err := st.GetOutbound(ob.ID)
	require.NoError(t, err)
	require.Contains(t, loadedOb.SettingsJSON, "ob-secret-pass")

	user := &models.NodeUser{NodeUUID: "n1", Username: "ledger-user"}
	require.NoError(t, st.UpsertUser(user))
	require.NoError(t, st.AddLedger(user.ID, "topup", "op-1", 1024))
	require.NoError(t, st.DeleteUser(user.ID))

	var ledgerCount int64
	require.NoError(t, st.DB().Model(&models.QuotaLedger{}).Where("user_id = ?", user.ID).Count(&ledgerCount).Error)
	require.Zero(t, ledgerCount)
}

func TestSecretcryptFailureErrorsInsteadOfCorruptingOrLeaking(t *testing.T) {
	st := testDB(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "sub-user"}
	require.NoError(t, st.UpsertUser(user))
	subRow, err := st.EnsureSubscription(user.ID)
	require.NoError(t, err)
	origHash := subRow.TokenHash

	badSub := *subRow
	badSub.Token = "enc:v1:corrupted-ciphertext"
	require.Error(t, st.UpsertSubscription(&badSub))

	var checkSub models.Subscription
	require.NoError(t, st.DB().First(&checkSub, "id = ?", subRow.ID).Error)
	require.Equal(t, origHash, checkSub.TokenHash)

	cred := &models.Credential{
		ID:             "cred-corrupt",
		UserID:         user.ID,
		Kind:           "trojan",
		SecretMaterial: "enc:v1:corrupted-ciphertext",
		Enabled:        true,
	}
	require.NoError(t, st.DB().Create(cred).Error)
	_, err = st.NodeSnapshot("n1")
	require.Error(t, err)
}

func TestLatestCommandsReturnsNewestPerNodeWithoutPayload(t *testing.T) {
	st := testDB(t)
	base := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)

	seed := []models.ControlCommand{
		// node-a: two commands with identical CreatedAt -> rowid DESC must pick a-second!
		{ID: "cmd-a-1", NodeUUID: "node-a", OperationID: "op-a-1", Kind: "applyConfig", PayloadJSON: `{"big":"payload-a1"}`, Status: models.CmdApplied, CreatedAt: base, UpdatedAt: base},
		{ID: "cmd-a-2", NodeUUID: "node-a", OperationID: "op-a-2", Kind: "syncQuota", PayloadJSON: `{"big":"payload-a2"}`, Status: models.CmdSent, CreatedAt: base, UpdatedAt: base},
		// node-b: newer CreatedAt wins over older row.
		{ID: "cmd-b-1", NodeUUID: "node-b", OperationID: "op-b-1", Kind: "applyConfig", PayloadJSON: `{"big":"payload-b1"}`, Status: models.CmdSuperseded, CreatedAt: base.Add(-time.Minute), UpdatedAt: base},
		{ID: "cmd-b-2", NodeUUID: "node-b", OperationID: "op-b-2", Kind: "applyConfig", PayloadJSON: `{"big":"payload-b2"}`, Status: models.CmdFailed, LastError: "boom", CreatedAt: base.Add(2 * time.Minute), UpdatedAt: base.Add(2 * time.Minute)},
		// node-c: single command, oldest among winners.
		{ID: "cmd-c-1", NodeUUID: "node-c", OperationID: "op-c-1", Kind: "applyCert", PayloadJSON: `{"big":"payload-c1"}`, Status: models.CmdPending, CreatedAt: base.Add(-5 * time.Minute), UpdatedAt: base.Add(-5 * time.Minute)},
	}
	for i := range seed {
		require.NoError(t, st.DB().Create(&seed[i]).Error)
	}

	got, err := st.LatestCommands()
	require.NoError(t, err)
	require.Len(t, got, 3)

	// Ordered by created_at DESC, rowid DESC: node-b (base+2m), node-a (base, op-a-2), node-c (base-5m).
	require.Equal(t, "node-b", got[0].NodeUUID)
	require.Equal(t, "op-b-2", got[0].OperationID)
	require.Equal(t, models.CmdFailed, got[0].Status)
	require.Equal(t, "boom", got[0].LastError)
	require.Empty(t, got[0].PayloadJSON, "LatestCommands must omit PayloadJSON")

	require.Equal(t, "node-a", got[1].NodeUUID)
	require.Equal(t, "op-a-2", got[1].OperationID)
	require.Equal(t, models.CmdSent, got[1].Status)
	require.Empty(t, got[1].PayloadJSON, "LatestCommands must omit PayloadJSON")

	require.Equal(t, "node-c", got[2].NodeUUID)
	require.Equal(t, "op-c-1", got[2].OperationID)
	require.Equal(t, models.CmdPending, got[2].Status)
	require.Empty(t, got[2].PayloadJSON, "LatestCommands must omit PayloadJSON")
}
