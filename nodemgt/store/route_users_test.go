package store

import (
	"encoding/json"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/stretchr/testify/require"
)

func seedGrantedUsers(t *testing.T, st *Store, node, inboundID string, names ...string) []*models.NodeUser {
	t.Helper()
	out := make([]*models.NodeUser, 0, len(names))
	for _, name := range names {
		u := &models.NodeUser{NodeUUID: node, Username: name, Status: models.UserActive}
		require.NoError(t, st.UpsertUser(u))
		require.NoError(t, st.ReplaceGrants(u.ID, []string{inboundID}))
		out = append(out, u)
	}
	return out
}

func TestUpsertRouteStoresAndDedupsUserIDs(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice", "bob")
	out := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(out))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "by-user",
		Enabled:  true,
		Priority: 10,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + out.ID + `","user_ids":["` + users[0].ID + `","` + users[1].ID + `","` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, []string{users[0].ID, users[1].ID}, routeRuleUserIDs(got.RuleJSON))
}

func TestUpsertRouteEmptyUserIDsKeepsCatchAll(t *testing.T) {
	st := testDB(t)
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "all",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"in1","outbound_id":"direct"}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Empty(t, routeRuleUserIDs(got.RuleJSON))
	require.Contains(t, got.RuleJSON, `"inbound_id":"in1"`)
}

func TestUpsertRouteRejectsEmptyUserID(t *testing.T) {
	st := testDB(t)
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "bad",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"in1","outbound_id":"direct","user_ids":["u1",""]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "empty user id")
}

func TestUpsertRouteRejectsUserIDsWithoutInbound(t *testing.T) {
	st := testDB(t)
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "bad",
		Enabled:  true,
		RuleJSON: `{"outbound_id":"direct","user_ids":["u1"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "user_ids inbound required")
}

func TestUpsertRouteRejectsUngrantedUser(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	u := &models.NodeUser{NodeUUID: "n1", Username: "alice", Status: models.UserActive}
	require.NoError(t, st.UpsertUser(u))
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "bad",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + u.ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "user not granted")
}

func TestUpsertRouteRejectsMissingUser(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "bad",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["missing"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "user not found")
}

func TestUpsertRouteRejectsUnsupportedCoreProtocol(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "hysteria2", "a.example.com", 443)
	in.Core = models.CoreXray
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "bad",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "route_user_unsupported")
}

func TestUpsertRouteAllowsCrossNodeGrantedUser(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	u := &models.NodeUser{NodeUUID: "n2", Username: "visitor", Status: models.UserActive}
	require.NoError(t, st.UpsertUser(u))
	require.NoError(t, st.ReplaceGrants(u.ID, []string{in.ID}))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "visitor",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + u.ID + `"]}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, []string{u.ID}, routeRuleUserIDs(got.RuleJSON))
}

func TestRouteHAPreservesUserIDs(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	backup := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	require.NoError(t, st.UpsertOutbound(backup))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + primary.ID + `","strategy":"failover","backup_outbound_id":"` + backup.ID + `","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, []string{users[0].ID}, routeRuleUserIDs(got.RuleJSON))
	require.Equal(t, chainStrategyFailover, settingsString(got.RuleJSON, "strategy"))

	got.RuleJSON = `{"inbound_id":"` + in.ID + `","outbound_id":"` + primary.ID + `","strategy":"none","user_ids":["` + users[0].ID + `"]}`
	require.NoError(t, st.UpsertUserRoute(got))
	saved, err := st.GetRoute(got.ID)
	require.NoError(t, err)
	require.Equal(t, []string{users[0].ID}, routeRuleUserIDs(saved.RuleJSON))
	require.Equal(t, primary.ID, settingsString(saved.RuleJSON, "outbound_id"))
}

func TestUserRouteAllowedOnChainSource(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	users := seedGrantedUsers(t, st, "front", front.ID, "alice")
	row := &models.Route{
		NodeUUID: "front",
		Name:     "override",
		Enabled:  true,
		Priority: -10,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, []string{users[0].ID}, routeRuleUserIDs(got.RuleJSON))
}

func TestCatchAllStillRejectedOnChainSource(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(front))
	require.NoError(t, st.UpsertInbound(landing))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	err = st.UpsertRoute(&models.Route{
		NodeUUID: "front",
		Name:     "manual",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct"}`,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_in_use")
}

func TestForwardChainAllowsUserOverrideRoute(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	users := seedGrantedUsers(t, st, "front", front.ID, "alice")
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "front",
		Name:     "override",
		Enabled:  true,
		Priority: -10,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
}

func TestUserOverrideBlockedByChainFallbackPriority(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	users := seedGrantedUsers(t, st, "front", front.ID, "alice")
	err = st.UpsertRoute(&models.Route{
		NodeUUID: "front",
		Name:     "override",
		Enabled:  true,
		Priority: 10,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "chain_user_priority")
}

func TestBindChainRejectedWhenUserOverrideBehindFallback(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	users := seedGrantedUsers(t, st, "front", front.ID, "alice")
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "front",
		Name:     "override",
		Enabled:  true,
		Priority: 0,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "chain_user_priority")
}

func TestUserRouteRejectsMissingDisabledAndCoreMismatchOutbound(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	err := st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "missing-ob",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"no-such","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound required")

	off := &models.Outbound{NodeUUID: "n1", Name: "exit-off", Protocol: "freedom", Enabled: false}
	require.NoError(t, st.UpsertOutbound(off))
	err = st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "disabled-ob",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + off.ID + `","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound disabled")

	hy2 := &models.Outbound{NodeUUID: "n1", Name: "exit-hy2", Protocol: "hysteria2", Core: models.CoreSingBox, Enabled: true}
	require.NoError(t, st.UpsertOutbound(hy2))
	err = st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "core-mismatch",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + hy2.ID + `","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound core mismatch")

	other := &models.Outbound{NodeUUID: "n2", Name: "exit-other", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(other))
	err = st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "cross-node",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + other.ID + `","user_ids":["` + users[0].ID + `"]}`,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound required")
}

func TestInboundCoreChangeRejectsAnyTLSUserRoute(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	in.Core = models.CoreSingBox
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	exit := &models.Outbound{NodeUUID: "n1", Name: "exit-anytls", Protocol: "anytls", Core: models.CoreSingBox, Enabled: true}
	require.NoError(t, st.UpsertOutbound(exit))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "by-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + exit.ID + `","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	in.Core = models.CoreXray
	err := st.UpsertInbound(in)
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound core mismatch")
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.Equal(t, models.CoreSingBox, got.Core)
	saved, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.True(t, saved.Enabled)
	require.Equal(t, exit.ID, routeRuleOutboundID(saved.RuleJSON))
	require.Equal(t, []string{users[0].ID}, routeRuleUserIDs(saved.RuleJSON))
}

func TestInboundCoreChangeRejectsAnyTLSBackup(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	in.Core = models.CoreSingBox
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	backup := &models.Outbound{NodeUUID: "n1", Name: "exit-anytls", Protocol: "anytls", Core: models.CoreSingBox, Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	require.NoError(t, st.UpsertOutbound(backup))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"` + primary.ID + `","strategy":"failover","backup_outbound_id":"` + backup.ID + `","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	in.Core = models.CoreXray
	err := st.UpsertInbound(in)
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "outbound core mismatch")
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.Equal(t, models.CoreSingBox, got.Core)
}

func TestInboundCoreChangeAllowsDirectUserRoute(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	in.Core = models.CoreSingBox
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "direct-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}))
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "block-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"block","user_ids":["` + users[0].ID + `"]}`,
	}))
	in.Core = models.CoreXray
	require.NoError(t, st.UpsertInbound(in))
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.Equal(t, models.CoreXray, got.Core)
}

func TestInboundCoreChangeSkipsDisabledAndOtherInboundAnyTLS(t *testing.T) {
	st := testDB(t)
	inA := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	inA.Core = models.CoreSingBox
	inB := testInbound("n1", "in-b", "vless", "b.example.com", 8443)
	inB.Core = models.CoreSingBox
	require.NoError(t, st.UpsertInbound(inA))
	require.NoError(t, st.UpsertInbound(inB))
	usersA := seedGrantedUsers(t, st, "n1", inA.ID, "alice")
	usersB := seedGrantedUsers(t, st, "n1", inB.ID, "bob")
	exit := &models.Outbound{NodeUUID: "n1", Name: "exit-anytls", Protocol: "anytls", Core: models.CoreSingBox, Enabled: true}
	require.NoError(t, st.UpsertOutbound(exit))
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "off-user",
		Enabled:  false,
		RuleJSON: `{"inbound_id":"` + inA.ID + `","outbound_id":"` + exit.ID + `","user_ids":["` + usersA[0].ID + `"]}`,
	}))
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "other-in",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + inB.ID + `","outbound_id":"` + exit.ID + `","user_ids":["` + usersB[0].ID + `"]}`,
	}))
	inA.Core = models.CoreXray
	require.NoError(t, st.UpsertInbound(inA))
	got, err := st.GetInbound(inA.ID)
	require.NoError(t, err)
	require.Equal(t, models.CoreXray, got.Core)
}

func TestInboundCoreChangeRejectsUnsupportedUserRoutes(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "by-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}))
	in.Protocol = "hysteria2"
	in.Core = models.CoreXray
	err := st.UpsertInbound(in)
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "route_user_unsupported")
}

func TestUpsertInboundDisableAfterDeletedUser(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "by-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	require.NoError(t, st.DeleteUser(users[0].ID))
	in.Enabled = false
	require.NoError(t, st.UpsertInbound(in))
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)
	err = st.UpsertRoute(row)
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "user not found")
}

func TestUpsertInboundDisableAfterRevokedGrant(t *testing.T) {
	st := testDB(t)
	in := testInbound("n1", "in-a", "vless", "a.example.com", 443)
	require.NoError(t, st.UpsertInbound(in))
	users := seedGrantedUsers(t, st, "n1", in.ID, "alice")
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "by-user",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + in.ID + `","outbound_id":"direct","user_ids":["` + users[0].ID + `"]}`,
	}
	require.NoError(t, st.UpsertRoute(row))
	require.NoError(t, st.ReplaceGrants(users[0].ID, nil))
	in.Enabled = false
	require.NoError(t, st.UpsertInbound(in))
	got, err := st.GetInbound(in.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)
	err = st.UpsertRoute(row)
	require.ErrorIs(t, err, ErrInvalid)
	require.Contains(t, err.Error(), "user not granted")
}

func TestParseRouteUserIDsJSONRejectsWrongType(t *testing.T) {
	_, err := ParseRouteUserIDsJSON(json.RawMessage(`"alice"`))
	require.ErrorIs(t, err, ErrInvalid)
	ids, err := ParseRouteUserIDsJSON(json.RawMessage(`[" a ", "a"]`))
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, ids)
}

func TestCoreSupportsUserRouteMatrix(t *testing.T) {
	require.True(t, CoreSupportsUserRoute(models.CoreXray, "vless"))
	require.True(t, CoreSupportsUserRoute(models.CoreXray, "socks"))
	require.False(t, CoreSupportsUserRoute(models.CoreXray, "hysteria2"))
	require.True(t, CoreSupportsUserRoute(models.CoreSingBox, "hysteria2"))
	require.True(t, CoreSupportsUserRoute(models.CoreSingBox, "mixed"))
	require.True(t, CoreSupportsUserRoute(models.CoreSingBox, "anytls"))
	require.False(t, CoreSupportsUserRoute(models.CoreXray, "anytls"))
}
