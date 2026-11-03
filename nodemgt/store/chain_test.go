package store

import (
	"encoding/json"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/stretchr/testify/require"
)

func testInbound(node, name, proto, host string, port int) *models.Inbound {
	settings, _ := json.Marshal(map[string]any{
		"share_strategy": "other",
		"public_host":    host,
		"transport":      "tcp",
		"security":       "none",
	})
	return &models.Inbound{
		NodeUUID:     node,
		Core:         models.CoreXray,
		Name:         name,
		Protocol:     proto,
		Listen:       "0.0.0.0",
		Port:         port,
		SettingsJSON: string(settings),
		Enabled:      true,
	}
}

func ptrBool(v bool) *bool { return &v }

func TestForwardChainManyToOne(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vmess", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))

	view, nodes, err := st.UpsertChain(ChainUpsert{
		Name:              "US exit",
		Strategy:          chainStrategyNone,
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.Equal(t, chainStrategyNone, view.Strategy)
	require.False(t, view.BackupDirect)
	require.False(t, view.FallbackDirect)
	require.Len(t, view.Sources, 2)
	require.Len(t, view.Landings, 1)
	require.ElementsMatch(t, []string{"front-a", "front-b", "land"}, nodes)

	users, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Empty(t, users)
	relay, err := st.relayUserForInbound(landing.ID)
	require.NoError(t, err)
	require.Equal(t, models.UserKindRelay, relay.Kind)
	require.Equal(t, models.RelayUsernamePrefix, relay.Username)

	outbounds, err := st.ListOutbounds("")
	require.NoError(t, err)
	require.Len(t, outbounds, 2)
	routes, err := st.ListRoutes("")
	require.NoError(t, err)
	require.Len(t, routes, 2)
	for _, row := range outbounds {
		require.True(t, settingsFlag(row.SettingsJSON, "chain_managed"))
		require.Equal(t, "land.example.com", settingsString(row.SettingsJSON, "address"))
		require.Equal(t, landing.ID, settingsString(row.SettingsJSON, "landing_inbound_id"))
	}
}

func TestForwardChainOnlyPushesTouchedLineNodes(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vmess", "b.example.com", 8443)
	frontC := testInbound("front-c", "SG-C", "vless", "c.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))
	require.NoError(t, st.UpsertInbound(frontC))

	view, nodes, err := st.UpsertChain(ChainUpsert{
		Name:              "US exit",
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"front-a", "front-b", "land"}, nodes)

	_, nodes, err = st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		Name:              "US exit",
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.Empty(t, nodes)

	_, nodes, err = st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		Name:              "US exit",
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID, frontC.ID},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"front-c"}, nodes)

	_, nodes, err = st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		Name:              "US exit",
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontB.ID, frontC.ID},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"front-a"}, nodes)
}

func TestForwardChainChangeLandingPushesSources(t *testing.T) {
	st := testDB(t)
	landA := testInbound("land-a", "US-A", "vless", "a.example.com", 443)
	landB := testInbound("land-b", "US-B", "vless", "b.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vless", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landA))
	require.NoError(t, st.UpsertInbound(landB))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))

	view, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landA.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)

	_, nodes, err := st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		LandingInboundIDs: []string{landB.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"front-a", "front-b", "land-b"}, nodes)
}

func TestSyncSourceInboundDoesNotPushSiblingLines(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vless", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))
	_, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)

	frontA.Port = 9443
	require.NoError(t, st.UpsertInbound(frontA))
	nodes, err := st.SyncChainsForLanding(frontA.ID)
	require.NoError(t, err)
	require.Empty(t, nodes)
}

func TestForwardChainToggleEnabledPushesSourcesOnly(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vless", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))
	view, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	off := false
	_, nodes, err := st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
		Enabled:           &off,
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"front-a", "front-b"}, nodes)
}

func TestForwardChainSameNodeAddLinePushesOnlyNewNode(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA1 := testInbound("front-a", "HK-1", "vless", "a1.example.com", 8443)
	frontA2 := testInbound("front-a", "HK-2", "vless", "a2.example.com", 8444)
	frontB := testInbound("front-b", "JP-B", "vless", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA1))
	require.NoError(t, st.UpsertInbound(frontA2))
	require.NoError(t, st.UpsertInbound(frontB))
	view, nodes, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA1.ID, frontA2.ID},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"front-a", "land"}, nodes)
	_, nodes, err = st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA1.ID, frontA2.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"front-b"}, nodes)
}

func TestForwardChainConsolidatingRelayPushesLanding(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front-a", "HK-A", "vless", "a.example.com", 8443)
	frontB := testInbound("front-b", "JP-B", "vless", "b.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))
	view, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	extra := &models.NodeUser{Username: "__relay__old", Kind: models.UserKindRelay, Status: models.UserActive, DisplayName: "old"}
	require.NoError(t, st.UpsertUser(extra))
	require.NoError(t, st.EnsureGrant(extra.ID, landing.ID))
	_, nodes, err := st.UpsertChain(ChainUpsert{
		ID:                view.ID,
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"land"}, nodes)
	_, err = st.GetUser(extra.ID)
	require.Error(t, err)
}

func TestForwardChainSharesOneRelayUser(t *testing.T) {
	st := testDB(t)
	landA := testInbound("land-a", "US-A", "vless", "a.example.com", 443)
	landB := testInbound("land-b", "US-B", "vless", "b.example.com", 443)
	front := testInbound("front", "HK", "vless", "hk.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landA))
	require.NoError(t, st.UpsertInbound(landB))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{
		Strategy:          chainStrategyURLTest,
		LandingInboundIDs: []string{landA.ID, landB.ID},
		SourceInboundIDs:  []string{front.ID},
	})
	require.NoError(t, err)
	a, err := st.relayUserForInbound(landA.ID)
	require.NoError(t, err)
	b, err := st.relayUserForInbound(landB.ID)
	require.NoError(t, err)
	require.Equal(t, a.ID, b.ID)
	require.Equal(t, models.RelayUsernamePrefix, a.Username)
	views, err := st.ListUserViews("")
	require.NoError(t, err)
	require.Empty(t, views)
	_, err = st.EnsureSubscription(a.ID)
	require.Error(t, err)
	require.NoError(t, st.UpsertSubscription(&models.Subscription{UserID: a.ID, Format: "xray", Enabled: true}))
	require.NoError(t, st.HideRelaySubscriptions())
	subs, err := st.ListSubscriptions()
	require.NoError(t, err)
	for _, row := range subs {
		require.NotEqual(t, a.ID, row.UserID)
	}
}

func TestForwardChainSharesOutboundOnSameNode(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	frontA := testInbound("front", "HK-1", "vless", "a.example.com", 8443)
	frontB := testInbound("front", "HK-2", "vless", "a.example.com", 8444)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(frontA))
	require.NoError(t, st.UpsertInbound(frontB))

	view, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{frontA.ID, frontB.ID},
	})
	require.NoError(t, err)
	require.Len(t, view.Sources, 2)
	require.Equal(t, view.Sources[0].OutboundID, view.Sources[1].OutboundID)
	require.NotEqual(t, view.Sources[0].RouteID, view.Sources[1].RouteID)
	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
}

func TestForwardChainRejectsXrayHy2(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "hysteria2", "land.example.com", 443)
	landing.Core = models.CoreSingBox
	landing.SettingsJSON = `{"share_strategy":"other","public_host":"land.example.com","transport":"quic","security":"tls"}`
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_core_mismatch")
}

func TestForwardChainRejectsCycleAndBusySource(t *testing.T) {
	st := testDB(t)
	a := testInbound("n1", "A", "vless", "a.example.com", 443)
	b := testInbound("n2", "B", "vless", "b.example.com", 443)
	c := testInbound("n3", "C", "vless", "c.example.com", 443)
	require.NoError(t, st.UpsertInbound(a))
	require.NoError(t, st.UpsertInbound(b))
	require.NoError(t, st.UpsertInbound(c))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{b.ID}, SourceInboundIDs: []string{a.ID}})
	require.NoError(t, err)
	_, _, err = st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{a.ID}, SourceInboundIDs: []string{b.ID}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_cycle")
	_, _, err = st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{c.ID}, SourceInboundIDs: []string{a.ID}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_source_in_use")
}

func TestForwardChainSyncsLandingAddress(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "old.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{front.ID},
	})
	require.NoError(t, err)
	landing.SettingsJSON = `{"share_strategy":"other","public_host":"new.example.com","transport":"tcp","security":"none"}`
	require.NoError(t, st.UpsertInbound(landing))
	nodes, err := st.SyncChainsForLanding(landing.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"front"}, nodes)
	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	require.Equal(t, "new.example.com", settingsString(outbounds[0].SettingsJSON, "address"))
}

func TestForwardChainDeleteCleansManagedRows(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	view, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	_, err = st.DeleteChain(view.ID)
	require.NoError(t, err)
	outbounds, err := st.ListOutbounds("")
	require.NoError(t, err)
	require.Empty(t, outbounds)
	routes, err := st.ListRoutes("")
	require.NoError(t, err)
	require.Empty(t, routes)
	require.Error(t, st.DeleteOutbound("missing"))
}

func TestDeleteInboundRemovesChain(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	require.NoError(t, st.DeleteInbound(front.ID))
	views, err := st.ListChainViews("")
	require.NoError(t, err)
	require.Empty(t, views)
	outbounds, err := st.ListOutbounds("")
	require.NoError(t, err)
	require.Empty(t, outbounds)
}

func TestChainManagedOutboundCannotDeleteDirectly(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	view, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	err = st.DeleteOutbound(view.Sources[0].OutboundID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_managed")
	err = st.DeleteRoute(view.Sources[0].RouteID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_managed")
}

func TestForwardChainMultiLandingFailover(t *testing.T) {
	st := testDB(t)
	landA := testInbound("land-a", "US", "vless", "a.example.com", 443)
	landB := testInbound("land-b", "JP", "vless", "b.example.com", 443)
	front := testInbound("front", "HK", "vless", "hk.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landA))
	require.NoError(t, st.UpsertInbound(landB))
	require.NoError(t, st.UpsertInbound(front))

	view, _, err := st.UpsertChain(ChainUpsert{
		Name:              "exit pool",
		Strategy:          chainStrategyFailover,
		LandingInboundIDs: []string{landA.ID, landB.ID},
		SourceInboundIDs:  []string{front.ID},
		FallbackDirect:    ptrBool(true),
	})
	require.NoError(t, err)
	require.Equal(t, chainStrategyFailover, view.Strategy)
	require.True(t, view.FallbackDirect)
	require.Len(t, view.Landings, 2)
	require.Equal(t, landA.ID, view.Landings[0].LandingInboundID)
	require.Equal(t, landB.ID, view.Landings[1].LandingInboundID)

	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 3)
	var group *models.Outbound
	hops := 0
	for i := range outbounds {
		if settingsFlag(outbounds[i].SettingsJSON, "chain_group") {
			group = &outbounds[i]
			continue
		}
		hops++
	}
	require.Equal(t, 2, hops)
	require.NotNil(t, group)
	require.Equal(t, "failover", group.Protocol)
	require.Equal(t, view.Sources[0].OutboundID, group.ID)
	require.Len(t, settingsStringList(group.SettingsJSON, "member_ids"), 2)
	require.True(t, settingsFlag(group.SettingsJSON, "fallback_direct"))
	require.False(t, settingsFlag(group.SettingsJSON, "backup_direct"))
}

func TestForwardChainPlainOneHopHasNoGroup(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	view, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	require.Equal(t, chainStrategyNone, view.Strategy)
	require.False(t, view.BackupDirect)
	require.False(t, view.FallbackDirect)
	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	require.False(t, settingsFlag(outbounds[0].SettingsJSON, "chain_group"))
	require.Equal(t, view.Sources[0].OutboundID, outbounds[0].ID)
}

func TestForwardChainFailoverBackupDirect(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	view, _, err := st.UpsertChain(ChainUpsert{
		Strategy:          chainStrategyFailover,
		BackupDirect:      ptrBool(true),
		LandingInboundIDs: []string{landing.ID},
		SourceInboundIDs:  []string{front.ID},
	})
	require.NoError(t, err)
	require.True(t, view.BackupDirect)
	require.False(t, view.FallbackDirect)
	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 2)
	var group *models.Outbound
	for i := range outbounds {
		if settingsFlag(outbounds[i].SettingsJSON, "chain_group") {
			group = &outbounds[i]
		}
	}
	require.NotNil(t, group)
	require.Equal(t, "failover", group.Protocol)
	require.True(t, settingsFlag(group.SettingsJSON, "backup_direct"))
	require.Len(t, settingsStringList(group.SettingsJSON, "member_ids"), 1)
}

func TestForwardChainURLTestWithoutDirect(t *testing.T) {
	st := testDB(t)
	landA := testInbound("land-a", "US", "vless", "a.example.com", 443)
	landB := testInbound("land-b", "JP", "vless", "b.example.com", 443)
	front := testInbound("front", "HK", "vless", "hk.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landA))
	require.NoError(t, st.UpsertInbound(landB))
	require.NoError(t, st.UpsertInbound(front))

	view, _, err := st.UpsertChain(ChainUpsert{
		Strategy:          chainStrategyURLTest,
		LandingInboundIDs: []string{landA.ID, landB.ID},
		SourceInboundIDs:  []string{front.ID},
		FallbackDirect:    ptrBool(false),
	})
	require.NoError(t, err)
	require.Equal(t, chainStrategyURLTest, view.Strategy)
	outbounds, err := st.ListOutbounds("front")
	require.NoError(t, err)
	require.Len(t, outbounds, 3)
	var group *models.Outbound
	for i := range outbounds {
		if settingsFlag(outbounds[i].SettingsJSON, "chain_group") {
			group = &outbounds[i]
		}
	}
	require.NotNil(t, group)
	require.Equal(t, "urltest", group.Protocol)
	require.False(t, settingsFlag(group.SettingsJSON, "fallback_direct"))
}

func TestPlusTablesMigratedIncludesChains(t *testing.T) {
	st := testDB(t)
	require.True(t, st.DB().Migrator().HasTable(&models.ForwardChain{}))
	require.True(t, st.DB().Migrator().HasTable(&models.ForwardLink{}))
	require.True(t, st.DB().Migrator().HasTable(&models.ForwardLanding{}))
}

func TestForwardChainRejectsManualRouteInbound(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "front",
		Name:     "manual",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + front.ID + `","outbound_id":"direct"}`,
	}))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_route_in_use")
}

func TestManualRouteRejectsChainInbound(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
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

func TestManualRouteAllowsChainLanding(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "land",
		Name:     "next-hop",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + landing.ID + `","outbound_id":"direct"}`,
	}))
}

func TestForwardChainRejectsManualOutboundInbound(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	require.NoError(t, st.UpsertOutbound(&models.Outbound{
		NodeUUID:     "front",
		Name:         "copy-front",
		Protocol:     "vless",
		Enabled:      true,
		SettingsJSON: `{"source_inbound_id":"` + front.ID + `","address":"a.example.com","port":8443}`,
	}))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain_outbound_in_use")
}

func TestManualOutboundAllowsChainLanding(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
	require.NoError(t, st.UpsertOutbound(&models.Outbound{
		NodeUUID:     "land",
		Name:         "copy-land",
		Protocol:     "vless",
		Enabled:      true,
		SettingsJSON: `{"source_inbound_id":"` + landing.ID + `","address":"land.example.com","port":443}`,
	}))
}

func TestForwardChainAllowsLandingWithManualRoute(t *testing.T) {
	st := testDB(t)
	landing := testInbound("land", "US", "vless", "land.example.com", 443)
	front := testInbound("front", "HK", "vless", "a.example.com", 8443)
	require.NoError(t, st.UpsertInbound(landing))
	require.NoError(t, st.UpsertInbound(front))
	require.NoError(t, st.UpsertRoute(&models.Route{
		NodeUUID: "land",
		Name:     "next-hop",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"` + landing.ID + `","outbound_id":"direct"}`,
	}))
	_, _, err := st.UpsertChain(ChainUpsert{LandingInboundIDs: []string{landing.ID}, SourceInboundIDs: []string{front.ID}})
	require.NoError(t, err)
}
