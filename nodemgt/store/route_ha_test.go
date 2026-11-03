package store

import (
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/stretchr/testify/require"
)

func TestRouteFailoverCreatesHiddenGroup(t *testing.T) {
	st := testDB(t)
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	backup := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	require.NoError(t, st.UpsertOutbound(backup))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha",
		Enabled:  true,
		RuleJSON: `{"inbound_id":"in1","outbound_id":"` + primary.ID + `","strategy":"failover","backup_outbound_id":"` + backup.ID + `","fallback_direct":true}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, chainStrategyFailover, settingsString(got.RuleJSON, "strategy"))
	require.Equal(t, primary.ID, settingsString(got.RuleJSON, "primary_outbound_id"))
	require.Equal(t, backup.ID, settingsString(got.RuleJSON, "backup_outbound_id"))
	groupID := settingsString(got.RuleJSON, "group_outbound_id")
	require.NotEmpty(t, groupID)
	require.Equal(t, groupID, settingsString(got.RuleJSON, "outbound_id"))
	group, err := st.GetOutbound(groupID)
	require.NoError(t, err)
	require.True(t, settingsFlag(group.SettingsJSON, "route_managed"))
	require.Equal(t, "failover", group.Protocol)
	require.Equal(t, []string{primary.ID, backup.ID}, settingsStringList(group.SettingsJSON, "member_ids"))
	require.True(t, settingsFlag(group.SettingsJSON, "fallback_direct"))

	outs, err := st.ListOutbounds("n1")
	require.NoError(t, err)
	require.Len(t, outs, 3)
}

func TestRouteFailoverBackupDirectAndResaveNone(t *testing.T) {
	st := testDB(t)
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha",
		Enabled:  true,
		RuleJSON: `{"outbound_id":"` + primary.ID + `","strategy":"failover","backup_direct":true}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	got, err := st.GetRoute(row.ID)
	require.NoError(t, err)
	groupID := settingsString(got.RuleJSON, "group_outbound_id")
	require.NotEmpty(t, groupID)
	group, err := st.GetOutbound(groupID)
	require.NoError(t, err)
	require.Equal(t, []string{primary.ID}, settingsStringList(group.SettingsJSON, "member_ids"))
	require.True(t, settingsFlag(group.SettingsJSON, "backup_direct"))

	got.RuleJSON = `{"outbound_id":"` + primary.ID + `","strategy":"none"}`
	require.NoError(t, st.UpsertUserRoute(got))
	got, err = st.GetRoute(row.ID)
	require.NoError(t, err)
	require.Equal(t, primary.ID, settingsString(got.RuleJSON, "outbound_id"))
	require.Empty(t, settingsString(got.RuleJSON, "group_outbound_id"))
	_, err = st.GetOutbound(groupID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestRouteFailoverRequiresBackup(t *testing.T) {
	st := testDB(t)
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	err := st.UpsertUserRoute(&models.Route{
		NodeUUID: "n1",
		Name:     "ha",
		Enabled:  true,
		RuleJSON: `{"outbound_id":"` + primary.ID + `","strategy":"failover"}`,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "route_backup_required")
}

func TestDeleteRouteRemovesGroupOutbound(t *testing.T) {
	st := testDB(t)
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	backup := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	require.NoError(t, st.UpsertOutbound(backup))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha",
		Enabled:  true,
		RuleJSON: `{"outbound_id":"` + primary.ID + `","strategy":"failover","backup_outbound_id":"` + backup.ID + `"}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	groupID := settingsString(row.RuleJSON, "group_outbound_id")
	require.NoError(t, st.DeleteRoute(row.ID))
	_, err := st.GetOutbound(groupID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeletePrimaryOutboundRemovesFailoverRoute(t *testing.T) {
	st := testDB(t)
	primary := &models.Outbound{NodeUUID: "n1", Name: "exit-a", Protocol: "freedom", Enabled: true}
	backup := &models.Outbound{NodeUUID: "n1", Name: "exit-b", Protocol: "freedom", Enabled: true}
	require.NoError(t, st.UpsertOutbound(primary))
	require.NoError(t, st.UpsertOutbound(backup))
	row := &models.Route{
		NodeUUID: "n1",
		Name:     "ha",
		Enabled:  true,
		RuleJSON: `{"outbound_id":"` + primary.ID + `","strategy":"failover","backup_outbound_id":"` + backup.ID + `"}`,
	}
	require.NoError(t, st.UpsertUserRoute(row))
	groupID := settingsString(row.RuleJSON, "group_outbound_id")
	require.NoError(t, st.DeleteOutbound(primary.ID))
	_, err := st.GetRoute(row.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = st.GetOutbound(groupID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = st.GetOutbound(backup.ID)
	require.NoError(t, err)
}
