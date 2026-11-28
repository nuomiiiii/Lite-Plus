package clients

import (
	"fmt"
	"testing"
	"time"

	"github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/database/trafficledger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSaveClientRemapsCalibrationCycleOnScheduleChange(t *testing.T) {
	dsn := fmt.Sprintf("file:save-client-remap-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Client{},
		&models.ClientDeploymentProfile{},
		&models.TrafficCalibrationAdjustment{},
		&models.TrafficCycleFirstDay{},
	))

	now := time.Now().UTC()
	todayCST := trafficledger.BeijingDay(now)
	day := todayCST.Day()
	client := models.Client{
		UUID:            "node-save-remap",
		Name:            "node-save-remap",
		TrafficResetDay: &day,
	}
	require.NoError(t, db.Create(&client).Error)

	_, oldCycle, err := trafficledger.CurrentTrafficCycleFor(client, now)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.TrafficCalibrationAdjustment{
		CalibrationID: "cal-1",
		Client:        client.UUID,
		Cycle:         oldCycle,
		Day:           todayCST.Format(time.DateOnly),
		UpDelta:       -100,
		DownDelta:     -200,
		TargetUp:      0,
		TargetDown:    0,
		Operator:      "admin",
		CreatedAt:     now,
	}).Error)

	// Switch from default Beijing midnight to a custom UTC clock on the same day.
	require.NoError(t, saveClient(db, map[string]interface{}{
		"uuid":                   client.UUID,
		"traffic_reset_day":      float64(day),
		"traffic_reset_time":     "04:00:00",
		"traffic_reset_timezone": "UTC",
	}))

	var refreshed models.Client
	require.NoError(t, db.First(&refreshed, "uuid = ?", client.UUID).Error)
	_, newCycle, err := trafficledger.CurrentTrafficCycleFor(refreshed, now)
	require.NoError(t, err)
	require.NotEqual(t, oldCycle, newCycle)

	var adj models.TrafficCalibrationAdjustment
	require.NoError(t, db.First(&adj, "calibration_id = ?", "cal-1").Error)
	assert.Equal(t, newCycle, adj.Cycle, "saveClient must remap active calibration rows to the new cycle")
}
