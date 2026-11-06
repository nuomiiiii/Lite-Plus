package store

import (
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

const (
	ledgerReasonUsage = "usage"

	finishedCommandRetention = 7 * 24 * time.Hour
	retentionCleanupBatch    = 5000
)

func (s *Store) CleanupExpired(now time.Time) error {
	if err := s.cleanupUsageLedger(); err != nil {
		return err
	}
	return s.cleanupFinishedCommands(now)
}

func (s *Store) cleanupUsageLedger() error {
	for {
		var ids []string
		if err := s.db.Model(&models.QuotaLedger{}).
			Where("reason = ?", ledgerReasonUsage).
			Limit(retentionCleanupBatch).
			Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := s.db.Where("id IN ?", ids).Delete(&models.QuotaLedger{}).Error; err != nil {
			return err
		}
	}
}

func (s *Store) cleanupFinishedCommands(at time.Time) error {
	finished := []string{models.CmdApplied, models.CmdFailed, models.CmdSuperseded}
	if err := s.db.Model(&models.ControlCommand{}).
		Where("status IN ? AND payload_json <> ?", finished, "").
		UpdateColumn("payload_json", "").Error; err != nil {
		return err
	}
	cutoff := at.UTC().Add(-finishedCommandRetention)
	for {
		var ids []string
		if err := s.db.Model(&models.ControlCommand{}).
			Where("status IN ? AND updated_at < ?", finished, cutoff).
			Limit(retentionCleanupBatch).
			Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := s.db.Where("id IN ?", ids).Delete(&models.ControlCommand{}).Error; err != nil {
			return err
		}
	}
}
