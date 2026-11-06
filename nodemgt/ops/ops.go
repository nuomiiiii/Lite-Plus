package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"gorm.io/gorm"
)

type Service struct {
	Store *store.Store
}

func New(st *store.Store) *Service { return &Service{Store: st} }

func ensureOpID(operationID string) string {
	if strings.TrimSpace(operationID) == "" {
		return uuid.NewString()
	}
	return strings.TrimSpace(operationID)
}

func (s *Service) Assign(actor, userID, planID, operationID string, now time.Time) (*models.Assignment, error) {
	operationID = ensureOpID(operationID)
	if existing, err := s.Store.FindAssignmentByOp(operationID); err == nil {
		return existing, enqueueUserSync(s.Store, existing.UserID, "applyConfig", operationID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	user, err := s.Store.GetUser(userID)
	if err != nil {
		return nil, err
	}
	plan, err := s.Store.GetPlan(planID)
	if err != nil {
		return nil, err
	}
	ends := now.Add(time.Duration(plan.DurationDays) * 24 * time.Hour)
	asg := &models.Assignment{
		UserID:       user.ID,
		PlanID:       plan.ID,
		StartsAt:     now,
		EndsAt:       &ends,
		TrafficBytes: plan.TrafficBytes,
		RateLimitBps: plan.RateLimitBps,
		DeviceLimit:  plan.DeviceLimit,
		OperationID:  operationID,
	}
	existing, err := s.Store.ListAssignments(user.ID)
	if err != nil {
		return nil, err
	}
	wasDisabled := user.Status == models.UserDisabled
	user.QuotaBytes = plan.TrafficBytes
	user.RateLimitBps = plan.RateLimitBps
	user.DeviceLimit = plan.DeviceLimit
	user.ExpiresAt = &ends
	if len(existing) == 0 {
		user.UsedBytes = 0
	}
	if !wasDisabled {
		user.Status = models.UserActive
	}
	err = s.Store.DB().Transaction(func(tx *gorm.DB) error {
		inner := store.New(tx)
		if err := inner.UpsertUser(user); err != nil {
			return err
		}
		if err := inner.SaveAssignment(asg); err != nil {
			return err
		}
		if err := inner.AddLedger(user.ID, "assign", operationID+"-grant", plan.TrafficBytes); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
		_ = inner.Audit(actor, "nodemgt.assign", user.ID, plan.ID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := enqueueUserSync(s.Store, user.ID, "applyConfig", operationID); err != nil {
		return nil, err
	}
	return asg, nil
}

func (s *Service) ApplyPlanToAssignees(actor, planID, operationID string, now time.Time, prevDurationDays int) ([]string, error) {
	planID = strings.TrimSpace(planID)
	if planID == "" {
		return nil, fmt.Errorf("%w: plan required", store.ErrInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	plan, err := s.Store.GetPlan(planID)
	if err != nil {
		return nil, err
	}
	asgs, err := s.Store.ListAssignments("")
	if err != nil {
		return nil, err
	}
	latest := map[string]models.Assignment{}
	for _, asg := range asgs {
		if _, ok := latest[asg.UserID]; !ok {
			latest[asg.UserID] = asg
		}
	}
	var affected []string
	for userID, asg := range latest {
		if asg.PlanID != plan.ID {
			continue
		}
		user, err := s.Store.GetUser(userID)
		if err != nil {
			return affected, err
		}
		next := asg
		next.TrafficBytes = plan.TrafficBytes
		next.RateLimitBps = plan.RateLimitBps
		next.DeviceLimit = plan.DeviceLimit
		if prevDurationDays > 0 && prevDurationDays != plan.DurationDays && next.EndsAt != nil {
			ends := next.EndsAt.Add(time.Duration(plan.DurationDays-prevDurationDays) * 24 * time.Hour)
			next.EndsAt = &ends
		}
		user.QuotaBytes = plan.TrafficBytes
		user.RateLimitBps = plan.RateLimitBps
		user.DeviceLimit = plan.DeviceLimit
		if next.EndsAt != nil {
			ends := *next.EndsAt
			user.ExpiresAt = &ends
		}
		op := ensureOpID("")
		if strings.TrimSpace(operationID) != "" {
			op = ensureOpID(operationID + "-" + user.ID)
		}
		err = s.Store.DB().Transaction(func(tx *gorm.DB) error {
			inner := store.New(tx)
			if err := inner.UpsertUser(user); err != nil {
				return err
			}
			if err := inner.SaveAssignment(&next); err != nil {
				return err
			}
			_ = inner.Audit(actor, "nodemgt.plan.apply", user.ID, plan.ID)
			return enqueueUserSync(inner, user.ID, "applyConfig", op)
		})
		if err != nil {
			return affected, err
		}
		affected = append(affected, user.ID)
	}
	return affected, nil
}

func (s *Service) Unassign(actor, userID, operationID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("%w: user required", store.ErrInvalid)
	}
	if _, err := s.Store.GetUser(userID); err != nil {
		return err
	}
	operationID = ensureOpID(operationID)
	err := s.Store.DB().Transaction(func(tx *gorm.DB) error {
		inner := store.New(tx)
		if err := inner.DeleteAssignments(userID); err != nil {
			return err
		}
		if err := inner.DB().Model(&models.NodeUser{}).Where("id = ?", userID).Updates(map[string]any{
			"quota_bytes": 0,
			"updated_at":  time.Now().UTC(),
		}).Error; err != nil {
			return err
		}
		_ = inner.Audit(actor, "nodemgt.unassign", userID, "")
		return nil
	})
	if err != nil {
		return err
	}
	return enqueueUserSync(s.Store, userID, "applyConfig", operationID)
}

func (s *Service) UnassignPlan(actor, planID, operationID string) ([]string, error) {
	planID = strings.TrimSpace(planID)
	if planID == "" {
		return nil, fmt.Errorf("%w: plan required", store.ErrInvalid)
	}
	asgs, err := s.Store.ListAssignments("")
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var affected []string
	for _, asg := range asgs {
		if asg.PlanID != planID {
			continue
		}
		if _, ok := seen[asg.UserID]; ok {
			continue
		}
		seen[asg.UserID] = struct{}{}
		if err := s.Unassign(actor, asg.UserID, ensureOpID(operationID)); err != nil {
			return affected, err
		}
		affected = append(affected, asg.UserID)
	}
	return affected, nil
}

func (s *Service) Renew(actor, userID, operationID string, now time.Time) (*models.Assignment, error) {
	operationID = ensureOpID(operationID)
	if existing, err := s.Store.FindAssignmentByOp(operationID); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	list, err := s.Store.ListAssignments(userID)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: no assignment", store.ErrInvalid)
	}
	latest := list[0]
	plan, err := s.Store.GetPlan(latest.PlanID)
	if err != nil {
		return nil, err
	}
	base := now
	if latest.EndsAt != nil && latest.EndsAt.After(now) {
		base = *latest.EndsAt
	}
	ends := base.Add(time.Duration(plan.DurationDays) * 24 * time.Hour)
	asg := &models.Assignment{
		UserID:       userID,
		PlanID:       plan.ID,
		StartsAt:     now,
		EndsAt:       &ends,
		TrafficBytes: plan.TrafficBytes,
		RateLimitBps: plan.RateLimitBps,
		DeviceLimit:  plan.DeviceLimit,
		OperationID:  operationID,
	}
	user, err := s.Store.GetUser(userID)
	if err != nil {
		return nil, err
	}
	user.ExpiresAt = &ends
	if user.Status == models.UserExpired {
		user.Status = models.UserActive
	}
	err = s.Store.DB().Transaction(func(tx *gorm.DB) error {
		inner := store.New(tx)
		if err := inner.UpsertUser(user); err != nil {
			return err
		}
		if err := inner.SaveAssignment(asg); err != nil {
			return err
		}
		_ = inner.Audit(actor, "nodemgt.renew", user.ID, plan.ID)
		return enqueueUserSync(inner, user.ID, "applyConfig", operationID)
	})
	if err != nil {
		return nil, err
	}
	return asg, nil
}

func (s *Service) Topup(actor, userID, operationID string, extraBytes int64) error {
	if extraBytes == 0 {
		return fmt.Errorf("%w: extra_bytes", store.ErrInvalid)
	}
	operationID = ensureOpID(operationID)
	return s.Store.DB().Transaction(func(tx *gorm.DB) error {
		inner := store.New(tx)
		if err := inner.AddLedger(userID, "topup", operationID, extraBytes); errors.Is(err, store.ErrConflict) {
			return nil
		} else if err != nil {
			return err
		}
		if err := tx.Model(&models.NodeUser{}).Where("id = ?", userID).
			UpdateColumn("quota_bytes", gorm.Expr("quota_bytes + ?", extraBytes)).Error; err != nil {
			return err
		}
		_ = inner.Audit(actor, "nodemgt.topup", userID, fmt.Sprintf("%d", extraBytes))
		return enqueueUserSync(inner, userID, "syncQuota", operationID)
	})
}

func (s *Service) Modify(actor, userID, operationID string, quota *int64, rate *int64, devices *int, expires *time.Time) error {
	user, err := s.Store.GetUser(userID)
	if err != nil {
		return err
	}
	if quota != nil {
		user.QuotaBytes = *quota
	}
	if rate != nil {
		user.RateLimitBps = *rate
	}
	if devices != nil {
		if *devices < 0 {
			return fmt.Errorf("%w: device_limit must be >= 0", store.ErrInvalid)
		}
		user.DeviceLimit = *devices
	}
	if expires != nil {
		user.ExpiresAt = expires
	}
	if err := s.Store.UpsertUser(user); err != nil {
		return err
	}
	_ = s.Store.Audit(actor, "nodemgt.modify", user.ID, ensureOpID(operationID))
	return enqueueUserSync(s.Store, user.ID, "applyConfig", ensureOpID(operationID))
}

func (s *Service) Disable(_, userID, operationID string) error {
	if err := s.Store.SetUserStatus(userID, models.UserDisabled); err != nil {
		return err
	}
	user, err := s.Store.GetUser(userID)
	if err != nil {
		return err
	}
	return enqueueUserSync(s.Store, user.ID, "revokeUser", ensureOpID(operationID))
}

func (s *Service) RecordPresenceFromNode(nodeUUID string, users []store.UserPresence) error {
	for _, user := range users {
		if err := s.Store.RecordUserPresence(nodeUUID, user.UserID, user.Online, user.IPs); err != nil {
			if errors.Is(err, store.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Service) RecordUsage(userID string, bytes int64) error {
	return s.RecordUsageFromNode("", userID, bytes, "")
}

func (s *Service) RecordUsageFromNode(nodeUUID, userID string, bytes int64, batchID string) error {
	if bytes <= 0 {
		return nil
	}
	if err := s.Store.UserOnNode(userID, nodeUUID); err != nil {
		return err
	}
	if strings.TrimSpace(batchID) == "" {
		batchID = uuid.NewString()
	}
	return s.Store.DB().Transaction(func(tx *gorm.DB) error {
		inner := store.New(tx)
		ledgerOp := batchID
		if strings.TrimSpace(userID) != "" {
			ledgerOp = userID + ":" + batchID
		}
		seen, err := inner.UsageBatchSeen(userID, ledgerOp)
		if err != nil {
			return err
		}
		if seen {
			return nil
		}
		reset, err := inner.ApplyUserTrafficReset(userID, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := inner.ApplyUsageBatch(userID, ledgerOp, bytes); errors.Is(err, store.ErrConflict) {
			return nil
		} else if err != nil {
			return err
		}
		if !reset {
			return nil
		}
		user, err := inner.GetUser(userID)
		if err != nil {
			return err
		}
		return enqueueUserSync(inner, userID, "syncQuota", trafficResetOpID(userID, user.TrafficResetCycle))
	})
}

func (s *Service) SyncDueTrafficResets(at time.Time) ([]string, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	users, err := s.Store.ListMonthlyResetUsers()
	if err != nil {
		return nil, err
	}
	var ids []string
	for i := range users {
		id := users[i].ID
		applied := false
		err := s.Store.DB().Transaction(func(tx *gorm.DB) error {
			inner := store.New(tx)
			ok, err := inner.ApplyUserTrafficReset(id, at)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			user, err := inner.GetUser(id)
			if err != nil {
				return err
			}
			if err := enqueueUserSync(inner, id, "syncQuota", trafficResetOpID(id, user.TrafficResetCycle)); err != nil {
				return err
			}
			applied = true
			return nil
		})
		if err != nil {
			return ids, err
		}
		if applied {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func trafficResetOpID(userID, cycle string) string {
	return "traffic-reset:" + userID + ":" + cycle
}

func enqueueUserSync(st *store.Store, userID, kind, operationID string) error {
	nodes, err := st.NodeIDsForUser(userID)
	if err != nil {
		return err
	}
	operationID = ensureOpID(operationID)
	for i, nodeUUID := range nodes {
		if nodeUUID == "" {
			continue
		}
		op := operationID
		if i > 0 {
			op = operationID + "-" + nodeUUID
		}
		var payload []byte
		if kind == "revokeUser" {
			payload, err = json.Marshal(map[string]any{"user_ids": []string{userID}})
		} else {
			snap, snapErr := st.NodeSnapshot(nodeUUID)
			if snapErr != nil {
				return snapErr
			}
			payload, err = json.Marshal(snap)
		}
		if err != nil {
			return err
		}
		if err := st.EnqueueCommand(&models.ControlCommand{
			OperationID: op,
			NodeUUID:    nodeUUID,
			Kind:        kind,
			PayloadJSON: string(payload),
			Status:      models.CmdPending,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) SnapshotPayload(nodeUUID string) (string, error) {
	snap, err := s.Store.NodeSnapshot(nodeUUID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(snap)
	return string(b), err
}
