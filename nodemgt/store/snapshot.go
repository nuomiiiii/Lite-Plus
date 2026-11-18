package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
)

type snapshotCredential struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	UUID      string     `json:"uuid"`
	Secret    string     `json:"secret"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type snapshotUser struct {
	models.NodeUser
	InboundIDs  []string             `json:"inbound_ids"`
	Credentials []snapshotCredential `json:"credentials"`
}

func (s *Store) ListUsersOnNode(nodeUUID string) ([]models.NodeUser, error) {
	if strings.TrimSpace(nodeUUID) == "" {
		return s.ListUsers("")
	}
	inbounds, err := s.ListInbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	inboundIDs := make([]string, 0, len(inbounds))
	for _, in := range inbounds {
		inboundIDs = append(inboundIDs, in.ID)
	}
	var granted []string
	if len(inboundIDs) > 0 {
		seenGrantUsers := map[string]struct{}{}
		for _, chunk := range chunkStrings(inboundIDs, sqliteChunkSize) {
			var part []string
			if err := s.db.Model(&models.Grant{}).Where("inbound_id IN ?", chunk).Distinct("user_id").Pluck("user_id", &part).Error; err != nil {
				return nil, err
			}
			for _, uid := range part {
				if _, ok := seenGrantUsers[uid]; !ok {
					seenGrantUsers[uid] = struct{}{}
					granted = append(granted, uid)
				}
			}
		}
	}
	if len(granted) == 0 {
		var rows []models.NodeUser
		return rows, s.db.Where("node_uuid = ?", nodeUUID).Order("created_at ASC").Find(&rows).Error
	}
	if len(granted) <= sqliteChunkSize {
		var rows []models.NodeUser
		return rows, s.db.Where("node_uuid = ? OR id IN ?", nodeUUID, granted).Order("created_at ASC").Find(&rows).Error
	}
	var directRows []models.NodeUser
	if err := s.db.Where("node_uuid = ?", nodeUUID).Order("created_at ASC").Find(&directRows).Error; err != nil {
		return nil, err
	}
	byID := make(map[string]models.NodeUser, len(directRows)+len(granted))
	for _, u := range directRows {
		byID[u.ID] = u
	}
	for _, chunk := range chunkStrings(granted, sqliteChunkSize) {
		var part []models.NodeUser
		if err := s.db.Where("id IN ?", chunk).Find(&part).Error; err != nil {
			return nil, err
		}
		for _, u := range part {
			byID[u.ID] = u
		}
	}
	rows := make([]models.NodeUser, 0, len(byID))
	for _, u := range byID {
		rows = append(rows, u)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})
	return rows, nil
}

func (s *Store) NodeUUIDsForUser(userID string) ([]string, error) {
	return s.NodeIDsForUser(userID)
}

func (s *Store) NodeIDsForUser(userID string) ([]string, error) {
	seen := map[string]struct{}{}
	if user, err := s.GetUser(userID); err == nil && strings.TrimSpace(user.NodeUUID) != "" {
		seen[user.NodeUUID] = struct{}{}
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	grants, err := s.ListGrants(userID)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return mapKeys(seen), nil
	}
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.InboundID)
	}
	for _, chunk := range chunkStrings(ids, sqliteChunkSize) {
		var inbounds []models.Inbound
		if err := s.db.Where("id IN ?", chunk).Find(&inbounds).Error; err != nil {
			return nil, err
		}
		for _, in := range inbounds {
			if in.NodeUUID != "" {
				seen[in.NodeUUID] = struct{}{}
			}
		}
	}
	return mapKeys(seen), nil
}

func (s *Store) UserOnNode(userID, nodeUUID string) error {
	if strings.TrimSpace(nodeUUID) == "" {
		return nil
	}
	nodes, err := s.NodeIDsForUser(userID)
	if err != nil {
		return err
	}
	for _, id := range nodes {
		if id == nodeUUID {
			return nil
		}
	}
	return ErrForbidden
}

func (s *Store) NodeSnapshot(nodeUUID string) (map[string]any, error) {
	inbounds, err := s.ListInbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	for i := range inbounds {
		opened, openErr := openInboundSecretsStrict(inbounds[i])
		if openErr != nil {
			return nil, openErr
		}
		inbounds[i] = opened
	}
	outbounds, err := s.ListOutbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	for i := range outbounds {
		opened, openErr := openOutboundSecretsStrict(outbounds[i])
		if openErr != nil {
			return nil, openErr
		}
		outbounds[i] = opened
	}
	routes, err := s.ListRoutes(nodeUUID)
	if err != nil {
		return nil, err
	}
	users, err := s.ListUsersOnNode(nodeUUID)
	if err != nil {
		return nil, err
	}
	inboundIDs := map[string]struct{}{}
	for _, in := range inbounds {
		inboundIDs[in.ID] = struct{}{}
	}
	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}
	grantsByUser := make(map[string][]models.Grant, len(userIDs))
	credsByUser := make(map[string][]models.Credential, len(userIDs))
	latestAsg := make(map[string]models.Assignment, len(userIDs))
	planByID := map[string]models.Plan{}
	if len(userIDs) > 0 {
		for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
			var grantRows []models.Grant
			if err := s.db.Where("user_id IN ?", chunk).Order("created_at ASC").Find(&grantRows).Error; err != nil {
				return nil, err
			}
			for _, g := range grantRows {
				grantsByUser[g.UserID] = append(grantsByUser[g.UserID], g)
			}

			var credRows []models.Credential
			if err := s.db.Where("user_id IN ?", chunk).Order("created_at ASC").Find(&credRows).Error; err != nil {
				return nil, err
			}
			for i := range credRows {
				plain, openErr := secretcrypt.Open(credRows[i].SecretMaterial)
				if openErr != nil {
					return nil, fmt.Errorf("decrypt credential %s: %w", credRows[i].ID, openErr)
				}
				credRows[i].SecretMaterial = plain
				credsByUser[credRows[i].UserID] = append(credsByUser[credRows[i].UserID], credRows[i])
			}
		}

		planIDSet := map[string]struct{}{}
		for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
			var asgRows []models.Assignment
			if err := s.db.Where("user_id IN ?", chunk).Order("created_at DESC").Find(&asgRows).Error; err != nil {
				return nil, err
			}
			for _, a := range asgRows {
				if _, ok := latestAsg[a.UserID]; !ok {
					latestAsg[a.UserID] = a
					if a.PlanID != "" {
						planIDSet[a.PlanID] = struct{}{}
					}
				}
			}
		}
		if len(planIDSet) > 0 {
			planIDs := make([]string, 0, len(planIDSet))
			for id := range planIDSet {
				planIDs = append(planIDs, id)
			}
			for _, chunk := range chunkStrings(planIDs, sqliteChunkSize) {
				var planRows []models.Plan
				if err := s.db.Where("id IN ?", chunk).Find(&planRows).Error; err != nil {
					return nil, err
				}
				for _, p := range planRows {
					planByID[p.ID] = p
				}
			}
		}
	}
	at := now()
	var ackedUsageOps []string
	if len(userIDs) > 0 {
		cutoff := at.Add(-2 * time.Hour)
		seenOps := map[string]struct{}{}
		for _, chunk := range chunkStrings(userIDs, sqliteChunkSize) {
			var ops []string
			if err := s.db.Model(&models.QuotaLedger{}).
				Where("user_id IN ? AND reason = ? AND created_at >= ?", chunk, ledgerReasonUsageDedup, cutoff).
				Pluck("op_id", &ops).Error; err != nil {
				return nil, err
			}
			for _, op := range ops {
				if op == "" {
					continue
				}
				if _, ok := seenOps[op]; !ok {
					seenOps[op] = struct{}{}
					ackedUsageOps = append(ackedUsageOps, op)
				}
			}
		}
	}
	snapUsers := make([]snapshotUser, 0, len(users))
	for _, u := range users {
		view := snapshotUser{NodeUser: u, InboundIDs: []string{}}
		for _, g := range grantsByUser[u.ID] {
			if _, ok := inboundIDs[g.InboundID]; ok {
				view.InboundIDs = append(view.InboundIDs, g.InboundID)
			}
		}
		for _, c := range credsByUser[u.ID] {
			secret := c.SecretMaterial
			if secret == "" {
				secret = c.UUID
			}
			view.Credentials = append(view.Credentials, snapshotCredential{
				ID:        c.ID,
				Kind:      c.Kind,
				UUID:      c.UUID,
				Secret:    secret,
				Enabled:   c.Enabled,
				ExpiresAt: c.ExpiresAt,
			})
		}
		if view.RateLimitBps <= 0 {
			if asg, ok := latestAsg[u.ID]; ok && (asg.EndsAt == nil || asg.EndsAt.After(at)) {
				if plan, pok := planByID[asg.PlanID]; pok {
					view.RateLimitBps = plan.RateLimitBps
				}
			}
		}
		snapUsers = append(snapUsers, view)
	}
	certs, err := s.ListCerts(nodeUUID)
	if err != nil {
		return nil, err
	}
	for i := range inbounds {
		inbounds[i].SettingsJSON = inboundcfg.NormalizeSniffSettingsJSON(inbounds[i].SettingsJSON)
	}
	return map[string]any{
		"node_uuid":       nodeUUID,
		"acked_usage_ops": ackedUsageOps,
		"inbounds":        inbounds,
		"outbounds":       outbounds,
		"routes":          routes,
		"users":           snapUsers,
		"certs":           certs,
		"dial_stack":      s.NodeDialStack(nodeUUID),
	}, nil
}

func assignedPlan(s *Store, userID string) (*models.Plan, bool) {
	asg, err := s.ListAssignments(userID)
	if err != nil || len(asg) == 0 {
		return nil, false
	}
	plan, err := s.GetPlan(asg[0].PlanID)
	if err != nil || plan == nil {
		return nil, false
	}
	return plan, true
}

func mapKeys(seen map[string]struct{}) []string {
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
