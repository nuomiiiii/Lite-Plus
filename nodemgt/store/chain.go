package store

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/cert"
	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

const (
	relayUsernamePrefix   = "__relay__"
	chainStrategyNone     = "none"
	chainStrategyFailover = "failover"
	chainStrategyURLTest  = "urltest"
	chainGroupProtocol    = "urltest"
)

type ChainView struct {
	models.ForwardChain
	Landings     []ChainLandingView `json:"landings"`
	LandingNames []string           `json:"landing_names"`
	Sources      []ChainHopView     `json:"sources"`
	SourceNames  []string           `json:"source_names"`
}

type ChainLandingView struct {
	ID               string `json:"id"`
	LandingInboundID string `json:"landing_inbound_id"`
	LandingName      string `json:"landing_name"`
	LandingNodeUUID  string `json:"landing_node_uuid"`
	LandingProtocol  string `json:"landing_protocol"`
	LandingPort      int    `json:"landing_port"`
}

type ChainHopView struct {
	ID              string `json:"id"`
	SourceInboundID string `json:"source_inbound_id"`
	SourceName      string `json:"source_name"`
	SourceNodeUUID  string `json:"source_node_uuid"`
	SourceProtocol  string `json:"source_protocol"`
	SourcePort      int    `json:"source_port"`
	OutboundID      string `json:"outbound_id"`
	RouteID         string `json:"route_id"`
}

type ChainUpsert struct {
	ID                string
	Name              string
	Strategy          string
	BackupDirect      *bool
	FallbackDirect    *bool
	LandingInboundIDs []string
	SourceInboundIDs  []string
	Enabled           *bool
}

func (s *Store) ListChainViews(nodeUUID string) ([]ChainView, error) {
	var chains []models.ForwardChain
	if err := s.db.Order("created_at ASC").Find(&chains).Error; err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return []ChainView{}, nil
	}
	views := make([]ChainView, 0, len(chains))
	for i := range chains {
		view, err := s.chainView(chains[i])
		if err != nil {
			return nil, err
		}
		if nodeUUID != "" && !chainOnNode(view, nodeUUID) {
			continue
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Store) GetChainView(id string) (*ChainView, error) {
	row, err := s.getChain(id)
	if err != nil {
		return nil, err
	}
	view, err := s.chainView(*row)
	if err != nil {
		return nil, err
	}
	return &view, nil
}

func (s *Store) UpsertChain(in ChainUpsert) (*ChainView, []string, error) {
	var existing *models.ForwardChain
	if id := strings.TrimSpace(in.ID); id != "" {
		row, err := s.getChain(id)
		if err == nil {
			existing = row
		} else if !isNotFound(err) {
			return nil, nil, err
		}
	}
	strategyRaw := strings.TrimSpace(in.Strategy)
	strategy := normalizeChainStrategy(in.Strategy)
	if strategyRaw == "" && existing != nil {
		strategy = normalizeChainStrategy(existing.Strategy)
	}
	backupDirect := false
	if in.BackupDirect != nil {
		backupDirect = *in.BackupDirect
	} else if existing != nil && strategyRaw == "" {
		backupDirect = existing.BackupDirect
	}
	landings := uniqueIDs(in.LandingInboundIDs)
	if strategy == chainStrategyFailover && (backupDirect || len(landings) < 2) {
		if len(landings) == 0 {
			return nil, nil, fmt.Errorf("%w: chain_landing_required", ErrInvalid)
		}
		landings = landings[:1]
		backupDirect = true
	} else if strategy == chainStrategyFailover {
		landings = landings[:2]
		backupDirect = false
	} else if strategy == chainStrategyURLTest {
		if len(landings) < 2 {
			return nil, nil, fmt.Errorf("%w: chain_pool_required", ErrInvalid)
		}
		backupDirect = false
	} else {
		if len(landings) == 0 {
			return nil, nil, fmt.Errorf("%w: chain_landing_required", ErrInvalid)
		}
		landings = landings[:1]
		backupDirect = false
		strategy = chainStrategyNone
	}
	sources := uniqueIDs(in.SourceInboundIDs)
	if len(sources) == 0 {
		return nil, nil, fmt.Errorf("%w: chain_source_required", ErrInvalid)
	}
	landingSet := map[string]struct{}{}
	for _, id := range landings {
		landingSet[id] = struct{}{}
	}
	for _, id := range sources {
		if _, ok := landingSet[id]; ok {
			return nil, nil, fmt.Errorf("%w: chain_same_inbound", ErrInvalid)
		}
	}
	landingRows := make([]models.Inbound, 0, len(landings))
	for _, id := range landings {
		row, err := s.GetInbound(id)
		if err != nil {
			return nil, nil, err
		}
		landingRows = append(landingRows, *row)
	}
	sourceRows := make([]models.Inbound, 0, len(sources))
	for _, id := range sources {
		row, err := s.GetInbound(id)
		if err != nil {
			return nil, nil, err
		}
		for _, landing := range landingRows {
			if err := chainCoreOK(row.Core, landing.Protocol); err != nil {
				return nil, nil, err
			}
		}
		sourceRows = append(sourceRows, *row)
	}
	if err := s.chainGraphOK(strings.TrimSpace(in.ID), landings, sources); err != nil {
		return nil, nil, err
	}
	for _, id := range sources {
		if err := s.inboundHasManualForwarding(id); err != nil {
			return nil, nil, err
		}
	}

	var affected []string
	chainID := strings.TrimSpace(in.ID)
	err := s.db.Transaction(func(tx *gorm.DB) error {
		st := New(tx)
		fallbackDirect := false
		if !backupDirect && (strategy == chainStrategyURLTest || strategy == chainStrategyFailover) && in.FallbackDirect != nil {
			fallbackDirect = *in.FallbackDirect
		}
		chain := models.ForwardChain{
			ID:             chainID,
			Name:           strings.TrimSpace(in.Name),
			Strategy:       strategy,
			BackupDirect:   backupDirect,
			FallbackDirect: fallbackDirect,
			Enabled:        true,
		}
		if in.Enabled != nil {
			chain.Enabled = *in.Enabled
		}
		if chain.Name == "" {
			chain.Name = strings.TrimSpace(landingRows[0].Name)
		}
		if chain.ID != "" {
			if existing, err := st.getChain(chain.ID); err == nil {
				chain.CreatedAt = existing.CreatedAt
				if in.Enabled == nil {
					chain.Enabled = existing.Enabled
				}
				if strings.TrimSpace(in.Name) == "" {
					chain.Name = existing.Name
				}
				if strings.TrimSpace(in.Strategy) == "" {
					chain.Strategy = normalizeChainStrategy(existing.Strategy)
					if in.BackupDirect == nil {
						chain.BackupDirect = existing.BackupDirect
					}
					if in.FallbackDirect == nil {
						chain.FallbackDirect = existing.FallbackDirect
					}
				}
			} else if !isNotFound(err) {
				return err
			}
		}
		if err := st.saveChain(&chain); err != nil {
			return err
		}
		chainID = chain.ID
		if err := st.replaceLandings(&chain, landingRows); err != nil {
			return err
		}
		for i := range landingRows {
			if _, err := st.ensureRelayUser(&landingRows[i]); err != nil {
				return err
			}
			affected = append(affected, landingRows[i].NodeUUID)
		}
		keep := map[string]struct{}{}
		byNode := map[string][]models.Inbound{}
		for _, source := range sourceRows {
			byNode[source.NodeUUID] = append(byNode[source.NodeUUID], source)
		}
		for nodeUUID, nodeSources := range byNode {
			group, err := st.materializeNodeHops(&chain, landingRows, nodeUUID, nodeSources[0].Core)
			if err != nil {
				return err
			}
			for i, source := range nodeSources {
				src := source
				link, err := st.materializeLink(&chain, &src, group, i)
				if err != nil {
					return err
				}
				keep[link.SourceInboundID] = struct{}{}
				affected = append(affected, source.NodeUUID)
			}
		}
		dropped, err := st.dropUnkeptLinks(chain.ID, keep)
		if err != nil {
			return err
		}
		affected = append(affected, dropped...)
		return st.dropUnusedManagedOutbounds(chain.ID)
	})
	if err != nil {
		return nil, nil, err
	}
	view, err := s.GetChainView(chainID)
	if err != nil {
		return nil, uniqueIDs(affected), err
	}
	return view, uniqueIDs(affected), nil
}

func (s *Store) DeleteChain(id string) ([]string, error) {
	var affected []string
	err := s.db.Transaction(func(tx *gorm.DB) error {
		nodes, err := deleteChainTx(tx, strings.TrimSpace(id))
		affected = nodes
		return err
	})
	return uniqueIDs(affected), err
}

func (s *Store) DetachInboundChains(inboundID string) ([]string, error) {
	inboundID = strings.TrimSpace(inboundID)
	if inboundID == "" {
		return nil, nil
	}
	var affected []string
	err := s.db.Transaction(func(tx *gorm.DB) error {
		nodes, err := detachInboundChainsTx(tx, inboundID)
		affected = nodes
		return err
	})
	return uniqueIDs(affected), err
}

func (s *Store) SyncChainsForLanding(inboundID string) ([]string, error) {
	inboundID = strings.TrimSpace(inboundID)
	if inboundID == "" {
		return nil, nil
	}
	chains, err := s.chainsUsingInbound(inboundID)
	if err != nil {
		return nil, err
	}
	var affected []string
	for i := range chains {
		view, err := s.chainView(chains[i])
		if err != nil {
			return affected, err
		}
		sourceIDs := make([]string, 0, len(view.Sources))
		for _, hop := range view.Sources {
			sourceIDs = append(sourceIDs, hop.SourceInboundID)
		}
		landingIDs := make([]string, 0, len(view.Landings))
		for _, row := range view.Landings {
			landingIDs = append(landingIDs, row.LandingInboundID)
		}
		if len(sourceIDs) == 0 || len(landingIDs) == 0 {
			continue
		}
		enabled := chains[i].Enabled
		strategy, backup, fallback := interpretChainHA(chains[i].Strategy, chains[i].BackupDirect, chains[i].FallbackDirect, len(landingIDs))
		_, nodes, err := s.UpsertChain(ChainUpsert{
			ID:                chains[i].ID,
			Name:              chains[i].Name,
			Strategy:          strategy,
			BackupDirect:      &backup,
			FallbackDirect:    &fallback,
			LandingInboundIDs: landingIDs,
			SourceInboundIDs:  sourceIDs,
			Enabled:           &enabled,
		})
		affected = append(affected, nodes...)
		if err != nil {
			return uniqueIDs(affected), err
		}
	}
	return uniqueIDs(affected), nil
}

func (s *Store) ChainManagedOutbound(id string) bool {
	row, err := s.GetOutbound(id)
	if err != nil {
		return false
	}
	return settingsFlag(row.SettingsJSON, "chain_managed")
}

func (s *Store) ChainManagedRoute(id string) bool {
	row, err := s.GetRoute(id)
	if err != nil {
		return false
	}
	return settingsFlag(row.RuleJSON, "chain_managed")
}

// InboundBoundToChain reports whether this inbound is a forwarding 线路入站.
// 落地入站 only receives hops from other nodes, so routes and outbounds on
// that inbound stay allowed.
func (s *Store) InboundBoundToChain(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	var n int64
	if err := s.db.Model(&models.ForwardLink{}).Where("source_inbound_id = ?", id).Count(&n).Error; err != nil {
		return false
	}
	return n > 0
}

func (s *Store) inboundHasManualForwarding(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	var routes []models.Route
	if err := s.db.Find(&routes).Error; err != nil {
		return err
	}
	for _, row := range routes {
		if settingsFlag(row.RuleJSON, "chain_managed") {
			continue
		}
		if routeRuleInboundID(row.RuleJSON) == id {
			return fmt.Errorf("%w: chain_route_in_use", ErrConflict)
		}
	}
	var outs []models.Outbound
	if err := s.db.Find(&outs).Error; err != nil {
		return err
	}
	for _, row := range outs {
		if settingsFlag(row.SettingsJSON, "chain_managed") {
			continue
		}
		if settingsString(row.SettingsJSON, "source_inbound_id") == id || settingsString(row.SettingsJSON, "landing_inbound_id") == id {
			return fmt.Errorf("%w: chain_outbound_in_use", ErrConflict)
		}
	}
	return nil
}

func (s *Store) chainView(row models.ForwardChain) (ChainView, error) {
	view := ChainView{
		ForwardChain: row,
		Landings:     []ChainLandingView{},
		LandingNames: []string{},
		Sources:      []ChainHopView{},
		SourceNames:  []string{},
	}
	view.Strategy = normalizeChainStrategy(row.Strategy)
	var landings []models.ForwardLanding
	if err := s.db.Where("chain_id = ?", row.ID).Order("sort_index ASC, created_at ASC").Find(&landings).Error; err != nil {
		return view, err
	}
	for _, item := range landings {
		hop := ChainLandingView{ID: item.ID, LandingInboundID: item.LandingInboundID}
		if landing, err := s.GetInbound(item.LandingInboundID); err == nil {
			hop.LandingName = landing.Name
			hop.LandingNodeUUID = landing.NodeUUID
			hop.LandingProtocol = landing.Protocol
			hop.LandingPort = landing.Port
		}
		view.Landings = append(view.Landings, hop)
		if hop.LandingName != "" {
			view.LandingNames = append(view.LandingNames, hop.LandingName)
		}
	}
	var links []models.ForwardLink
	if err := s.db.Where("chain_id = ?", row.ID).Order("sort_index ASC, created_at ASC").Find(&links).Error; err != nil {
		return view, err
	}
	for _, link := range links {
		hop := ChainHopView{
			ID:              link.ID,
			SourceInboundID: link.SourceInboundID,
			OutboundID:      link.OutboundID,
			RouteID:         link.RouteID,
		}
		if source, err := s.GetInbound(link.SourceInboundID); err == nil {
			hop.SourceName = source.Name
			hop.SourceNodeUUID = source.NodeUUID
			hop.SourceProtocol = source.Protocol
			hop.SourcePort = source.Port
		}
		view.Sources = append(view.Sources, hop)
		if hop.SourceName != "" {
			view.SourceNames = append(view.SourceNames, hop.SourceName)
		}
	}
	view.Strategy, view.BackupDirect, view.FallbackDirect = interpretChainHA(view.Strategy, view.BackupDirect, view.FallbackDirect, len(view.Landings))
	return view, nil
}

func chainOnNode(view ChainView, nodeUUID string) bool {
	for _, landing := range view.Landings {
		if landing.LandingNodeUUID == nodeUUID {
			return true
		}
	}
	for _, hop := range view.Sources {
		if hop.SourceNodeUUID == nodeUUID {
			return true
		}
	}
	return false
}

func (s *Store) getChain(id string) (*models.ForwardChain, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}
	var row models.ForwardChain
	err := s.db.First(&row, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) saveChain(row *models.ForwardChain) error {
	if row.ID == "" {
		row.ID = newID()
	}
	s.keepCreatedAt(&models.ForwardChain{}, row.ID, &row.CreatedAt)
	row.UpdatedAt = now()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.saveAll(row)
}

func (s *Store) chainsUsingInbound(inboundID string) ([]models.ForwardChain, error) {
	inboundID = strings.TrimSpace(inboundID)
	ids := map[string]struct{}{}
	var landings []models.ForwardLanding
	if err := s.db.Where("landing_inbound_id = ?", inboundID).Find(&landings).Error; err != nil {
		return nil, err
	}
	for _, row := range landings {
		ids[row.ChainID] = struct{}{}
	}
	if link, err := s.linkBySource(inboundID); err == nil {
		ids[link.ChainID] = struct{}{}
	} else if !isNotFound(err) {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	var chains []models.ForwardChain
	if err := s.db.Where("id IN ?", keys).Order("created_at ASC").Find(&chains).Error; err != nil {
		return nil, err
	}
	return chains, nil
}

func (s *Store) replaceLandings(chain *models.ForwardChain, landings []models.Inbound) error {
	if err := s.db.Where("chain_id = ?", chain.ID).Delete(&models.ForwardLanding{}).Error; err != nil {
		return err
	}
	nowTs := now()
	for i, landing := range landings {
		row := models.ForwardLanding{
			ID:               newID(),
			ChainID:          chain.ID,
			LandingInboundID: landing.ID,
			SortIndex:        i,
			CreatedAt:        nowTs,
			UpdatedAt:        nowTs,
		}
		if err := s.db.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) chainGraphOK(chainID string, landings, sources []string) error {
	var links []models.ForwardLink
	if err := s.db.Find(&links).Error; err != nil {
		return err
	}
	var rows []models.ForwardLanding
	if err := s.db.Find(&rows).Error; err != nil {
		return err
	}
	landingsOf := map[string][]string{}
	for _, row := range rows {
		if row.ChainID == chainID {
			continue
		}
		landingsOf[row.ChainID] = append(landingsOf[row.ChainID], row.LandingInboundID)
	}
	edges := map[string][]string{}
	for _, link := range links {
		if link.ChainID == chainID {
			continue
		}
		if owned, err := s.linkBySource(link.SourceInboundID); err == nil && owned.ChainID != chainID && chainID != "" {
			if owned.SourceInboundID == link.SourceInboundID {
				// keep existing occupancy check below
			}
		}
		edges[link.SourceInboundID] = append(edges[link.SourceInboundID], landingsOf[link.ChainID]...)
	}
	sourceSet := map[string]struct{}{}
	for _, source := range sources {
		sourceSet[source] = struct{}{}
		if owned, err := s.linkBySource(source); err == nil && owned.ChainID != chainID {
			return fmt.Errorf("%w: chain_source_in_use", ErrConflict)
		} else if err != nil && !isNotFound(err) {
			return err
		}
		edges[source] = append(edges[source], landings...)
	}
	for _, landing := range landings {
		if chainReachesAny(edges, landing, sourceSet) {
			return fmt.Errorf("%w: chain_cycle", ErrInvalid)
		}
	}
	return nil
}

func chainReachesAny(edges map[string][]string, start string, targets map[string]struct{}) bool {
	seen := map[string]struct{}{}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if _, ok := targets[cur]; ok {
			return true
		}
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}
		queue = append(queue, edges[cur]...)
	}
	return false
}

func (s *Store) linkBySource(sourceID string) (*models.ForwardLink, error) {
	var row models.ForwardLink
	err := s.db.First(&row, "source_inbound_id = ?", strings.TrimSpace(sourceID)).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) materializeNodeHops(chain *models.ForwardChain, landings []models.Inbound, nodeUUID, core string) (*models.Outbound, error) {
	hops := make([]*models.Outbound, 0, len(landings))
	ids := make([]string, 0, len(landings))
	for i := range landings {
		hop, err := s.upsertHopOutbound(chain, &landings[i], nodeUUID, core)
		if err != nil {
			return nil, err
		}
		hops = append(hops, hop)
		ids = append(ids, hop.ID)
	}
	if !chainNeedsGroup(chain, len(hops)) {
		return hops[0], nil
	}
	return s.upsertGroupOutbound(chain, nodeUUID, core, ids)
}

func chainNeedsGroup(chain *models.ForwardChain, landingCount int) bool {
	switch normalizeChainStrategy(chain.Strategy) {
	case chainStrategyFailover:
		return chain.BackupDirect || landingCount > 1 || chain.FallbackDirect
	case chainStrategyURLTest:
		return landingCount > 1 || chain.FallbackDirect
	default:
		return false
	}
}

func (s *Store) materializeLink(chain *models.ForwardChain, source *models.Inbound, outbound *models.Outbound, sort int) (*models.ForwardLink, error) {
	link := models.ForwardLink{
		ChainID:         chain.ID,
		SourceInboundID: source.ID,
		SortIndex:       sort,
	}
	if existing, err := s.linkBySource(source.ID); err == nil {
		link = *existing
		link.ChainID = chain.ID
		link.SortIndex = sort
	} else if !isNotFound(err) {
		return nil, err
	}
	route, err := s.upsertManagedRoute(chain, source, outbound)
	if err != nil {
		return nil, err
	}
	link.OutboundID = outbound.ID
	link.RouteID = route.ID
	if link.ID == "" {
		link.ID = newID()
	}
	s.keepCreatedAt(&models.ForwardLink{}, link.ID, &link.CreatedAt)
	link.UpdatedAt = now()
	if link.CreatedAt.IsZero() {
		link.CreatedAt = link.UpdatedAt
	}
	if err := s.saveAll(&link); err != nil {
		return nil, err
	}
	return &link, nil
}

func (s *Store) upsertHopOutbound(chain *models.ForwardChain, landing *models.Inbound, nodeUUID, core string) (*models.Outbound, error) {
	settings, err := s.outboundSettingsFromLanding(chain.ID, landing)
	if err != nil {
		return nil, err
	}
	row := &models.Outbound{
		NodeUUID:     nodeUUID,
		Core:         core,
		Name:         managedOutboundName(landing),
		Protocol:     landing.Protocol,
		SettingsJSON: settings,
		Enabled:      chain.Enabled,
	}
	if existing, err := s.managedOutboundOnNode(nodeUUID, landing.ID); err == nil && !settingsFlag(existing.SettingsJSON, "chain_group") {
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
		row.Name = existing.Name
	} else if err != nil && !isNotFound(err) {
		return nil, err
	}
	if err := s.UpsertOutbound(row); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) upsertGroupOutbound(chain *models.ForwardChain, nodeUUID, core string, memberIDs []string) (*models.Outbound, error) {
	proto := chainGroupProtocol
	if normalizeChainStrategy(chain.Strategy) == chainStrategyFailover {
		proto = "failover"
	}
	settings, _ := json.Marshal(map[string]any{
		"chain_id":        chain.ID,
		"chain_managed":   true,
		"chain_group":     true,
		"strategy":        normalizeChainStrategy(chain.Strategy),
		"backup_direct":   chain.BackupDirect,
		"fallback_direct": chain.FallbackDirect,
		"member_ids":      memberIDs,
		"interval":        "1m",
	})
	row := &models.Outbound{
		NodeUUID:     nodeUUID,
		Core:         core,
		Name:         managedGroupName(chain, nodeUUID),
		Protocol:     proto,
		SettingsJSON: string(settings),
		Enabled:      chain.Enabled,
	}
	if existing, err := s.managedGroupOnNode(nodeUUID, chain.ID); err == nil {
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
		row.Name = existing.Name
	} else if !isNotFound(err) {
		return nil, err
	}
	if err := s.UpsertOutbound(row); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) managedGroupOnNode(nodeUUID, chainID string) (*models.Outbound, error) {
	var rows []models.Outbound
	if err := s.db.Where("node_uuid = ?", nodeUUID).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		if settingsString(rows[i].SettingsJSON, "chain_id") == chainID && settingsFlag(rows[i].SettingsJSON, "chain_group") {
			return &rows[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) dropUnusedManagedOutbounds(chainID string) error {
	var rows []models.Outbound
	if err := s.db.Find(&rows).Error; err != nil {
		return err
	}
	used := map[string]struct{}{}
	var links []models.ForwardLink
	if err := s.db.Where("chain_id = ?", chainID).Find(&links).Error; err != nil {
		return err
	}
	for _, link := range links {
		used[link.OutboundID] = struct{}{}
	}
	for i := range rows {
		if settingsString(rows[i].SettingsJSON, "chain_id") != chainID || !settingsFlag(rows[i].SettingsJSON, "chain_managed") {
			continue
		}
		if settingsFlag(rows[i].SettingsJSON, "chain_group") {
			if _, ok := used[rows[i].ID]; ok {
				continue
			}
			if err := s.db.Delete(&models.Outbound{}, "id = ?", rows[i].ID).Error; err != nil {
				return err
			}
			continue
		}
		var n int64
		if err := s.db.Model(&models.ForwardLink{}).Where("outbound_id = ?", rows[i].ID).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		keep := false
		for j := range rows {
			if !settingsFlag(rows[j].SettingsJSON, "chain_group") {
				continue
			}
			for _, id := range settingsStringList(rows[j].SettingsJSON, "member_ids") {
				if id == rows[i].ID {
					keep = true
					break
				}
			}
			if keep {
				break
			}
		}
		if keep {
			continue
		}
		if err := s.db.Delete(&models.Outbound{}, "id = ?", rows[i].ID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertManagedRoute(chain *models.ForwardChain, source *models.Inbound, outbound *models.Outbound) (*models.Route, error) {
	rule, _ := json.Marshal(map[string]any{
		"inbound_id":    source.ID,
		"outbound_id":   outbound.ID,
		"chain_id":      chain.ID,
		"chain_managed": true,
		"domain":        "",
		"ip":            "",
		"network":       "",
		"protocol":      "",
		"port":          "",
		"source":        "",
	})
	row := &models.Route{
		NodeUUID: source.NodeUUID,
		Name:     managedRouteName(source),
		Priority: 0,
		RuleJSON: string(rule),
		Enabled:  chain.Enabled,
	}
	if existing, err := s.managedRouteForSource(source.ID); err == nil {
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
		row.Name = existing.Name
		row.Priority = existing.Priority
	} else if !isNotFound(err) {
		return nil, err
	}
	if err := s.UpsertRoute(row); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) managedOutboundOnNode(nodeUUID, landingID string) (*models.Outbound, error) {
	var rows []models.Outbound
	if err := s.db.Where("node_uuid = ?", nodeUUID).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		if settingsFlag(rows[i].SettingsJSON, "chain_group") {
			continue
		}
		if settingsString(rows[i].SettingsJSON, "landing_inbound_id") == landingID && settingsFlag(rows[i].SettingsJSON, "chain_managed") {
			return &rows[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) managedRouteForSource(sourceID string) (*models.Route, error) {
	var rows []models.Route
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		if settingsString(rows[i].RuleJSON, "inbound_id") == sourceID && settingsFlag(rows[i].RuleJSON, "chain_managed") {
			return &rows[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) dropUnkeptLinks(chainID string, keep map[string]struct{}) ([]string, error) {
	var links []models.ForwardLink
	if err := s.db.Where("chain_id = ?", chainID).Find(&links).Error; err != nil {
		return nil, err
	}
	var affected []string
	for _, link := range links {
		if _, ok := keep[link.SourceInboundID]; ok {
			continue
		}
		if source, err := s.GetInbound(link.SourceInboundID); err == nil {
			affected = append(affected, source.NodeUUID)
		}
		if err := s.db.Delete(&models.ForwardLink{}, "id = ?", link.ID).Error; err != nil {
			return affected, err
		}
		if err := s.deleteManagedRoute(link.RouteID); err != nil {
			return affected, err
		}
		if err := s.deleteOutboundIfUnused(link.OutboundID); err != nil {
			return affected, err
		}
	}
	return affected, nil
}

func (s *Store) deleteManagedRoute(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	return s.db.Delete(&models.Route{}, "id = ?", id).Error
}

func (s *Store) deleteOutboundIfUnused(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	var n int64
	if err := s.db.Model(&models.ForwardLink{}).Where("outbound_id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.db.Delete(&models.Outbound{}, "id = ?", id).Error
}

func deleteChainTx(tx *gorm.DB, id string) ([]string, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	st := New(tx)
	if _, err := st.getChain(id); err != nil {
		return nil, err
	}
	var affected []string
	var landings []models.ForwardLanding
	if err := tx.Where("chain_id = ?", id).Find(&landings).Error; err != nil {
		return nil, err
	}
	for _, row := range landings {
		if landing, err := st.GetInbound(row.LandingInboundID); err == nil {
			affected = append(affected, landing.NodeUUID)
		}
	}
	keep := map[string]struct{}{}
	dropped, err := st.dropUnkeptLinks(id, keep)
	if err != nil {
		return affected, err
	}
	affected = append(affected, dropped...)
	if err := st.dropUnusedManagedOutbounds(id); err != nil {
		return affected, err
	}
	if err := tx.Where("chain_id = ?", id).Delete(&models.ForwardLanding{}).Error; err != nil {
		return affected, err
	}
	if err := tx.Delete(&models.ForwardChain{}, "id = ?", id).Error; err != nil {
		return affected, err
	}
	return affected, nil
}

func detachInboundChainsTx(tx *gorm.DB, inboundID string) ([]string, error) {
	st := New(tx)
	var affected []string
	chains, err := st.chainsUsingInbound(inboundID)
	if err != nil {
		return nil, err
	}
	for i := range chains {
		var landingCount int64
		if err := tx.Model(&models.ForwardLanding{}).Where("chain_id = ?", chains[i].ID).Count(&landingCount).Error; err != nil {
			return affected, err
		}
		var sourceCount int64
		if err := tx.Model(&models.ForwardLink{}).Where("chain_id = ?", chains[i].ID).Count(&sourceCount).Error; err != nil {
			return affected, err
		}
		landingHit := tx.Where("chain_id = ? AND landing_inbound_id = ?", chains[i].ID, inboundID).Delete(&models.ForwardLanding{})
		if landingHit.Error != nil {
			return affected, landingHit.Error
		}
		if link, err := st.linkBySource(inboundID); err == nil && link.ChainID == chains[i].ID {
			if source, err := st.GetInbound(inboundID); err == nil {
				affected = append(affected, source.NodeUUID)
			}
			if err := tx.Delete(&models.ForwardLink{}, "id = ?", link.ID).Error; err != nil {
				return affected, err
			}
			if err := st.deleteManagedRoute(link.RouteID); err != nil {
				return affected, err
			}
			if err := st.deleteOutboundIfUnused(link.OutboundID); err != nil {
				return affected, err
			}
			sourceCount--
		} else if err != nil && !isNotFound(err) {
			return affected, err
		}
		if landingHit.RowsAffected > 0 {
			landingCount -= landingHit.RowsAffected
		}
		if landingCount <= 0 || sourceCount <= 0 {
			nodes, delErr := deleteChainTx(tx, chains[i].ID)
			affected = append(affected, nodes...)
			if delErr != nil && !isNotFound(delErr) {
				return affected, delErr
			}
			continue
		}
		if nodes, err := st.rebuildChainHops(&chains[i]); err != nil {
			return affected, err
		} else {
			affected = append(affected, nodes...)
		}
	}
	return affected, nil
}

func (s *Store) rebuildChainHops(chain *models.ForwardChain) ([]string, error) {
	view, err := s.chainView(*chain)
	if err != nil {
		return nil, err
	}
	landingRows := make([]models.Inbound, 0, len(view.Landings))
	for _, row := range view.Landings {
		landing, err := s.GetInbound(row.LandingInboundID)
		if err != nil {
			return nil, err
		}
		landingRows = append(landingRows, *landing)
	}
	byNode := map[string][]models.Inbound{}
	var affected []string
	for _, hop := range view.Sources {
		source, err := s.GetInbound(hop.SourceInboundID)
		if err != nil {
			return affected, err
		}
		byNode[source.NodeUUID] = append(byNode[source.NodeUUID], *source)
		affected = append(affected, source.NodeUUID)
	}
	keep := map[string]struct{}{}
	for nodeUUID, nodeSources := range byNode {
		group, err := s.materializeNodeHops(chain, landingRows, nodeUUID, nodeSources[0].Core)
		if err != nil {
			return affected, err
		}
		for i := range nodeSources {
			src := nodeSources[i]
			link, err := s.materializeLink(chain, &src, group, i)
			if err != nil {
				return affected, err
			}
			keep[link.SourceInboundID] = struct{}{}
		}
	}
	if _, err := s.dropUnkeptLinks(chain.ID, keep); err != nil {
		return affected, err
	}
	return affected, s.dropUnusedManagedOutbounds(chain.ID)
}

func (s *Store) ensureRelayUser(landing *models.Inbound) (*models.NodeUser, error) {
	if user, err := s.relayUserForInbound(landing.ID); err == nil {
		if err := s.EnsureGrant(user.ID, landing.ID); err != nil {
			return nil, err
		}
		return user, nil
	} else if !isNotFound(err) {
		return nil, err
	}
	user := &models.NodeUser{
		NodeUUID:    landing.NodeUUID,
		Username:    relayUsernamePrefix + landing.ID,
		DisplayName: strings.TrimSpace(landing.Name),
		Kind:        models.UserKindRelay,
		Status:      models.UserActive,
	}
	if user.DisplayName == "" {
		user.DisplayName = "relay"
	}
	if err := s.UpsertUser(user); err != nil {
		return nil, err
	}
	if _, _, err := s.IssueCredential(user.ID, "uuid", "", nil); err != nil {
		return nil, err
	}
	if err := s.EnsureGrant(user.ID, landing.ID); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) relayUserForInbound(inboundID string) (*models.NodeUser, error) {
	var grants []models.Grant
	if err := s.db.Where("inbound_id = ?", inboundID).Find(&grants).Error; err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.UserID)
	}
	if len(ids) == 0 {
		return nil, ErrNotFound
	}
	var users []models.NodeUser
	if err := s.db.Where("id IN ? AND kind = ?", ids, models.UserKindRelay).Order("created_at ASC").Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, ErrNotFound
	}
	return &users[0], nil
}

func (s *Store) EnsureGrant(userID, inboundID string) error {
	userID = strings.TrimSpace(userID)
	inboundID = strings.TrimSpace(inboundID)
	if userID == "" || inboundID == "" {
		return fmt.Errorf("%w: grant required", ErrInvalid)
	}
	var n int64
	if err := s.db.Model(&models.Grant{}).Where("user_id = ? AND inbound_id = ?", userID, inboundID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.db.Create(&models.Grant{ID: newID(), UserID: userID, InboundID: inboundID, CreatedAt: now()}).Error
}

func (s *Store) outboundSettingsFromLanding(chainID string, landing *models.Inbound) (string, error) {
	cfg := inboundcfg.Parse(landing.SettingsJSON)
	host, port, ok := s.landingDial(landing, cfg)
	if !ok {
		return "", fmt.Errorf("%w: chain_no_address", ErrInvalid)
	}
	user, err := s.ensureRelayUser(landing)
	if err != nil {
		return "", err
	}
	creds, err := s.ListCredentials(user.ID)
	if err != nil {
		return "", err
	}
	uuid, secret := relaySecret(creds)
	if uuid == "" && secret == "" && !httpLike(landing.Protocol) {
		return "", fmt.Errorf("%w: empty secret", ErrInvalid)
	}
	if secret == "" {
		secret = uuid
	}
	password := secret
	if strings.EqualFold(landing.Protocol, "shadowsocks") {
		method := cfg.SSMethod
		if method == "" {
			method = inboundcfg.DefaultSSMethod()
		}
		if inboundcfg.IsSS2022(method) {
			password = inboundcfg.SS2022SharePassword(cfg.SSPassword, secret, landing.ID, method)
		}
	}
	username := ""
	if httpLike(landing.Protocol) {
		if len(cfg.Accounts) > 0 {
			username = cfg.Accounts[0].User
			if cfg.Accounts[0].Pass != "" {
				password = cfg.Accounts[0].Pass
			}
		} else {
			username = user.Username
		}
	}
	transport := cfg.Transport
	if transport == "" {
		transport = inboundcfg.DefaultTransport(landing.Protocol)
	}
	security := cfg.Security
	if security == "" {
		security = inboundcfg.DefaultSecurity(landing.Protocol)
	}
	item := map[string]any{
		"address":            host,
		"port":               port,
		"username":           username,
		"password":           password,
		"uuid":               uuid,
		"flow":               cfg.Flow,
		"domain_strategy":    "AsIs",
		"transport":          transport,
		"security":           security,
		"sni":                inboundcfg.ShareSNI(cfg),
		"fingerprint":        cfg.Fingerprint,
		"ws_path":            cfg.WSPath,
		"ws_host":            cfg.WSHost,
		"grpc_service":       cfg.GRPCService,
		"ss_method":          cfg.SSMethod,
		"reality_public_key": cfg.RealityPublicKey,
		"reality_short_id":   cfg.RealityShortID,
		"spider_x":           cfg.SpiderX,
		"source_inbound_id":  landing.ID,
		"landing_inbound_id": landing.ID,
		"chain_id":           chainID,
		"chain_managed":      true,
	}
	if strings.EqualFold(landing.Protocol, "shadowsocks") {
		method := cfg.SSMethod
		if method == "" {
			method = inboundcfg.DefaultSSMethod()
		}
		item["ss_method"] = method
		item["ss_network"] = inboundcfg.NormalizeSSNetwork(transport)
		item["transport"] = "tcp"
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Store) landingDial(landing *models.Inbound, cfg inboundcfg.Settings) (string, int, bool) {
	ipv4, ipv6 := s.nodeIPs(landing.NodeUUID)
	certDomain := s.certDomain(landing.NodeUUID, cfg.CertID)
	host := ""
	switch inboundcfg.NormalizeShareStrategy(cfg.ShareStrategy) {
	case "listen":
		host = unwrapHost(landing.Listen)
	case "other":
		host = strings.TrimSpace(cfg.PublicHost)
	case "none":
		host = strings.TrimSpace(cfg.PublicHost)
		if host == "" {
			host = strings.TrimSpace(cfg.TLSDomain)
		}
		if host == "" {
			host = certDomain
		}
		if host == "" {
			host = stackHost(cfg.Stack, ipv4, ipv6)
		}
		if host == "" {
			host = unwrapHost(landing.Listen)
		}
	default:
		host = strings.TrimSpace(cfg.TLSDomain)
		if host == "" {
			host = certDomain
		}
		if host == "" {
			host = stackHost(cfg.Stack, ipv4, ipv6)
		}
	}
	host = canonicalHost(host)
	port := landing.Port
	if cfg.PublicPort > 0 && cfg.PublicPort <= 65535 {
		port = cfg.PublicPort
	}
	if inboundcfg.IsWildcardListen(host) || host == "" || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func (s *Store) nodeIPs(nodeUUID string) (string, string) {
	if strings.TrimSpace(nodeUUID) == "" || !s.db.Migrator().HasTable("clients") {
		return "", ""
	}
	var row struct {
		IPv4 string
		IPv6 string
	}
	if err := s.db.Table("clients").Select("ipv4", "ipv6").Where("uuid = ?", nodeUUID).Take(&row).Error; err != nil {
		return "", ""
	}
	return strings.TrimSpace(row.IPv4), strings.TrimSpace(row.IPv6)
}

func (s *Store) certDomain(nodeUUID, certID string) string {
	certs, err := s.ListCerts(nodeUUID)
	if err != nil {
		return ""
	}
	for _, row := range certs {
		if !strings.EqualFold(strings.TrimSpace(row.Status), models.CertIssued) {
			continue
		}
		domain := cert.UsableShareHost(row.Domain, row.ShareDomain)
		if domain == "" {
			continue
		}
		if certID != "" && row.ID == certID {
			return domain
		}
	}
	for _, row := range certs {
		if !strings.EqualFold(strings.TrimSpace(row.Status), models.CertIssued) {
			continue
		}
		if domain := cert.UsableShareHost(row.Domain, row.ShareDomain); domain != "" {
			return domain
		}
	}
	return ""
}

func chainCoreOK(sourceCore, landingProto string) error {
	if strings.EqualFold(strings.TrimSpace(sourceCore), models.CoreXray) && xrayCannotDial(landingProto) {
		return fmt.Errorf("%w: chain_core_mismatch", ErrInvalid)
	}
	return nil
}

func xrayCannotDial(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic", "anytls":
		return true
	default:
		return false
	}
}

func httpLike(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http", "socks":
		return true
	default:
		return false
	}
}

func relaySecret(creds []models.Credential) (id, secret string) {
	for _, c := range creds {
		if !c.Enabled {
			continue
		}
		if id == "" && strings.TrimSpace(c.UUID) != "" {
			id = strings.TrimSpace(c.UUID)
		}
		if secret == "" && strings.TrimSpace(c.SecretMaterial) != "" {
			secret = strings.TrimSpace(c.SecretMaterial)
		}
	}
	return id, secret
}

func normalizeChainStrategy(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case chainStrategyURLTest:
		return chainStrategyURLTest
	case chainStrategyFailover:
		return chainStrategyFailover
	default:
		return chainStrategyNone
	}
}

func interpretChainHA(strategy string, backupDirect, fallbackDirect bool, landingCount int) (string, bool, bool) {
	strategy = normalizeChainStrategy(strategy)
	if landingCount <= 1 {
		if strategy == chainStrategyURLTest {
			return chainStrategyNone, false, false
		}
		if strategy == chainStrategyFailover && !backupDirect {
			if fallbackDirect {
				return chainStrategyFailover, true, false
			}
			return chainStrategyNone, false, false
		}
	}
	if strategy == chainStrategyNone || backupDirect {
		return strategy, backupDirect && strategy == chainStrategyFailover, false
	}
	return strategy, false, fallbackDirect
}

func managedGroupName(chain *models.ForwardChain, nodeUUID string) string {
	return "chain-" + shortID(chain.ID) + "-" + shortID(nodeUUID)
}

func managedOutboundName(landing *models.Inbound) string {
	short := shortID(landing.ID)
	name := strings.TrimSpace(landing.Name)
	if name == "" || reservedOutboundTag("relay-"+name) {
		return "relay-" + short
	}
	return "relay-" + name + "-" + short
}

func settingsStringList(raw, key string) []string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			id := strings.TrimSpace(fmt.Sprint(item))
			if id != "" && id != "<nil>" {
				out = append(out, id)
			}
		}
		return out
	case []string:
		return uniqueIDs(v)
	default:
		return nil
	}
}

func managedRouteName(source *models.Inbound) string {
	name := strings.TrimSpace(source.Name)
	if name == "" {
		return "chain-" + shortID(source.ID)
	}
	return "chain-" + name
}

func shortID(id string) string {
	id = strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func settingsFlag(raw, key string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch n := v.(type) {
	case bool:
		return n
	case string:
		return strings.EqualFold(n, "true") || n == "1"
	default:
		return false
	}
}

func settingsString(raw, key string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func uniqueIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func isNotFound(err error) bool {
	return err != nil && (err == ErrNotFound || err == gorm.ErrRecordNotFound)
}

func unwrapHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) > 2 {
		return host[1 : len(host)-1]
	}
	return host
}

func stackHost(stack, ipv4, ipv6 string) string {
	v4 := strings.TrimSpace(ipv4)
	v6 := strings.TrimSpace(ipv6)
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv4":
		if v4 != "" {
			return v4
		}
		return v6
	default:
		if v6 != "" {
			return v6
		}
		return v4
	}
}

func canonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	lower := strings.ToLower(host)
	switch {
	case strings.HasPrefix(lower, "https://"):
		host = host[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		host = host[len("http://"):]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	host = unwrapHost(strings.TrimSpace(host))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			return ip.String()
		}
		return h
	}
	return host
}
