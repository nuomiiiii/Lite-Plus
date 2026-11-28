package jsonrpc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/control"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/pkg/rpc"
)

const (
	nodemgtProbeRPCTimeout      = 9 * time.Second
	maxConcurrentChainHopProbes = 8
)

func nodemgtOutboundTag(row *models.Outbound) string {
	if row == nil {
		return ""
	}
	if name := strings.TrimSpace(row.Name); name != "" {
		return name
	}
	return strings.TrimSpace(row.ID)
}

func nodemgtOutboundTest(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := denyAPIKey(ctx); err != nil {
		return nil, err
	}
	var p struct {
		ID string `json:"id"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id is required", nil)
	}
	st := nodemgtST()
	out, err := st.GetOutbound(id)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	tag := nodemgtOutboundTag(out)
	if !out.Enabled {
		return map[string]any{
			"ok":          false,
			"error":       "outbound is disabled",
			"outbound_id": out.ID,
			"node_uuid":   out.NodeUUID,
			"core":        out.Core,
			"tag":         tag,
		}, nil
	}
	res := control.ProbeOutbound(ctx, out.NodeUUID, out.Core, tag, nodemgtProbeRPCTimeout)
	return map[string]any{
		"ok":          res.OK,
		"latency_ms":  res.LatencyMS,
		"status_code": res.StatusCode,
		"error":       res.Error,
		"outbound_id": out.ID,
		"node_uuid":   out.NodeUUID,
		"core":        out.Core,
		"tag":         tag,
	}, nil
}

type chainHopProbeTarget struct {
	sourceNodeUUID   string
	sourceNames      []string
	landingInboundID string
	landingName      string
	landingNodeUUID  string
	outbound         *models.Outbound
}

type chainHopProbeResult struct {
	SourceNodeUUID   string   `json:"source_node_uuid"`
	SourceNames      []string `json:"source_names"`
	LandingInboundID string   `json:"landing_inbound_id,omitempty"`
	LandingName      string   `json:"landing_name,omitempty"`
	LandingNodeUUID  string   `json:"landing_node_uuid,omitempty"`
	OutboundID       string   `json:"outbound_id"`
	Core             string   `json:"core"`
	Tag              string   `json:"tag"`
	OK               bool     `json:"ok"`
	LatencyMS        int64    `json:"latency_ms"`
	StatusCode       int      `json:"status_code,omitempty"`
	Error            string   `json:"error,omitempty"`
}

func resolveChainHopOutbounds(st *store.Store, out *models.Outbound) []*models.Outbound {
	if out == nil {
		return nil
	}
	proto := strings.ToLower(strings.TrimSpace(out.Protocol))
	if proto != "urltest" && proto != "failover" {
		return []*models.Outbound{out}
	}
	var settings struct {
		MemberIDs []string `json:"member_ids"`
	}
	_ = json.Unmarshal([]byte(out.SettingsJSON), &settings)
	var members []*models.Outbound
	for _, memberID := range settings.MemberIDs {
		memberID = strings.TrimSpace(memberID)
		if memberID == "" {
			continue
		}
		if member, err := st.GetOutbound(memberID); err == nil && member != nil {
			members = append(members, member)
		}
	}
	if len(members) == 0 {
		return []*models.Outbound{out}
	}
	return members
}

func outboundLandingInboundID(out *models.Outbound) string {
	if out == nil || strings.TrimSpace(out.SettingsJSON) == "" {
		return ""
	}
	var settings struct {
		LandingInboundID string `json:"landing_inbound_id"`
	}
	_ = json.Unmarshal([]byte(out.SettingsJSON), &settings)
	return strings.TrimSpace(settings.LandingInboundID)
}

func nodemgtChainTest(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := denyAPIKey(ctx); err != nil {
		return nil, err
	}
	var p struct {
		ID string `json:"id"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id is required", nil)
	}
	st := nodemgtST()
	view, err := st.GetChainView(id)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if !view.Enabled {
		return map[string]any{
			"ok":           false,
			"error":        "chain is disabled",
			"chain_id":     view.ID,
			"passed_count": 0,
			"total_count":  0,
			"results":      []chainHopProbeResult{},
		}, nil
	}

	landingByID := make(map[string]store.ChainLandingView, len(view.Landings))
	for _, landing := range view.Landings {
		landingByID[landing.LandingInboundID] = landing
	}

	var targets []*chainHopProbeTarget
	targetByKey := map[string]*chainHopProbeTarget{}

	for _, src := range view.Sources {
		if strings.TrimSpace(src.OutboundID) == "" {
			continue
		}
		rootOut, err := st.GetOutbound(src.OutboundID)
		if err != nil || rootOut == nil {
			continue
		}
		hops := resolveChainHopOutbounds(st, rootOut)
		for _, hopOut := range hops {
			key := hopOut.NodeUUID + "::" + hopOut.ID
			if existing, ok := targetByKey[key]; ok {
				if src.SourceName != "" {
					existing.sourceNames = append(existing.sourceNames, src.SourceName)
				}
				continue
			}
			landingID := outboundLandingInboundID(hopOut)
			landing := landingByID[landingID]
			if landing.LandingInboundID == "" && len(view.Landings) == 1 {
				landing = view.Landings[0]
				landingID = landing.LandingInboundID
			}
			sourceNames := []string{}
			if src.SourceName != "" {
				sourceNames = append(sourceNames, src.SourceName)
			}
			t := &chainHopProbeTarget{
				sourceNodeUUID:   hopOut.NodeUUID,
				sourceNames:      sourceNames,
				landingInboundID: landingID,
				landingName:      landing.LandingName,
				landingNodeUUID:  landing.LandingNodeUUID,
				outbound:         hopOut,
			}
			targetByKey[key] = t
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		return map[string]any{
			"ok":           false,
			"error":        "no forward hops configured",
			"chain_id":     view.ID,
			"passed_count": 0,
			"total_count":  0,
			"results":      []chainHopProbeResult{},
		}, nil
	}

	results := make([]chainHopProbeResult, len(targets))
	sem := make(chan struct{}, maxConcurrentChainHopProbes)
	var wg sync.WaitGroup
	for i, target := range targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tag := nodemgtOutboundTag(target.outbound)
			var probeRes control.OutboundProbeResult
			if !target.outbound.Enabled {
				probeRes = control.OutboundProbeResult{OK: false, Error: "outbound is disabled"}
			} else {
				probeRes = control.ProbeOutbound(ctx, target.outbound.NodeUUID, target.outbound.Core, tag, nodemgtProbeRPCTimeout)
			}
			results[i] = chainHopProbeResult{
				SourceNodeUUID:   target.sourceNodeUUID,
				SourceNames:      target.sourceNames,
				LandingInboundID: target.landingInboundID,
				LandingName:      target.landingName,
				LandingNodeUUID:  target.landingNodeUUID,
				OutboundID:       target.outbound.ID,
				Core:             target.outbound.Core,
				Tag:              tag,
				OK:               probeRes.OK,
				LatencyMS:        probeRes.LatencyMS,
				StatusCode:       probeRes.StatusCode,
				Error:            probeRes.Error,
			}
		}()
	}
	wg.Wait()

	passed := 0
	var minLatency int64
	nodeAnyOK := map[string]bool{}
	var firstErr string
	for _, r := range results {
		if _, seen := nodeAnyOK[r.SourceNodeUUID]; !seen {
			nodeAnyOK[r.SourceNodeUUID] = false
		}
		if r.OK {
			passed++
			nodeAnyOK[r.SourceNodeUUID] = true
			if r.LatencyMS > 0 && (minLatency == 0 || r.LatencyMS < minLatency) {
				minLatency = r.LatencyMS
			}
		} else if firstErr == "" && r.Error != "" {
			firstErr = r.Error
		}
	}

	overallOK := passed == len(results)
	strategy := strings.ToLower(strings.TrimSpace(view.Strategy))
	if strategy == "failover" || strategy == "urltest" {
		overallOK = len(nodeAnyOK) > 0
		for _, ok := range nodeAnyOK {
			if !ok {
				overallOK = false
				break
			}
		}
	}

	resp := map[string]any{
		"ok":             overallOK,
		"chain_id":       view.ID,
		"passed_count":   passed,
		"total_count":    len(results),
		"min_latency_ms": minLatency,
		"results":        results,
	}
	if !overallOK && firstErr != "" {
		resp["error"] = firstErr
	}
	return resp, nil
}
