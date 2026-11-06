package jsonrpc

import (
	"context"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/pkg/rpc"
)

func nodemgtChainList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListChainViews(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return rows, nil
}

func nodemgtChainUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID                string   `json:"id"`
		Name              string   `json:"name"`
		Strategy          string   `json:"strategy"`
		BackupDirect      *bool    `json:"backup_direct"`
		FallbackDirect    *bool    `json:"fallback_direct"`
		LandingInboundID  string   `json:"landing_inbound_id"`
		LandingInboundIDs []string `json:"landing_inbound_ids"`
		SourceInboundIDs  []string `json:"source_inbound_ids"`
		Enabled           *bool    `json:"enabled"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	landings := append([]string{}, p.LandingInboundIDs...)
	if len(landings) == 0 && strings.TrimSpace(p.LandingInboundID) != "" {
		landings = []string{p.LandingInboundID}
	}
	st := nodemgtST()
	view, nodes, err := st.UpsertChain(store.ChainUpsert{
		ID:                p.ID,
		Name:              p.Name,
		Strategy:          p.Strategy,
		BackupDirect:      p.BackupDirect,
		FallbackDirect:    p.FallbackDirect,
		LandingInboundIDs: landings,
		SourceInboundIDs:  p.SourceInboundIDs,
		Enabled:           p.Enabled,
	})
	if err != nil {
		return nil, nodemgtErr(err)
	}
	target := p.ID
	if view != nil {
		target = view.ID
	}
	_ = nodemgtAudit(ctx, st, "nodemgt.chain.upsert", target, strings.TrimSpace(p.Name))
	nodemgtPushNodes(st, nodes...)
	return view, nil
}

func nodemgtChainDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	row, err := st.GetChainView(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	nodes, err := st.DeleteChain(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	_ = nodemgtAudit(ctx, st, "nodemgt.chain.delete", p.ID, row.Name)
	nodemgtPushNodes(st, nodes...)
	return map[string]any{"ok": true}, nil
}
