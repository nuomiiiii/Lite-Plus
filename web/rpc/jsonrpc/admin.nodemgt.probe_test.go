package jsonrpc

import (
	"context"
	"testing"

	"github.com/nuomiiiii/lite/pkg/rpc"
)

func TestNodemgtProbeRPCsDenyAPIKey(t *testing.T) {
	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Permission: rpc.RoleAdmin,
		Principal: &rpc.Principal{
			Type:     rpc.PrincipalAPIKey,
			IsAPIKey: true,
		},
	})
	req := &rpc.JsonRpcRequest{
		Version: "2.0",
		Method:  "admin:nodemgt.outbound.test",
		Params:  map[string]any{"id": "ob-1"},
		ID:      1,
	}
	if _, err := nodemgtOutboundTest(ctx, req); err == nil || err.Code != rpc.PermissionDenied {
		t.Fatalf("expected PermissionDenied for API key on outbound.test, got %+v", err)
	}
	req.Method = "admin:nodemgt.chain.test"
	if _, err := nodemgtChainTest(ctx, req); err == nil || err.Code != rpc.PermissionDenied {
		t.Fatalf("expected PermissionDenied for API key on chain.test, got %+v", err)
	}
}
