package jsonrpc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/pkg/rpc"
)

func TestNodemgtRouteUpsertWiresUserIDs(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `UserIDs          json.RawMessage `+"`json:\"user_ids\"`") {
		t.Fatal("route.upsert must accept user_ids")
	}
	if !strings.Contains(text, `"user_ids":           userIDs`) {
		t.Fatal("routeView must return user_ids")
	}
	if !strings.Contains(text, `view["operation_id"] = opID`) {
		t.Fatal("route.upsert must return this save's operation_id")
	}
	if !strings.Contains(text, `json:"operation_id"`) {
		t.Fatal("control.status must look up a command by operation_id")
	}
}

func TestNodemgtRouteUpsertAndViewUserIDs(t *testing.T) {
	db := dbcore.GetDBInstance()
	st := store.New(db)
	node := "route-user-" + uuid.NewString()[:8]
	in := &models.Inbound{
		NodeUUID: node, Core: models.CoreXray, Name: "in-a", Protocol: "vless",
		Listen: "127.0.0.1", Port: 18443, Enabled: true,
	}
	if err := st.UpsertInbound(in); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteInbound(in.ID) })
	alice := &models.NodeUser{NodeUUID: node, Username: "alice-" + uuid.NewString()[:6], Status: models.UserActive}
	bob := &models.NodeUser{NodeUUID: node, Username: "bob-" + uuid.NewString()[:6], Status: models.UserActive}
	if err := st.UpsertUser(alice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUser(bob); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = st.DeleteUser(alice.ID)
		_ = st.DeleteUser(bob.ID)
	})
	if err := st.ReplaceGrants(alice.ID, []string{in.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceGrants(bob.ID, []string{in.ID}); err != nil {
		t.Fatal(err)
	}
	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Principal:  rpc.NewUserPrincipal("admin-1"),
		Permission: rpc.RoleAdmin,
		UserUUID:   "admin-1",
	})
	res, rpcErr := nodemgtRouteUpsert(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		ID:      1,
		Method:  "admin:nodemgt.route.upsert",
		Params: map[string]any{
			"node_uuid":  node,
			"name":       "split",
			"inbound_id": in.ID,
			"outbound_id": "direct",
			"user_ids":   []string{alice.ID, bob.ID, alice.ID},
			"priority":   10,
			"enabled":    true,
		},
	})
	if rpcErr != nil {
		t.Fatalf("upsert: %+v", rpcErr)
	}
	view, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("view type %T", res)
	}
	t.Cleanup(func() {
		id, _ := view["id"].(string)
		if id != "" {
			_ = st.DeleteRoute(id)
		}
	})
	ids, _ := view["user_ids"].([]string)
	if len(ids) != 2 || ids[0] != alice.ID || ids[1] != bob.ID {
		t.Fatalf("user_ids=%v", view["user_ids"])
	}
	raw, _ := json.Marshal(map[string]any{"user_ids": "alice"})
	_, rpcErr = nodemgtRouteUpsert(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		ID:      2,
		Method:  "admin:nodemgt.route.upsert",
		Params:  json.RawMessage(`{"node_uuid":"` + node + `","name":"bad","outbound_id":"direct","user_ids":"alice"}`),
	})
	if rpcErr == nil {
		t.Fatal("string user_ids must fail")
	}
	_ = raw
}
