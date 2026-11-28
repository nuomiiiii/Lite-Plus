package mcp

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nuomiiiii/lite/database/models"
	nmmodels "github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestToolDescriptorsIncludeNodemgtTools(t *testing.T) {
	names := map[string]bool{}
	for _, descriptor := range toolDescriptors() {
		if name, ok := descriptor["name"].(string); ok {
			names[name] = true
		}
	}
	for _, want := range []string{
		"nodemgt_overview",
		"nodemgt_inbounds",
		"nodemgt_outbounds",
		"nodemgt_routes",
		"nodemgt_chains",
		"nodemgt_users",
		"nodemgt_plans",
		"nodemgt_subscriptions",
		"nodemgt_certs",
		"nodemgt_sync",
	} {
		if !names[want] {
			t.Fatalf("missing MCP tool descriptor %q", want)
		}
	}
}

func TestMCPNodemgtEnforcesLeaseNodeAuthorization(t *testing.T) {
	dsn := fmt.Sprintf("file:mcp-nodemgt-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(
		&nmmodels.Inbound{},
		&nmmodels.Outbound{},
		&nmmodels.Route{},
		&nmmodels.Plan{},
		&nmmodels.ControlCommand{},
	); err != nil {
		t.Fatal(err)
	}
	prevDB := mcpNodemgtDB
	mcpNodemgtDB = func() *gorm.DB { return db }
	t.Cleanup(func() { mcpNodemgtDB = prevDB })

	prevLog := mcpNodemgtLogFn
	mcpNodemgtLogFn = nil
	t.Cleanup(func() { mcpNodemgtLogFn = prevLog })

	prevLookup := lookupAuthorizedNode
	lookupAuthorizedNode = func(lease models.MCPLease, uuid string) (models.Client, error) {
		if lease.AllNodes {
			return models.Client{UUID: uuid}, nil
		}
		for _, target := range parseTargetUUIDs(lease.TargetUUIDs) {
			if target == uuid {
				return models.Client{UUID: uuid}, nil
			}
		}
		return models.Client{}, errTool("node is not authorized by this MCP lease")
	}
	t.Cleanup(func() { lookupAuthorizedNode = prevLookup })

	st := store.New(db)
	inA := nmmodels.Inbound{NodeUUID: "node-a", Core: nmmodels.CoreSingBox, Name: "in-a", Protocol: "socks", Listen: "0.0.0.0", Port: 1080, Enabled: true}
	inB := nmmodels.Inbound{NodeUUID: "node-b", Core: nmmodels.CoreSingBox, Name: "in-b", Protocol: "socks", Listen: "0.0.0.0", Port: 1081, Enabled: true}
	if err := st.UpsertInbound(&inA); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertInbound(&inB); err != nil {
		t.Fatal(err)
	}

	scopedLease := models.MCPLease{ID: "lease-a", AllNodes: false, TargetUUIDs: `["node-a"]`}

	// Scoped lease can list only node-a's inbound.
	res, err := callNodemgtTool(nil, scopedLease, "nodemgt_inbounds", map[string]any{"action": "list"})
	if err != nil {
		t.Fatalf("scoped list failed: %v", err)
	}
	listMap := res.(gin.H)
	inbounds := listMap["inbounds"].([]nmmodels.Inbound)
	if len(inbounds) != 1 || inbounds[0].NodeUUID != "node-a" {
		t.Fatalf("expected only node-a inbound, got %+v", inbounds)
	}

	// Scoped lease cannot delete node-b's inbound.
	if _, err := callNodemgtTool(nil, scopedLease, "nodemgt_inbounds", map[string]any{"action": "delete", "id": inB.ID}); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected unauthorized error deleting node-b inbound, got %v", err)
	}

	// Scoped lease cannot manage global users without AllNodes.
	if _, err := callNodemgtTool(nil, scopedLease, "nodemgt_users", map[string]any{"action": "list"}); err == nil || !strings.Contains(err.Error(), "all-nodes") {
		t.Fatalf("expected all-nodes error on nodemgt_users, got %v", err)
	}

	// AllNodes lease can manage global plans.
	allLease := models.MCPLease{ID: "lease-all", AllNodes: true}
	if _, err := callNodemgtTool(nil, allLease, "nodemgt_plans", map[string]any{
		"action":        "upsert",
		"name":          "pro",
		"traffic_bytes": float64(1024),
		"duration_days": float64(30),
	}); err != nil {
		t.Fatalf("all-nodes plan upsert failed: %v", err)
	}
}

func TestMCPNodemgtRedactsSecretsAndPayloads(t *testing.T) {
	dsn := fmt.Sprintf("file:mcp-nodemgt-redact-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(
		&nmmodels.Inbound{},
		&nmmodels.Outbound{},
		&nmmodels.Subscription{},
		&nmmodels.ControlCommand{},
	); err != nil {
		t.Fatal(err)
	}
	prevDB := mcpNodemgtDB
	mcpNodemgtDB = func() *gorm.DB { return db }
	t.Cleanup(func() { mcpNodemgtDB = prevDB })

	prevLog := mcpNodemgtLogFn
	mcpNodemgtLogFn = nil
	t.Cleanup(func() { mcpNodemgtLogFn = prevLog })

	prevLookup := lookupAuthorizedNode
	lookupAuthorizedNode = func(_ models.MCPLease, uuid string) (models.Client, error) {
		return models.Client{UUID: uuid}, nil
	}
	t.Cleanup(func() { lookupAuthorizedNode = prevLookup })

	st := store.New(db)
	in := nmmodels.Inbound{
		NodeUUID:     "node-a",
		Core:         nmmodels.CoreSingBox,
		Name:         "vless-reality",
		Protocol:     "vless",
		Listen:       "0.0.0.0",
		Port:         443,
		SettingsJSON: `{"reality_private_key":"super-secret-priv","ss_password":"super-secret-ss","accounts":[{"user":"alice","pass":"super-secret-pass"}]}`,
		Enabled:      true,
	}
	if err := st.UpsertInbound(&in); err != nil {
		t.Fatal(err)
	}
	out := nmmodels.Outbound{
		NodeUUID:     "node-a",
		Core:         nmmodels.CoreSingBox,
		Name:         "hy2-out",
		Protocol:     "hysteria2",
		SettingsJSON: `{"address":"1.2.3.4","port":443,"password":"super-secret-out-pass"}`,
		Enabled:      true,
	}
	if err := st.UpsertOutbound(&out); err != nil {
		t.Fatal(err)
	}
	sub := nmmodels.Subscription{
		UserID:  "user-1",
		Token:   "super-secret-sub-token",
		Format:  "sing-box",
		Enabled: true,
	}
	if err := st.UpsertSubscription(&sub); err != nil {
		t.Fatal(err)
	}
	cmd := nmmodels.ControlCommand{
		OperationID: "op-1",
		NodeUUID:    "node-a",
		Kind:        "applyConfig",
		PayloadJSON: `{"secret":"never-expose-payload"}`,
		Status:      nmmodels.CmdApplied,
	}
	if err := st.EnqueueCommand(&cmd); err != nil {
		t.Fatal(err)
	}

	allLease := models.MCPLease{ID: "lease-all", AllNodes: true}

	inRes, err := callNodemgtTool(nil, allLease, "nodemgt_inbounds", map[string]any{"action": "list"})
	if err != nil {
		t.Fatal(err)
	}
	inRow := inRes.(gin.H)["inbounds"].([]nmmodels.Inbound)[0]
	if strings.Contains(inRow.SettingsJSON, "super-secret") {
		t.Fatalf("inbound secrets leaked to MCP: %s", inRow.SettingsJSON)
	}

	outRes, err := callNodemgtTool(nil, allLease, "nodemgt_outbounds", map[string]any{"action": "list"})
	if err != nil {
		t.Fatal(err)
	}
	outRow := outRes.(gin.H)["outbounds"].([]nmmodels.Outbound)[0]
	if strings.Contains(outRow.SettingsJSON, "super-secret") {
		t.Fatalf("outbound secrets leaked to MCP: %s", outRow.SettingsJSON)
	}

	subRes, err := callNodemgtTool(nil, allLease, "nodemgt_subscriptions", map[string]any{"action": "list"})
	if err != nil {
		t.Fatal(err)
	}
	subRow := subRes.(gin.H)["subscriptions"].([]nmmodels.Subscription)[0]
	if subRow.Token != mcpMaskedSecret {
		t.Fatalf("subscription token leaked to MCP: %q", subRow.Token)
	}

	statusRes, err := callNodemgtTool(nil, allLease, "nodemgt_sync", map[string]any{"action": "status"})
	if err != nil {
		t.Fatal(err)
	}
	deliveries := statusRes.(gin.H)["delivery"].([]gin.H)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery row, got %d", len(deliveries))
	}
	if _, hasPayload := deliveries[0]["payload_json"]; hasPayload {
		t.Fatalf("control command payload_json must not be exposed to MCP: %+v", deliveries[0])
	}
}
