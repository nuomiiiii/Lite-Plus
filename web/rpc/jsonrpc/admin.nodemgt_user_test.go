package jsonrpc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/pkg/rpc"
)

func TestNodemgtUserListDoesNotMutateDueTrafficResetOnRead(t *testing.T) {
	db := dbcore.GetDBInstance()
	st := store.New(db)
	user := &models.NodeUser{
		ID:                "usr-" + uuid.NewString()[:8],
		NodeUUID:          "node-read-test",
		Username:          "read-only-list",
		Status:            models.UserActive,
		TrafficResetDay:   1,
		TrafficResetCycle: "2020-01",
		QuotaBytes:        1000,
		UsedBytes:         450,
	}
	if err := st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteUser(user.ID) })

	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Principal:  rpc.NewUserPrincipal("admin-1"),
		Permission: rpc.RoleAdmin,
		UserUUID:   "admin-1",
	})
	res, rpcErr := nodemgtUserList(ctx, &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		ID:      1,
		Method:  "admin:nodemgt.user.list",
		Params:  map[string]any{"node_uuid": "node-read-test"},
	})
	if rpcErr != nil {
		t.Fatalf("nodemgtUserList failed: %+v", rpcErr)
	}
	rows, ok := res.([]store.UserView)
	if !ok || len(rows) != 1 || rows[0].ID != user.ID {
		t.Fatalf("unexpected nodemgtUserList result: %#v", res)
	}
	after, err := st.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.UsedBytes != 450 || after.TrafficResetCycle != "2020-01" {
		t.Fatalf("read-only user.list mutated traffic reset state: used=%d cycle=%q", after.UsedBytes, after.TrafficResetCycle)
	}
}

func TestParseOptionalJSONTime(t *testing.T) {
	got, set, err := parseOptionalJSONTime(nil)
	if err != nil || set || got != nil {
		t.Fatalf("omitted: got=%v set=%v err=%v", got, set, err)
	}
	got, set, err = parseOptionalJSONTime(json.RawMessage("null"))
	if err != nil || !set || got != nil {
		t.Fatalf("null: got=%v set=%v err=%v", got, set, err)
	}
	raw := json.RawMessage(`"2026-10-26T00:00:00Z"`)
	got, set, err = parseOptionalJSONTime(raw)
	want := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	if err != nil || !set || got == nil || !got.Equal(want) {
		t.Fatalf("rfc3339: got=%v set=%v err=%v", got, set, err)
	}
}

func TestNodemgtSettingsMetadataFlagsDoNotRestartListener(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `SubPublishName     *bool   `+"`json:\"sub_publish_name\"`") {
		t.Fatal("settings.set must treat sub_publish_name as optional")
	}
	if !strings.Contains(text, `SubPublishUserinfo *bool   `+"`json:\"sub_publish_userinfo\"`") {
		t.Fatal("settings.set must treat sub_publish_userinfo as optional")
	}
	if !strings.Contains(text, `restartSub := p.SubListenPort != nil || p.SubPath != nil || p.SubReuseHTTPS != nil`) {
		t.Fatal("subscription listener restart must stay limited to port, path, and HTTPS reuse")
	}
	if strings.Contains(text, "restartSub") && strings.Contains(text, "SubPublishName != nil || p.SubPublishUserinfo") {
		t.Fatal("metadata flags must not restart the subscription listener")
	}
}

func TestNodemgtUserUpsertAuditsAfterTransaction(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, `return nodemgtAudit(ctx, st, "nodemgt.user.upsert"`) {
		t.Fatal("user.upsert still writes the audit row inside the sqlite transaction")
	}
	if !strings.Contains(text, `	}); txErr != nil {
		return nil, nodemgtErr(txErr)
	}
	_ = nodemgtAudit(ctx, nodemgtST(), "nodemgt.user.upsert", p.ID, p.Username)`) {
		t.Fatal("user.upsert must write the audit row after the sqlite transaction commits")
	}
}

func TestNodemgtShouldClearPlan(t *testing.T) {
	if nodemgtShouldClearPlan("", false) {
		t.Fatal("new user with no plan must not unassign")
	}
	if nodemgtShouldClearPlan("plan-1", true) {
		t.Fatal("keeping or switching a plan must not unassign")
	}
	if nodemgtShouldClearPlan("plan-1", false) {
		t.Fatal("assigning a plan to a user without one must not unassign")
	}
	if !nodemgtShouldClearPlan("", true) {
		t.Fatal("clearing an existing plan must unassign")
	}
}

func TestNodemgtSecretAndCertRPCsRejectAPIKey(t *testing.T) {
	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Principal:  rpc.NewAPIKeyPrincipal(),
		Permission: rpc.RoleAdmin,
	})
	cases := []struct {
		name string
		call func(context.Context, *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError)
	}{
		{"inbound.list", nodemgtInboundList},
		{"inbound.upsert", nodemgtInboundUpsert},
		{"inbound.delete", nodemgtInboundDelete},
		{"inbound.reorder", nodemgtInboundReorder},
		{"outbound.list", nodemgtOutboundList},
		{"outbound.upsert", nodemgtOutboundUpsert},
		{"outbound.delete", nodemgtOutboundDelete},
		{"subscription.list", nodemgtSubList},
		{"subscription.upsert", nodemgtSubUpsert},
		{"subscription.delete", nodemgtSubDelete},
		{"subscription.preview", nodemgtSubPreview},
		{"credential.issue", nodemgtCredentialIssue},
		{"credential.rotate", nodemgtCredentialRotate},
		{"credential.revoke", nodemgtCredentialRevoke},
		{"settings.get", nodemgtSettingsGet},
		{"settings.set", nodemgtSettingsSet},
		{"cert.list", nodemgtCertList},
		{"cert.request", nodemgtCertRequest},
		{"cert.delete", nodemgtCertDelete},
		{"cert.set_auto_renew", nodemgtCertSetAutoRenew},
		{"root_cert.list", nodemgtRootCertList},
		{"root_cert.issue", nodemgtRootCertIssue},
		{"root_cert.delete", nodemgtRootCertDelete},
		{"root_cert.set_auto_renew", nodemgtRootCertSetAutoRenew},
	}
	for _, tc := range cases {
		_, rpcErr := tc.call(ctx, &rpc.JsonRpcRequest{Version: rpc.RPC_VERSION, ID: 1, Params: map[string]any{}})
		if rpcErr == nil || rpcErr.Code != rpc.PermissionDenied {
			t.Fatalf("%s with API key expected PermissionDenied, got %#v", tc.name, rpcErr)
		}
	}
}

func TestInboundAndOutboundViewOpenEncryptedSecretsKeepRealityKeyOmitted(t *testing.T) {
	sealedSS, err := secretcrypt.Seal("ss2022-server-key")
	if err != nil {
		t.Fatal(err)
	}
	sealedAccPass, err := secretcrypt.Seal("http-proxy-pass")
	if err != nil {
		t.Fatal(err)
	}
	sealedPriv, err := secretcrypt.Seal("reality-priv-secret")
	if err != nil {
		t.Fatal(err)
	}
	inSettings, _ := json.Marshal(map[string]any{
		"ss_method":           "2022-blake3-aes-128-gcm",
		"ss_password":         sealedSS,
		"reality_private_key": sealedPriv,
		"reality_public_key":  "reality-pub",
		"accounts":            []map[string]string{{"user": "alice", "pass": sealedAccPass}},
	})
	inView := inboundViewWithLinked(models.Inbound{
		ID:           "in-1",
		Protocol:     "shadowsocks",
		SettingsJSON: string(inSettings),
	}, false)
	if inView["ss_password"] != "ss2022-server-key" {
		t.Fatalf("expected opened ss_password, got %#v", inView["ss_password"])
	}
	accs, ok := inView["accounts"].([]inboundcfg.ProxyAccount)
	if !ok || len(accs) != 1 || accs[0].User != "alice" || accs[0].Pass != "http-proxy-pass" {
		t.Fatalf("expected opened proxy accounts, got %#v", inView["accounts"])
	}
	if _, exists := inView["reality_private_key"]; exists {
		t.Fatal("inbound view must never expose reality_private_key")
	}

	sealedOutPass, err := secretcrypt.Seal("outbound-secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	outSettings, _ := json.Marshal(map[string]any{
		"address":  "198.51.100.10",
		"port":     1080,
		"username": "bob",
		"password": sealedOutPass,
	})
	outView := outboundView(models.Outbound{
		ID:           "out-1",
		Protocol:     "socks",
		SettingsJSON: string(outSettings),
	})
	if outView["password"] != "outbound-secret-pass" {
		t.Fatalf("expected opened outbound password, got %#v", outView["password"])
	}
	rawOutJSON, _ := outView["settings_json"].(string)
	if strings.Contains(rawOutJSON, secretcrypt.Prefix) || !strings.Contains(rawOutJSON, "outbound-secret-pass") {
		t.Fatalf("expected opened outbound settings_json without ciphertext prefix, got %s", rawOutJSON)
	}
}
