package jsonrpc

import (
	"os"
	"strings"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

func TestResolveInboundSortIndexKeepsZero(t *testing.T) {
	next := func() int {
		t.Fatal("explicit sort must not auto-assign")
		return 0
	}
	zero := 0
	if got := resolveInboundSortIndex("", &zero, nil, next); got != 0 {
		t.Fatalf("explicit 0 must stay 0, got %d", got)
	}
	eight := 8
	if got := resolveInboundSortIndex("", &eight, nil, next); got != 8 {
		t.Fatalf("explicit 8 must stay 8, got %d", got)
	}
	existing := &models.Inbound{SortIndex: 3}
	if got := resolveInboundSortIndex("id-1", nil, existing, next); got != 3 {
		t.Fatalf("edit without sort must keep existing, got %d", got)
	}
	called := false
	got := resolveInboundSortIndex("", nil, nil, func() int {
		called = true
		return 7
	})
	if !called || got != 7 {
		t.Fatalf("omitted sort on create must auto-assign, got %d", got)
	}
}

func TestInboundViewUsesSSNetwork(t *testing.T) {
	both := inboundView(models.Inbound{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"transport":"tcp","ss_network":"tcp,udp","ss_method":"aes-128-gcm"}`,
	})
	if both["transport"] != "tcp,udp" || both["ss_network"] != "tcp,udp" {
		t.Fatalf("ss_network tcp,udp, got transport=%v ss_network=%v", both["transport"], both["ss_network"])
	}
	tcp := inboundView(models.Inbound{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"transport":"tcp","ss_network":"tcp"}`,
	})
	if tcp["transport"] != "tcp" || tcp["ss_network"] != "tcp" {
		t.Fatalf("ss_network tcp, got transport=%v ss_network=%v", tcp["transport"], tcp["ss_network"])
	}
	vless := inboundView(models.Inbound{
		Protocol:     "vless",
		SettingsJSON: `{"transport":"tcp"}`,
	})
	if _, ok := vless["ss_network"]; ok {
		t.Fatalf("vless must not expose ss_network")
	}
}

func TestOutboundViewUsesSSNetwork(t *testing.T) {
	udp := outboundView(models.Outbound{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"transport":"tcp","ss_network":"udp","ss_method":"aes-128-gcm"}`,
	})
	if udp["transport"] != "udp" {
		t.Fatalf("ss_network udp, got %v", udp["transport"])
	}
	legacy := outboundView(models.Outbound{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"transport":"tcp","ss_method":"aes-128-gcm"}`,
	})
	if legacy["transport"] != "tcp,udp" {
		t.Fatalf("legacy tcp dummy should display both, got %v", legacy["transport"])
	}
	tcp := outboundView(models.Outbound{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"transport":"tcp","ss_network":"tcp"}`,
	})
	if tcp["transport"] != "tcp" {
		t.Fatalf("ss_network tcp, got %v", tcp["transport"])
	}
}

func TestInboundCreateEmptySortUsesGlobalLast(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	upsert := extractGoFunc(string(src), "func nodemgtInboundUpsert")
	if !strings.Contains(upsert, `st.NextInboundSortIndex("")`) {
		t.Fatal("empty sort must append after the global max, not the node max")
	}
}
