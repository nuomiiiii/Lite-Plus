package jsonrpc

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNodemgtUserListKeepsGoingIfResetSyncFails(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `logger.Warnf("nodemgt", "traffic reset sync: %v", err)`) {
		t.Fatal("user.list must not fail the whole list when monthly reset sync errors")
	}
	if strings.Contains(text, `if _, err := nodemgtOps().SyncDueTrafficResets(time.Now().UTC()); err != nil {
		return nil, nodemgtErr(err)
	}`) {
		t.Fatal("user.list still returns the traffic reset error")
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
