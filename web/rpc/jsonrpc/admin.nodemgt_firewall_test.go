package jsonrpc

import (
	"os"
	"strings"
	"testing"
)

func TestInboundFirewallMutationsConsumeExecGrant(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	upsert := extractGoFunc(text, "func nodemgtInboundUpsert")
	if !strings.Contains(upsert, "consumeScheduledExecGrant(") {
		t.Fatal("inbound upsert does not consume an exec grant for firewall changes")
	}
	if !strings.Contains(upsert, "firewall.EnsureApplyAllowed(") {
		t.Fatal("inbound upsert does not check firewall availability before linking")
	}
	if !strings.Contains(upsert, "firewall.PlannedInboundFirewallOp(") {
		t.Fatal("inbound upsert always mutates firewall")
	}
	if !strings.Contains(upsert, "GetClientByUUID(") {
		t.Fatal("inbound upsert must skip the exec grant after the node is gone")
	}
	del := extractGoFunc(text, "func nodemgtInboundDelete")
	if !strings.Contains(del, "consumeScheduledExecGrant(") {
		t.Fatal("deleting a linked inbound does not consume an exec grant")
	}
}

func TestSaveFirewallValidatesBeforeGrant(t *testing.T) {
	src, err := os.ReadFile("admin.firewall.go")
	if err != nil {
		t.Fatal(err)
	}
	save := extractGoFunc(string(src), "func adminSaveFirewall")
	guard := strings.Index(save, "firewall.GuardDefaultDeny(")
	ensure := strings.Index(save, "firewall.EnsureApplyAllowed(")
	grant := strings.Index(save, "consumeScheduledExecGrant(")
	if ensure < 0 || guard < 0 || grant < 0 {
		t.Fatal("save must check capability, default deny, and consume a grant")
	}
	if ensure > grant || guard > grant {
		t.Fatal("save must not consume the exec grant before capability and default-deny checks")
	}
	if !strings.Contains(save, "RevertSshPort(") || !strings.Contains(save, "prevSSH") {
		t.Fatal("failed ssh listen change must revert the saved ssh_port")
	}
	if !strings.Contains(save, "OmitKeep:") || !strings.Contains(string(src), `json:"omit_keep"`) {
		t.Fatal("save must persist omitted keep holes")
	}
	if !strings.Contains(string(src), "DropOmittedKeep(") {
		t.Fatal("view must not reattach omitted keep holes")
	}
	if !strings.Contains(save, "DropOrphanInboundRules(") {
		t.Fatal("save must drop inbound-origin rules whose inbound is gone")
	}
	get := extractGoFunc(string(src), "func adminGetFirewall")
	if !strings.Contains(get, "reconcileOrphanInbound(") {
		t.Fatal("get must drop leftover inbound-origin rules after the inbound was deleted")
	}
	adopt := extractGoFunc(string(src), "func adminAdoptFirewall")
	ensure = strings.Index(adopt, "firewall.EnsureApplyAllowed(")
	grant = strings.Index(adopt, "consumeScheduledExecGrant(")
	loaded := strings.Index(adopt, "host rules are not loaded")
	if ensure < 0 || grant < 0 || loaded < 0 || ensure > grant || loaded > grant {
		t.Fatal("adopt must not consume the exec grant before capability and snapshot checks")
	}
	if !strings.Contains(adopt, `disableOriginal = "timeout"`) || !strings.Contains(adopt, `view["disable_original"]`) {
		t.Fatal("adopt must keep the applied Plus rules when disable-original times out")
	}
	if strings.Index(adopt, "DispatchApply(") < 0 || strings.Index(adopt, "DispatchAdopt(") < strings.Index(adopt, "DispatchApply(") {
		t.Fatal("adopt must apply Plus rules before disable-original")
	}
}
