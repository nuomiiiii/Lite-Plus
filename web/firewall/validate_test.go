package firewall

import (
	"os"
	"strings"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	nodemgtmodels "github.com/nuomiiiii/lite/nodemgt/models"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func TestNormalizeRuleRejectsDualStack(t *testing.T) {
	_, err := NormalizeRule(v2.FirewallRule{
		Action:   "allow",
		Protocol: "tcp",
		Port:     "443",
		Stack:    "dual",
	})
	if err == nil {
		t.Fatal("dual stack must be rejected")
	}
}

func TestNormalizeRuleAllPorts(t *testing.T) {
	rule, err := NormalizeRule(v2.FirewallRule{
		Action:   "allow",
		Protocol: "tcp",
		Port:     "*",
		Source:   "10.240.3.4",
		Stack:    "v4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.Port != "*" || rule.Source != "10.240.3.4/32" {
		t.Fatalf("%+v", rule)
	}
	any, err := NormalizeRule(v2.FirewallRule{
		Action:   "allow",
		Protocol: "udp",
		Port:     "any",
		Stack:    "v4",
	})
	if err != nil || any.Port != "*" {
		t.Fatalf("%+v %v", any, err)
	}
}

func TestNormalizeRuleSeparatesSourceByStack(t *testing.T) {
	_, err := NormalizeRule(v2.FirewallRule{
		Action:   "allow",
		Protocol: "tcp",
		Port:     "443",
		Source:   "2001:db8::/32",
		Stack:    "v4",
	})
	if err == nil {
		t.Fatal("v6 source on v4 stack must fail")
	}
	rule, err := NormalizeRule(v2.FirewallRule{
		Action:   "allow",
		Protocol: "tcp",
		Port:     "80-90",
		Source:   "10.0.0.1",
		Stack:    "ipv4",
		Comment:  "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.Stack != "v4" || rule.Port != "80-90" || rule.Source != "10.0.0.1/32" {
		t.Fatalf("%+v", rule)
	}
}

func TestStacksForInbound(t *testing.T) {
	if got := StacksForInbound("dual"); len(got) != 2 || got[0] != "v4" || got[1] != "v6" {
		t.Fatalf("%v", got)
	}
	if got := StacksForInbound("ipv6"); len(got) != 1 || got[0] != "v6" {
		t.Fatalf("%v", got)
	}
	if got := StacksForInbound("ipv4"); len(got) != 1 || got[0] != "v4" {
		t.Fatalf("%v", got)
	}
}

func TestDefaultDenyConflict(t *testing.T) {
	if DefaultDenyConflict("ufw", []string{"ufw"}) {
		t.Fatal("driving ufw is not a conflict")
	}
	if !DefaultDenyConflict("nft", []string{"ufw"}) {
		t.Fatal("nft plus ufw must conflict")
	}
}

func TestProtocolForInbound(t *testing.T) {
	if ProtocolForInbound("hysteria2", "udp") != "udp" {
		t.Fatal("hysteria2")
	}
	if ProtocolForInbound("vless", "tcp") != "tcp" {
		t.Fatal("vless")
	}
	if ProtocolForInbound("vless", "quic") != "udp" {
		t.Fatal("quic")
	}
	if ProtocolForInbound("shadowsocks", "tcp,udp") != "both" {
		t.Fatal("ss both")
	}
	if ProtocolForInbound("shadowsocks", "tcp") != "tcp" {
		t.Fatal("ss tcp")
	}
	if ProtocolForInbound("shadowsocks", "udp") != "udp" {
		t.Fatal("ss udp")
	}
}

func TestInboundComment(t *testing.T) {
	got := InboundComment("HK-443", "hysteria2", "udp", "v4", 443)
	if got != "入站 HK-443 · hysteria2 · 443/udp · v4" {
		t.Fatalf("%s", got)
	}
}

func TestApplyDefaultDenyView(t *testing.T) {
	fresh := ApplyDefaultDenyView(v2.FirewallIntent{}, false, false)
	if fresh.DefaultDeny4 || fresh.DefaultDeny6 {
		t.Fatalf("new intent must keep default deny off: %+v", fresh)
	}
	kept := ApplyDefaultDenyView(v2.FirewallIntent{DefaultDeny4: false, DefaultDeny6: false}, true, false)
	if kept.DefaultDeny4 || kept.DefaultDeny6 {
		t.Fatalf("saved intent must keep deny off: %+v", kept)
	}
	on := ApplyDefaultDenyView(v2.FirewallIntent{DefaultDeny4: true, DefaultDeny6: true}, true, false)
	if !on.DefaultDeny4 || !on.DefaultDeny6 {
		t.Fatalf("saved deny on must stay on: %+v", on)
	}
	blocked := ApplyDefaultDenyView(v2.FirewallIntent{DefaultDeny4: true, DefaultDeny6: true}, true, true)
	if blocked.DefaultDeny4 || blocked.DefaultDeny6 {
		t.Fatalf("blocked hosts must not default deny on: %+v", blocked)
	}
}

func TestNormalizeSSHPort(t *testing.T) {
	empty, err := NormalizeSSHPort("  ")
	if err != nil || empty != "" {
		t.Fatalf("empty ssh port: %q %v", empty, err)
	}
	got, err := NormalizeSSHPort("2222")
	if err != nil || got != "2222" {
		t.Fatalf("ssh port: %q %v", got, err)
	}
	if _, err := NormalizeSSHPort("0"); err == nil {
		t.Fatal("port 0 must fail")
	}
	if _, err := NormalizeSSHPort("22-22"); err == nil {
		t.Fatal("ssh port must be a single port")
	}
	intent, err := NormalizeIntent(v2.FirewallIntent{SshPort: " 2222 "})
	if err != nil || intent.SshPort != "2222" {
		t.Fatalf("%+v %v", intent, err)
	}
}

func TestDisplaySshPortPrefersLiveUntilApplied(t *testing.T) {
	if got := DisplaySshPort("2200", "2222", false); got != "2222" {
		t.Fatalf("pending must show live listen: %q", got)
	}
	if got := DisplaySshPort("2200", "2222", true); got != "2200" {
		t.Fatalf("applied must show intent: %q", got)
	}
	if got := DisplaySshPort("2200", "", false); got != "2200" {
		t.Fatalf("no snapshot falls back to intent: %q", got)
	}
	if got := DisplaySshPort("", "22", true); got != "22" {
		t.Fatalf("applied empty intent uses snapshot: %q", got)
	}
}

func TestRewriteKeepSSH(t *testing.T) {
	keep := []v2.FirewallRule{
		{ID: "keep-v4-22", Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Origin: v2.FirewallOriginKeep, Comment: "SSH"},
		{ID: "keep-v6-22", Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v6", Origin: v2.FirewallOriginKeep, Comment: "SSH"},
		{ID: "keep-v4-3389", Enabled: true, Action: "allow", Protocol: "tcp", Port: "3389", Stack: "v4", Origin: v2.FirewallOriginKeep, Comment: "RDP"},
	}
	same := RewriteKeepSSH(keep, "", true, true)
	if len(same) != 3 || same[0].Port != "22" {
		t.Fatalf("empty ssh port must leave keep: %+v", same)
	}
	got := RewriteKeepSSH(keep, "2222", true, true)
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	var ssh, rdp int
	for _, rule := range got {
		switch rule.Comment {
		case "SSH":
			ssh++
			if rule.Port != "2222" || rule.Origin != v2.FirewallOriginKeep {
				t.Fatalf("%+v", rule)
			}
		case "RDP":
			rdp++
			if rule.Port != "3389" {
				t.Fatalf("%+v", rule)
			}
		default:
			t.Fatalf("%+v", rule)
		}
	}
	if ssh != 2 || rdp != 1 {
		t.Fatalf("ssh=%d rdp=%d %+v", ssh, rdp, got)
	}
	fresh := RewriteKeepSSH(nil, "2222", true, false)
	if len(fresh) != 1 || fresh[0].Port != "2222" || fresh[0].Stack != "v4" {
		t.Fatalf("missing keep must synthesize ssh: %+v", fresh)
	}
}

func TestNormalizeIntentRejectsDuplicateIdentity(t *testing.T) {
	_, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{Action: "allow", Protocol: "tcp", Port: "32688", Stack: "v4"},
			{Action: "deny", Protocol: "tcp", Port: "32688", Source: "*", Stack: "v4"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), ErrDuplicateRule.Error()) {
		t.Fatalf("same protocol/port/source must be rejected: %v", err)
	}
	got, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{Action: "allow", Protocol: "tcp", Port: "80", Stack: "v4"},
			{Action: "allow", Protocol: "udp", Port: "80", Stack: "v4"},
			{Action: "allow", Protocol: "tcp", Port: "80", Source: "10.0.0.1", Stack: "v4"},
			{Action: "allow", Protocol: "tcp", Port: "80", Stack: "v6"},
		},
	})
	if err != nil || len(got.Rules) != 4 {
		t.Fatalf("different protocol, source, or stack must stay: %+v %v", got.Rules, err)
	}
}

func TestUpsertRuleByIdentityReusesSamePort(t *testing.T) {
	existing := v2.FirewallRule{ID: "web-1", Action: "allow", Protocol: "tcp", Port: "32688", Stack: "v4", Priority: 103, Origin: v2.FirewallOriginWeb}
	inbound := v2.FirewallRule{ID: "in-1", Action: "allow", Protocol: "tcp", Port: "32688", Stack: "v4", Priority: 104, Origin: v2.FirewallOriginInbound, InboundID: "us02"}
	got := UpsertRuleByIdentity([]v2.FirewallRule{existing}, inbound)
	if len(got) != 1 || got[0].ID != "web-1" || got[0].Priority != 103 || got[0].InboundID != "us02" {
		t.Fatalf("same identity must reuse the row: %+v", got)
	}
}

func TestNormalizeIntentSortsByPriority(t *testing.T) {
	got, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{ID: "b", Action: "allow", Protocol: "tcp", Port: "443", Stack: "v4", Priority: 200},
			{ID: "a", Action: "allow", Protocol: "tcp", Port: "80", Stack: "v4", Priority: 50},
			{ID: "c", Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Priority: 200},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 3 || got.Rules[0].Port != "80" || got.Rules[1].ID != "b" || got.Rules[2].ID != "c" {
		t.Fatalf("rules must sort by priority then id: %+v", got.Rules)
	}
}

func TestNormalizeIntentKeepsDeclaredStack(t *testing.T) {
	got, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{Action: "allow", Protocol: "tcp", Port: "2083", Stack: "v6"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Stack != "v6" || got.Rules[0].Source != "" {
		t.Fatalf("unsourced v6 must not be copied onto v4: %+v", got.Rules)
	}
}

func TestNormalizeIntentExpandsBothProtocol(t *testing.T) {
	got, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{Action: "allow", Protocol: "both", Port: "53", Stack: "v4"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("%+v", got.Rules)
	}
	if got.Rules[0].Protocol != v2.FirewallProtoTCP || got.Rules[1].Protocol != v2.FirewallProtoUDP {
		t.Fatalf("%+v", got.Rules)
	}
	if got.Rules[0].Port != "53" || got.Rules[1].Port != "53" {
		t.Fatalf("%+v", got.Rules)
	}
}

func TestNormalizeIntentKeepsOmit(t *testing.T) {
	got, err := NormalizeIntent(v2.FirewallIntent{OmitKeep: []string{" SSH ", "ssh", "RDP"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.OmitKeep) != 2 || got.OmitKeep[0] != "ssh" || got.OmitKeep[1] != "rdp" {
		t.Fatalf("%+v", got.OmitKeep)
	}
}

func TestDropOmittedKeep(t *testing.T) {
	keep := []v2.FirewallRule{
		{Comment: "SSH", Origin: v2.FirewallOriginKeep, Port: "22", Protocol: "tcp", Stack: "v4"},
		{Comment: "RDP", Origin: v2.FirewallOriginKeep, Port: "3389", Protocol: "tcp", Stack: "v4"},
	}
	got := DropOmittedKeep(keep, []string{"SSH"})
	if len(got) != 1 || got[0].Comment != "RDP" {
		t.Fatalf("%+v", got)
	}
}

func TestNormalizeIntentDropsKeep(t *testing.T) {
	got, err := NormalizeIntent(v2.FirewallIntent{
		Rules: []v2.FirewallRule{
			{Origin: v2.FirewallOriginKeep, Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Comment: "SSH"},
			{Origin: v2.FirewallOriginWeb, Enabled: true, Action: "allow", Protocol: "tcp", Port: "443", Stack: "v4"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Port != "443" || got.Rules[0].Origin != v2.FirewallOriginWeb {
		t.Fatalf("%+v", got.Rules)
	}
}

func TestDropOrphanInboundRules(t *testing.T) {
	rules := []v2.FirewallRule{
		{ID: "web", Origin: v2.FirewallOriginWeb, Port: "80"},
		{ID: "live", Origin: v2.FirewallOriginInbound, InboundID: "in-live", Port: "443"},
		{ID: "gone", Origin: v2.FirewallOriginInbound, InboundID: "in-gone", Port: "2083"},
		{ID: "empty", Origin: v2.FirewallOriginInbound, Port: "45633"},
	}
	got := DropOrphanInboundRules(rules, map[string]struct{}{"in-live": {}})
	if len(got) != 2 || got[0].ID != "web" || got[1].ID != "live" {
		t.Fatalf("orphans must drop: %+v", got)
	}
	if kept := DropOrphanInboundRules(rules, nil); len(kept) != 4 {
		t.Fatalf("unknown inbound list must not prune: %+v", kept)
	}
}

func TestDropOwnedHostNoise(t *testing.T) {
	got := DropOwnedHostNoise([]v2.FirewallHostRule{
		{Key: "meta", Raw: "type filter hook input priority -1; policy accept;", Reason: "unsupported match"},
		{Key: "plus", Raw: "jump LITE_PLUS", Comment: "nft inet filter input 3"},
		{Key: "owned", Raw: "tcp dport 443 accept", Comment: "nft inet filter LITE_PLUS 8"},
		{Key: "ssh", Raw: "tcp dport 22 accept", Comment: "nft ip filter 1PANEL_BASIC 12", Adoptable: true, Port: "22"},
	})
	if len(got) != 1 || got[0].Key != "ssh" {
		t.Fatalf("%+v", got)
	}
}

func TestAttachKeepRules(t *testing.T) {
	keep := []v2.FirewallRule{
		{ID: "keep-v4-22", Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Origin: v2.FirewallOriginKeep, Comment: "SSH"},
		{ID: "keep-v6-22", Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v6", Origin: v2.FirewallOriginKeep, Comment: "SSH"},
		{ID: "keep-v4-3389", Enabled: true, Action: "allow", Protocol: "tcp", Port: "3389", Stack: "v4", Origin: v2.FirewallOriginKeep, Comment: "RDP"},
	}
	off := AttachKeepRules(v2.FirewallIntent{Rules: []v2.FirewallRule{{Port: "443"}}}, keep)
	if len(off.Rules) != 1 || off.Rules[0].Port != "443" {
		t.Fatalf("deny off must not attach: %+v", off.Rules)
	}
	v4Only := AttachKeepRules(v2.FirewallIntent{DefaultDeny4: true}, keep)
	if len(v4Only.Rules) != 2 || v4Only.Rules[0].Port != "22" || v4Only.Rules[1].Port != "3389" || v4Only.Rules[0].Stack != "v4" {
		t.Fatalf("v4 deny must attach v4 keep: %+v", v4Only.Rules)
	}
	dup := AttachKeepRules(v2.FirewallIntent{
		DefaultDeny4: true,
		DefaultDeny6: true,
		Rules: []v2.FirewallRule{
			{Enabled: true, Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Origin: v2.FirewallOriginInbound},
			{Enabled: false, Action: "allow", Protocol: "tcp", Port: "3389", Stack: "v4"},
		},
	}, keep)
	if len(dup.Rules) != 4 {
		t.Fatalf("skip enabled allow dupes only: %+v", dup.Rules)
	}
	if dup.Rules[0].Origin != v2.FirewallOriginKeep || dup.Rules[0].Port != "22" || dup.Rules[0].Stack != "v6" {
		t.Fatalf("v6 keep must still show: %+v", dup.Rules[0])
	}
	if dup.Rules[1].Port != "3389" || dup.Rules[1].Origin != v2.FirewallOriginKeep {
		t.Fatalf("disabled user 3389 must still show keep: %+v", dup.Rules[1])
	}
}

func TestListenHolesSkipsInboundAllows(t *testing.T) {
	intent := v2.FirewallIntent{
		DefaultDeny4: true,
		Rules: []v2.FirewallRule{
			{Origin: v2.FirewallOriginWeb, Enabled: true, Protocol: "tcp", Port: "22", Stack: v2.FirewallStackV4},
			{Origin: v2.FirewallOriginInbound, Enabled: true, Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4, Comment: "in"},
			{Origin: v2.FirewallOriginInbound, Enabled: false, Protocol: "tcp", Port: "80", Stack: v2.FirewallStackV4},
			{Origin: v2.FirewallOriginInbound, Enabled: true, Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV6},
		},
	}
	if holes := ListenHoles("unused", intent); len(holes) != 0 {
		t.Fatalf("inbound allow must not also become a listen hole: %+v", holes)
	}
}

func TestPlannedInboundFirewallOp(t *testing.T) {
	allow := true
	deny := false
	prev := &nodemgtmodels.Inbound{ID: "in-1", NodeUUID: "n1", Protocol: "vless", Port: 443, Enabled: true, SettingsJSON: `{"stack":"ipv4","transport":"tcp"}`}
	next := *prev
	cfg := inboundcfg.Settings{Stack: "ipv4", Transport: "tcp"}
	if PlannedInboundFirewallOp(false, &allow, nil, next, cfg) != InboundFirewallLink {
		t.Fatal("turning allow on must link")
	}
	if PlannedInboundFirewallOp(true, &allow, prev, next, cfg) != InboundFirewallNone {
		t.Fatal("remark-only save must not touch firewall")
	}
	next.Enabled = false
	if PlannedInboundFirewallOp(true, &allow, prev, next, cfg) != InboundFirewallLink {
		t.Fatal("disable while linked must rewrite firewall")
	}
	next.Enabled = true
	next.Port = 8443
	if PlannedInboundFirewallOp(true, &allow, prev, next, cfg) != InboundFirewallLink {
		t.Fatal("port change while linked must rewrite firewall")
	}
	if PlannedInboundFirewallOp(true, &deny, prev, *prev, cfg) != InboundFirewallUnlink {
		t.Fatal("turning allow off must unlink")
	}
	if PlannedInboundFirewallOp(false, &deny, nil, next, cfg) != InboundFirewallNone {
		t.Fatal("allow off and not linked must skip")
	}
	if PlannedInboundFirewallOp(true, nil, prev, next, cfg) != InboundFirewallNone {
		t.Fatal("omitted allow must not unlink")
	}
}

func TestInboundLinkWaitsForApplyFailure(t *testing.T) {
	src, err := os.ReadFile("link.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "return waitApply(") {
		t.Fatal("inbound link must wait for apply")
	}
	if !strings.Contains(text, "DeliveryFailed") {
		t.Fatal("inbound link must surface a failed apply")
	}
	if !strings.Contains(text, "dropInboundRulesLocal(") || !strings.Contains(text, "clientExists(") {
		t.Fatal("unlinking an inbound for a deleted server must not wait on the agent")
	}
}
