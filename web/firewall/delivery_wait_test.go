package firewall

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite/database/models"
)

func TestDispatchRegistersWaiterBeforeSend(t *testing.T) {
	src, err := os.ReadFile("delivery.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, name := range []string{"func DispatchSnapshot", "func dispatchApply", "func DispatchAdopt", "func DispatchInstall"} {
		fn := extractFunc(text, name)
		start := strings.Index(fn, "startWait(")
		dispatch := strings.Index(fn, "DispatchV2Event(")
		wait := strings.Index(fn, "waitFor(")
		if start < 0 || dispatch < 0 || wait < 0 || start > dispatch || dispatch > wait {
			t.Fatalf("%s must register the waiter before sending, then wait", name)
		}
	}
	if !strings.Contains(text, "applyWait") || !strings.Contains(text, "60 * time.Second") {
		t.Fatal("apply wait must cover nft/iptables plus watchdog")
	}
	install := extractFunc(text, "func DispatchInstall")
	if !strings.Contains(install, "installWait") || !strings.Contains(text, "4 * time.Minute") {
		t.Fatal("install wait must cover package manager nftables installs")
	}
	apply := extractFunc(text, "func dispatchApply")
	if strings.Contains(apply, "防火墙应用超时") {
		t.Fatal("timed-out apply must stay sent so a late agent result can still mark applied")
	}
	complete := extractFunc(text, "func CompleteResult")
	if !strings.Contains(complete, "result.Kind == v2.FirewallKindApply") {
		t.Fatal("only apply results may update delivery status")
	}
	if strings.Contains(complete, "FirewallKindAdopt") {
		t.Fatal("adopt results must not overwrite apply delivery")
	}
	clear := extractFunc(text, "func ClearNode")
	if strings.Contains(clear, "waitFor(") || !strings.Contains(clear, "dispatchApply(") {
		t.Fatal("deleting a server must send firewall clear without waiting")
	}
	online := strings.Index(clear, "IsAgentOnline(")
	dispatch := strings.Index(clear, "dispatchApply(")
	if online < 0 || dispatch < 0 || online > dispatch {
		t.Fatal("offline delete must not send firewall clear to the agent")
	}
	push := extractFunc(text, "func pushRow")
	if strings.Contains(push, "DispatchApply(") || !strings.Contains(push, "dispatchApply(") || !strings.Contains(push, "applyInFlight(") {
		t.Fatal("background retry must not wait on apply, and must skip an in-flight send")
	}
	if !strings.Contains(push, "force") || !strings.Contains(text, "func SyncOnConnect") {
		t.Fatal("agent reconnect must re-apply the panel intent even if the last apply was already marked done")
	}
	if !strings.Contains(push, "if !force && applyInFlight(row)") {
		t.Fatal("reconnect apply must not wait out a lost in-flight send")
	}
	inflight := extractFunc(text, "func applyInFlight")
	if !strings.Contains(inflight, "DeliverySent") || !strings.Contains(inflight, "applyWait") || !strings.Contains(inflight, "applyRetrySkew") {
		t.Fatal("in-flight apply must cover the sent window plus retry skew")
	}
}

func TestApplyInFlightSkipsRecentSent(t *testing.T) {
	now := time.Now()
	if !applyInFlight(models.ClientFirewallIntent{DeliveryStatus: "sent", DeliveryUpdatedAt: &now}) {
		t.Fatal("recent sent apply is still in flight")
	}
	late := now.Add(-applyWait - time.Second)
	if !applyInFlight(models.ClientFirewallIntent{DeliveryStatus: "sent", DeliveryUpdatedAt: &late}) {
		t.Fatal("a just-timed-out apply must not be resent until the late result window closes")
	}
	stale := now.Add(-applyWait - applyRetrySkew - time.Second)
	if applyInFlight(models.ClientFirewallIntent{DeliveryStatus: "sent", DeliveryUpdatedAt: &stale}) {
		t.Fatal("stale sent apply must be retried")
	}
	if applyInFlight(models.ClientFirewallIntent{DeliveryStatus: "failed", DeliveryUpdatedAt: &now}) {
		t.Fatal("failed apply is not in flight")
	}
}

func extractFunc(src, signature string) string {
	start := strings.Index(src, signature)
	if start < 0 {
		return ""
	}
	rest := src[start:]
	depth := 0
	for i, r := range rest {
		if r == '{' {
			depth++
		}
		if r == '}' {
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
