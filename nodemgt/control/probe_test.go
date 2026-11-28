package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/store"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func TestProbeOutboundLifecycleAndSpoofProtection(t *testing.T) {
	prevOnline := probeIsAgentOnline
	prevDispatch := probeDispatchEvent
	defer func() {
		probeIsAgentOnline = prevOnline
		probeDispatchEvent = prevDispatch
	}()

	// Offline node fails immediately.
	probeIsAgentOnline = func(string) bool { return false }
	res := ProbeOutbound(context.Background(), "node-a", "sing-box", "ob-1", 2*time.Second)
	if res.OK || res.Error != "node offline" {
		t.Fatalf("expected node offline, got %+v", res)
	}

	// Online node: reject cross-node spoof, then accept real node result.
	probeIsAgentOnline = func(uuid string) bool { return uuid == "node-a" }
	probeDispatchEvent = func(nodeUUID, method string, params any) bool {
		if method != v2.MethodNodemgtProbe {
			t.Errorf("expected probe to use %q (not nodemgt.control), got %q", v2.MethodNodemgtProbe, method)
		}
		m, _ := params.(map[string]any)
		opID, _ := m["operation_id"].(string)
		go func() {
			handled, err := CompleteProbe("node-b", opID, "applied", "", 1, 204)
			if !handled || !errors.Is(err, store.ErrForbidden) {
				t.Errorf("expected cross-node spoof rejection, got handled=%v err=%v", handled, err)
			}
			handled, err = CompleteProbe("", opID, "applied", "", 1, 204)
			if !handled || !errors.Is(err, store.ErrForbidden) {
				t.Errorf("expected empty-node spoof rejection, got handled=%v err=%v", handled, err)
			}
			handled, err = CompleteProbe("node-a", opID, "applied", "", 73, 204)
			if !handled || err != nil {
				t.Errorf("expected legitimate probe completion, got handled=%v err=%v", handled, err)
			}
		}()
		return true
	}

	res = ProbeOutbound(context.Background(), "node-a", "sing-box", "ob-1", 3*time.Second)
	if !res.OK || res.LatencyMS != 73 || res.StatusCode != 204 || res.Error != "" {
		t.Fatalf("unexpected probe result: %+v", res)
	}

	// Unknown operation ID is not handled by CompleteProbe.
	handled, err := CompleteProbe("node-a", "not-a-probe", "applied", "", 10, 204)
	if handled || err != nil {
		t.Fatalf("expected unknown opID to pass through, got handled=%v err=%v", handled, err)
	}

	// Empty applied reply (latency=0, status_code=0) must not be treated as OK.
	probeDispatchEvent = func(nodeUUID, method string, params any) bool {
		m, _ := params.(map[string]any)
		opID, _ := m["operation_id"].(string)
		go func() {
			_, _ = CompleteProbe("node-a", opID, "applied", "", 0, 0)
		}()
		return true
	}
	res = ProbeOutbound(context.Background(), "node-a", "sing-box", "ob-1", 3*time.Second)
	if res.OK || res.Error == "" {
		t.Fatalf("expected empty probe result to fail, got %+v", res)
	}
}
