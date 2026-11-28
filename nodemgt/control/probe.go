package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/store"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
)

const (
	defaultMasterProbeTimeout = 9 * time.Second
	minMasterProbeTimeout     = 1 * time.Second
	maxMasterProbeTimeout     = 10 * time.Second
)

type OutboundProbeResult struct {
	OK         bool   `json:"ok"`
	LatencyMS  int64  `json:"latency_ms"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type probeWaiter struct {
	nodeUUID string
	ch       chan OutboundProbeResult
}

var (
	probeMu      sync.Mutex
	probeWaiters = map[string]*probeWaiter{}

	probeIsAgentOnline = agent_runtime.IsAgentOnline
	probeDispatchEvent = agent_runtime.DispatchV2Event
)

func newProbeOperationID() string {
	var raw [12]byte
	_, _ = rand.Read(raw[:])
	return "probe-" + hex.EncodeToString(raw[:])
}

func registerProbeWaiter(opID, nodeUUID string) *probeWaiter {
	w := &probeWaiter{
		nodeUUID: strings.TrimSpace(nodeUUID),
		ch:       make(chan OutboundProbeResult, 1),
	}
	probeMu.Lock()
	probeWaiters[opID] = w
	probeMu.Unlock()
	return w
}

func unregisterProbeWaiter(opID string) {
	probeMu.Lock()
	delete(probeWaiters, opID)
	probeMu.Unlock()
}

// CompleteProbe delivers an ephemeral connectivity probe result from an Agent
// to the waiting RPC goroutine. Returns handled=false if opID is not an active
// probe (so normal DB-backed control commands continue to HandleResult).
func CompleteProbe(nodeUUID, opID, status, errMsg string, latencyMS int64, statusCode int) (bool, error) {
	opID = strings.TrimSpace(opID)
	if opID == "" {
		return false, nil
	}
	probeMu.Lock()
	w, ok := probeWaiters[opID]
	if !ok {
		probeMu.Unlock()
		return false, nil
	}
	nodeUUID = strings.TrimSpace(nodeUUID)
	if w.nodeUUID != "" && w.nodeUUID != nodeUUID {
		probeMu.Unlock()
		return true, store.ErrForbidden
	}
	delete(probeWaiters, opID)
	probeMu.Unlock()

	trimmedErr := strings.TrimSpace(errMsg)
	okStatus := strings.EqualFold(strings.TrimSpace(status), "applied") && trimmedErr == ""
	if okStatus && latencyMS <= 0 && statusCode <= 0 {
		okStatus = false
		trimmedErr = "agent does not support connectivity probe"
	}
	res := OutboundProbeResult{
		OK:         okStatus,
		LatencyMS:  latencyMS,
		StatusCode: statusCode,
		Error:      trimmedErr,
	}
	select {
	case w.ch <- res:
	default:
	}
	return true, nil
}

// ProbeOutbound asks an online Agent to test connectivity through a live
// outbound tag on the specified core and waits for the result.
func ProbeOutbound(ctx context.Context, nodeUUID, core, tag string, timeout time.Duration) OutboundProbeResult {
	nodeUUID = strings.TrimSpace(nodeUUID)
	core = strings.TrimSpace(core)
	tag = strings.TrimSpace(tag)
	if nodeUUID == "" || tag == "" {
		return OutboundProbeResult{OK: false, Error: "invalid outbound probe target"}
	}
	if !probeIsAgentOnline(nodeUUID) {
		return OutboundProbeResult{OK: false, Error: "node offline"}
	}
	if timeout <= 0 {
		timeout = defaultMasterProbeTimeout
	}
	if timeout < minMasterProbeTimeout {
		timeout = minMasterProbeTimeout
	}
	if timeout > maxMasterProbeTimeout {
		timeout = maxMasterProbeTimeout
	}
	agentTimeout := timeout - time.Second
	if agentTimeout < minMasterProbeTimeout {
		agentTimeout = minMasterProbeTimeout
	}

	opID := newProbeOperationID()
	waiter := registerProbeWaiter(opID, nodeUUID)
	defer unregisterProbeWaiter(opID)

	queued := probeDispatchEvent(nodeUUID, v2.MethodNodemgtProbe, map[string]any{
		"operation_id": opID,
		"kind":         "testOutbound",
		"payload": map[string]any{
			"core":       core,
			"tag":        tag,
			"timeout_ms": int(agentTimeout.Milliseconds()),
		},
	})
	if !queued {
		return OutboundProbeResult{OK: false, Error: "node offline"}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-waiter.ch:
		return res
	case <-timer.C:
		return OutboundProbeResult{OK: false, Error: "probe timed out"}
	case <-ctx.Done():
		return OutboundProbeResult{OK: false, Error: "probe cancelled"}
	}
}
