package protection

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite/database/models"
	protstore "github.com/nuomiiiii/lite/database/protection"
)

func TestHitSupersededHonorsResetAt(t *testing.T) {
	created := time.Date(2026, 11, 7, 3, 0, 0, 0, time.UTC)
	if !hitSuperseded(created, created.Add(time.Minute).Format(time.RFC3339Nano)) {
		t.Fatal("old hit must not fan out after unban")
	}
	if hitSuperseded(created.Add(2*time.Minute), created.Format(time.RFC3339Nano)) {
		t.Fatal("new attack after reset must still fan out")
	}
	if !hitSuperseded(created, "") {
		t.Fatal("a revoke without reset time must not resurrect the old hit")
	}
}

func TestProtectionDeliveryGuardsLeavesAndRevokes(t *testing.T) {
	src, err := os.ReadFile("delivery.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	ingest := extractFunc(text, "func ingestLocalHit")
	if !strings.Contains(ingest, "IsMember") {
		t.Fatal("ingest must skip non-member hits")
	}
	if !strings.Contains(ingest, "UpsertBan") {
		t.Fatal("group hits must persist through the serialized ban write")
	}
	if !strings.Contains(text, "hitEligibleForFanout") || !strings.Contains(text, "ProtectionModeEnforce") {
		t.Fatal("fan-out must re-check the current enabled enforce policy, whitelist and grant")
	}
	sync := extractFunc(text, "func syncProtection")
	if !strings.Contains(sync, "ListPendingLeaves") || !strings.Contains(sync, "emptyGroupSnapshot") {
		t.Fatal("reconnect must replay leave snapshots even after the group row is gone")
	}
	if !strings.Contains(sync, "needsLeaveApply") || !strings.Contains(text, "func leaveDeliveryWaiting") {
		t.Fatal("pending leave cleanup must wait like config delivery")
	}
	if !strings.Contains(ingest, "inserted") {
		t.Fatal("duplicate events must not fan out again")
	}
	if !strings.Contains(sync, "!group.Enabled") {
		t.Fatal("disabled groups must sync empty snapshots, not current bans")
	}
	if !strings.Contains(text, "func PushPending") || !strings.Contains(sync, "needsProtectionApply") {
		t.Fatal("HTTP pull must skip already-applied configs instead of minting a new apply every round")
	}
	complete := extractFunc(text, "func CompleteReport")
	if !strings.Contains(complete, "ConfigRev") {
		t.Fatal("stale report config revisions must not ingest new bans")
	}
	fanout := extractFunc(text, "func hitEligibleForFanout")
	if strings.Contains(fanout, "formed <= rev.Revision") {
		t.Fatal("applied group revision must not block a new attack after unban")
	}
	if !strings.Contains(fanout, "hitSuperseded") {
		t.Fatal("fan-out must still reject delayed hits formed before the unban reset")
	}
	result := extractFunc(text, "func CompleteResult")
	if !strings.Contains(result, "ClearLeave") || !strings.Contains(result, "ProtectionStatusOK") {
		t.Fatal("leave tombstones must clear only after a successful snapshot")
	}
}

func TestUpdateGroupClearsLeaversAndDisabledGroups(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	update := extractFunc(text, "func UpdateGroup")
	if !strings.Contains(update, "RecordLeave") || !strings.Contains(update, "!row.Enabled") {
		t.Fatal("leave and disable must send empty snapshots")
	}
	if !strings.Contains(text, "unbanWhitelisted") {
		t.Fatal("whitelist save must unban peers, not only prune local rows")
	}
	shared := extractFunc(text, "func fanoutSharedBan")
	if !strings.Contains(shared, "ClaimSharedFanout") {
		t.Fatal("shared fan-out must claim a revision with the current revoke state")
	}
	if strings.Contains(shared, "BumpGroupRevision") {
		t.Fatal("fan-out must not bump the group after a separate revoke check")
	}
	if strings.Contains(update, "SaveGroup") {
		t.Fatal("updating a group must not write an old revision back over a concurrent bump")
	}
	if !strings.Contains(update, "UpdateGroupAndBump") {
		t.Fatal("group edits must bump revision in the same field update")
	}
	unban := extractFunc(text, "func Unban")
	if strings.Contains(unban, "BumpGroupRevision") {
		t.Fatal("group unban must not publish a new revision before the revoke is stored")
	}
	if !strings.Contains(unban, "RevokeGroupIP") || !strings.Contains(unban, "HasGroupedBan") {
		t.Fatal("local unban must refuse grouped records")
	}
	snap := extractFunc(text, "func groupSnapshot")
	if !strings.Contains(snap, "LoadGroupSnapshot") {
		t.Fatal("snapshots must use one consistent group read")
	}
}

func TestNeedsProtectionApplyWaitsForInFlight(t *testing.T) {
	now := time.Now()
	row := models.ClientProtectionConfig{
		Revision:          2,
		AppliedRevision:   1,
		DeliveryStatus:    protstore.DeliverySent,
		DeliveryUpdatedAt: &now,
	}
	if needsProtectionApply(row) {
		t.Fatal("an in-flight apply must not mint another event")
	}
	stale := now.Add(-2 * time.Minute)
	row.DeliveryUpdatedAt = &stale
	if !needsProtectionApply(row) {
		t.Fatal("an expired in-flight apply must be retried")
	}
	failed := now
	row.DeliveryStatus = protstore.DeliveryFailed
	row.DeliveryUpdatedAt = &failed
	if needsProtectionApply(row) {
		t.Fatal("a failed apply must wait before retrying")
	}
}

func TestNeedsLeaveApplyWaitsForInFlight(t *testing.T) {
	now := time.Now()
	leave := models.ProtectionGroupLeave{
		DeliveryStatus:    protstore.DeliverySent,
		DeliveryUpdatedAt: &now,
	}
	if needsLeaveApply(leave) {
		t.Fatal("an in-flight leave cleanup must not mint another event")
	}
	stale := now.Add(-2 * time.Minute)
	leave.DeliveryUpdatedAt = &stale
	if !needsLeaveApply(leave) {
		t.Fatal("an expired in-flight leave cleanup must be retried")
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
