package firewall

import (
	"testing"

	"github.com/nuomiiiii/lite/database/models"
)

func TestIntentFromRowUnifiesPairedPolicy(t *testing.T) {
	got := IntentFromRow(&models.ClientFirewallIntent{
		DefaultDeny4: true,
		BlockPing6:   true,
		RulesJSON:    "[]",
	})
	if !got.DefaultDeny4 || !got.DefaultDeny6 || !got.BlockPing4 || !got.BlockPing6 {
		t.Fatalf("stored one-sided switch must apply to both stacks: %+v", got)
	}
}
