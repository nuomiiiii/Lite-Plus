package v2

import "testing"

func TestUnifyPairedPolicyCopiesOneSidedSwitch(t *testing.T) {
	intent := FirewallIntent{DefaultDeny4: true, BlockPing6: true}
	UnifyPairedPolicy(&intent)
	if !intent.DefaultDeny4 || !intent.DefaultDeny6 || !intent.BlockPing4 || !intent.BlockPing6 {
		t.Fatalf("one switch must persist both stacks: %+v", intent)
	}
	off := FirewallIntent{}
	UnifyPairedPolicy(&off)
	if off.DefaultDeny4 || off.DefaultDeny6 || off.BlockPing4 || off.BlockPing6 {
		t.Fatalf("off must stay off: %+v", off)
	}
}
