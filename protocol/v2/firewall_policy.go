package v2

// UnifyPairedPolicy copies a one-sided ping/deny switch onto both stacks.
// Plus UI is one switch; a later v4/v6 NIC must inherit the same policy.
func UnifyPairedPolicy(intent *FirewallIntent) {
	if intent == nil {
		return
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		intent.DefaultDeny4 = true
		intent.DefaultDeny6 = true
	}
	if intent.BlockPing4 || intent.BlockPing6 {
		intent.BlockPing4 = true
		intent.BlockPing6 = true
	}
}
