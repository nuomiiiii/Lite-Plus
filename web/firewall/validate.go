package firewall

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	v2 "github.com/nuomiiiii/lite/protocol/v2"
	"github.com/nuomiiiii/lite/utils"
)

const (
	MaxRules     = 200
	MaxComment   = 120
	DefaultPrio  = 100
	MinPriority  = 1
	MaxPriority  = 9999
	ExportVersion = 1
)

var (
	ErrTooManyRules        = errors.New("firewall rule limit exceeded")
	ErrInvalidRule         = errors.New("invalid firewall rule")
	ErrDuplicateRule       = errors.New("firewall rule already exists")
	ErrInvalidStack        = errors.New("firewall stack must be v4 or v6")
	ErrStackSource         = errors.New("source CIDR does not match the rule stack")
	ErrDefaultDenyConflict = errors.New("default deny conflicts with ufw or firewalld")
	ErrDefaultDenyNeedScan = errors.New("请先扫描主机规则后再打开入站默认拒绝")
)

func NormalizeIntent(intent v2.FirewallIntent) (v2.FirewallIntent, error) {
	rules := make([]v2.FirewallRule, 0, len(intent.Rules))
	seen := make(map[string]struct{}, len(intent.Rules))
	for _, rule := range intent.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Origin), v2.FirewallOriginKeep) {
			continue
		}
		for _, expanded := range ExpandProtocols(rule) {
			normalized, err := NormalizeRule(expanded)
			if err != nil {
				return v2.FirewallIntent{}, err
			}
			if _, ok := seen[normalized.ID]; ok {
				normalized.ID = newRuleID()
			}
			seen[normalized.ID] = struct{}{}
			rules = append(rules, normalized)
		}
	}
	ident := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		key := RuleIdentityKey(rule)
		if _, ok := ident[key]; ok {
			return v2.FirewallIntent{}, ErrDuplicateRule
		}
		ident[key] = struct{}{}
	}
	if len(rules) > MaxRules {
		return v2.FirewallIntent{}, ErrTooManyRules
	}
	sshPort, err := NormalizeSSHPort(intent.SshPort)
	if err != nil {
		return v2.FirewallIntent{}, err
	}
	intent.SshPort = sshPort
	intent.OmitKeep = NormalizeOmitKeep(intent.OmitKeep)
	sortIntentRules(rules)
	intent.Rules = rules
	return intent, nil
}

func sortIntentRules(rules []v2.FirewallRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}

func RuleIdentityKey(rule v2.FirewallRule) string {
	return strings.ToLower(strings.TrimSpace(rule.Protocol)) + "\x00" +
		strings.TrimSpace(rule.Port) + "\x00" +
		strings.TrimSpace(rule.Source) + "\x00" +
		strings.TrimSpace(rule.Stack)
}

func UpsertRuleByIdentity(rules []v2.FirewallRule, rule v2.FirewallRule) []v2.FirewallRule {
	key := RuleIdentityKey(rule)
	for i, existing := range rules {
		if RuleIdentityKey(existing) != key {
			continue
		}
		rule.ID = existing.ID
		if existing.Priority > 0 {
			rule.Priority = existing.Priority
		}
		rules[i] = rule
		return rules
	}
	return append(rules, rule)
}

func ExpandProtocols(rule v2.FirewallRule) []v2.FirewallRule {
	switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
	case v2.FirewallProtoBoth, "tcpudp", "tcp/udp", "tcp+udp":
		tcp := rule
		tcp.Protocol = v2.FirewallProtoTCP
		tcp.ID = strings.TrimSpace(rule.ID)
		udp := rule
		udp.Protocol = v2.FirewallProtoUDP
		udp.ID = ""
		return []v2.FirewallRule{tcp, udp}
	default:
		return []v2.FirewallRule{rule}
	}
}

func NormalizeOmitKeep(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" || len(key) > 40 {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
		if len(out) >= 16 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func KeepOmitKey(rule v2.FirewallRule) string {
	return strings.ToLower(strings.TrimSpace(rule.Comment))
}

func DropOmittedKeep(keep []v2.FirewallRule, omit []string) []v2.FirewallRule {
	omit = NormalizeOmitKeep(omit)
	if len(omit) == 0 {
		return keep
	}
	skip := make(map[string]struct{}, len(omit))
	for _, key := range omit {
		skip[key] = struct{}{}
	}
	out := make([]v2.FirewallRule, 0, len(keep))
	for _, rule := range keep {
		if _, ok := skip[KeepOmitKey(rule)]; ok {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func NormalizeSSHPort(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	port, err := parsePort(raw)
	if err != nil {
		return "", fmt.Errorf("%w: ssh port", ErrInvalidRule)
	}
	return strconv.Itoa(port), nil
}

func NormalizeRule(rule v2.FirewallRule) (v2.FirewallRule, error) {
	id := strings.TrimSpace(rule.ID)
	if id == "" {
		id = newRuleID()
	}
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action != v2.FirewallActionAllow && action != v2.FirewallActionDeny {
		return v2.FirewallRule{}, fmt.Errorf("%w: action", ErrInvalidRule)
	}
	protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if protocol != v2.FirewallProtoTCP && protocol != v2.FirewallProtoUDP {
		return v2.FirewallRule{}, fmt.Errorf("%w: protocol", ErrInvalidRule)
	}
	stack := normalizeStack(rule.Stack)
	if stack == "" {
		return v2.FirewallRule{}, ErrInvalidStack
	}
	port, err := normalizePort(rule.Port)
	if err != nil {
		return v2.FirewallRule{}, err
	}
	source, err := normalizeSource(rule.Source, stack)
	if err != nil {
		return v2.FirewallRule{}, err
	}
	comment := strings.TrimSpace(rule.Comment)
	if len([]rune(comment)) > MaxComment {
		return v2.FirewallRule{}, fmt.Errorf("%w: comment", ErrInvalidRule)
	}
	origin := strings.ToLower(strings.TrimSpace(rule.Origin))
	switch origin {
	case "", v2.FirewallOriginWeb, v2.FirewallOriginImported, v2.FirewallOriginInbound, v2.FirewallOriginFile, v2.FirewallOriginHost, v2.FirewallOriginKeep:
	default:
		origin = v2.FirewallOriginWeb
	}
	if origin == "" {
		origin = v2.FirewallOriginWeb
	}
	priority := rule.Priority
	if priority == 0 {
		priority = DefaultPrio
	}
	if priority < MinPriority || priority > MaxPriority {
		return v2.FirewallRule{}, fmt.Errorf("%w: priority", ErrInvalidRule)
	}
	return v2.FirewallRule{
		ID:        id,
		Enabled:   rule.Enabled,
		Action:    action,
		Protocol:  protocol,
		Port:      port,
		Source:    source,
		Stack:     stack,
		Comment:   comment,
		Origin:    origin,
		Priority:  priority,
		InboundID: strings.TrimSpace(rule.InboundID),
		HostKey:   strings.TrimSpace(rule.HostKey),
	}, nil
}

func StacksForInbound(stack string) []string {
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv6", "v6", "ip6", "6":
		return []string{v2.FirewallStackV6}
	case "dual", "both":
		return []string{v2.FirewallStackV4, v2.FirewallStackV6}
	default:
		return []string{v2.FirewallStackV4}
	}
}

func ProtocolForInbound(protocol, transport string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "quic" || strings.Contains(p, "hysteria") || p == "tuic" {
		return v2.FirewallProtoUDP
	}
	if p == "shadowsocks" {
		t = strings.ReplaceAll(strings.ReplaceAll(t, " ", ""), "/", ",")
		switch t {
		case "udp":
			return v2.FirewallProtoUDP
		case "tcp":
			return v2.FirewallProtoTCP
		default:
			return v2.FirewallProtoBoth
		}
	}
	return v2.FirewallProtoTCP
}

func InboundComment(name, protocol, proto, stack string, port int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "inbound"
	}
	if proto == "" {
		proto = ProtocolForInbound(protocol, "")
	}
	return fmt.Sprintf("入站 %s · %s · %d/%s · %s", name, strings.TrimSpace(protocol), port, proto, stack)
}

func newRuleID() string {
	id := utils.GenerateRandomString(16)
	if id == "" {
		return fmt.Sprintf("fw%x", net.IPv4len)
	}
	return id
}

func normalizeStack(stack string) string {
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case v2.FirewallStackV4, "ipv4", "4", "ip4":
		return v2.FirewallStackV4
	case v2.FirewallStackV6, "ipv6", "6", "ip6":
		return v2.FirewallStackV6
	default:
		return ""
	}
}

func normalizePort(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "*" || strings.EqualFold(raw, "any") {
		return "*", nil
	}
	if raw == "" {
		return "", fmt.Errorf("%w: port", ErrInvalidRule)
	}
	if strings.Contains(raw, ",") {
		return "", fmt.Errorf("%w: port", ErrInvalidRule)
	}
	from, to, ok := strings.Cut(raw, "-")
	if !ok {
		port, err := parsePort(raw)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(port), nil
	}
	start, err := parsePort(from)
	if err != nil {
		return "", err
	}
	end, err := parsePort(to)
	if err != nil {
		return "", err
	}
	if end < start {
		return "", fmt.Errorf("%w: port", ErrInvalidRule)
	}
	if start == end {
		return strconv.Itoa(start), nil
	}
	return fmt.Sprintf("%d-%d", start, end), nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: port", ErrInvalidRule)
	}
	return port, nil
}

func normalizeSource(raw, stack string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" || strings.EqualFold(raw, "any") || raw == "0.0.0.0/0" && stack == v2.FirewallStackV4 || raw == "::/0" && stack == v2.FirewallStackV6 {
		return "", nil
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return "", fmt.Errorf("%w: source", ErrInvalidRule)
		}
		if err := matchStackAddr(prefix.Addr(), stack); err != nil {
			return "", err
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("%w: source", ErrInvalidRule)
	}
	if err := matchStackAddr(addr, stack); err != nil {
		return "", err
	}
	if addr.Is4() {
		return addr.String() + "/32", nil
	}
	return addr.String() + "/128", nil
}

func matchStackAddr(addr netip.Addr, stack string) error {
	if stack == v2.FirewallStackV4 && addr.Is4() {
		return nil
	}
	if stack == v2.FirewallStackV6 && addr.Is6() {
		return nil
	}
	return ErrStackSource
}

func ApplyDefaultDenyView(intent v2.FirewallIntent, _, blocked bool) v2.FirewallIntent {
	if blocked {
		intent.DefaultDeny4 = false
		intent.DefaultDeny6 = false
	}
	return intent
}

func DisplaySshPort(intentPort, snapPort string, applied bool) string {
	intentPort = strings.TrimSpace(intentPort)
	snapPort = strings.TrimSpace(snapPort)
	if applied && intentPort != "" {
		return intentPort
	}
	if snapPort != "" {
		return snapPort
	}
	return intentPort
}

func isSSHKeep(rule v2.FirewallRule) bool {
	return strings.EqualFold(strings.TrimSpace(rule.Origin), v2.FirewallOriginKeep) &&
		strings.EqualFold(strings.TrimSpace(rule.Comment), "SSH")
}

func RewriteKeepSSH(keep []v2.FirewallRule, sshPort string, stackV4, stackV6 bool) []v2.FirewallRule {
	sshPort = strings.TrimSpace(sshPort)
	if sshPort == "" {
		return keep
	}
	out := make([]v2.FirewallRule, 0, len(keep)+2)
	stacks := map[string]bool{}
	for _, rule := range keep {
		if isSSHKeep(rule) {
			stacks[rule.Stack] = true
			continue
		}
		out = append(out, rule)
	}
	if len(stacks) == 0 {
		if stackV4 {
			stacks[v2.FirewallStackV4] = true
		}
		if stackV6 {
			stacks[v2.FirewallStackV6] = true
		}
	}
	if len(stacks) == 0 {
		stacks[v2.FirewallStackV4] = true
		stacks[v2.FirewallStackV6] = true
	}
	for _, stack := range []string{v2.FirewallStackV4, v2.FirewallStackV6} {
		if !stacks[stack] {
			continue
		}
		out = append(out, v2.FirewallRule{
			ID:       "keep-" + stack + "-" + sshPort,
			Enabled:  true,
			Action:   v2.FirewallActionAllow,
			Protocol: v2.FirewallProtoTCP,
			Port:     sshPort,
			Stack:    stack,
			Comment:  "SSH",
			Origin:   v2.FirewallOriginKeep,
			Priority: 1,
		})
	}
	return out
}

func DropOrphanInboundRules(rules []v2.FirewallRule, live map[string]struct{}) []v2.FirewallRule {
	if live == nil {
		return rules
	}
	out := make([]v2.FirewallRule, 0, len(rules))
	for _, rule := range rules {
		if strings.EqualFold(strings.TrimSpace(rule.Origin), v2.FirewallOriginInbound) {
			id := strings.TrimSpace(rule.InboundID)
			if id == "" {
				continue
			}
			if _, ok := live[id]; !ok {
				continue
			}
		}
		out = append(out, rule)
	}
	return out
}

func DropOwnedHostNoise(rules []v2.FirewallHostRule) []v2.FirewallHostRule {
	if len(rules) == 0 {
		return rules
	}
	out := make([]v2.FirewallHostRule, 0, len(rules))
	for _, rule := range rules {
		if ownedHostNoise(rule) {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func ownedHostNoise(rule v2.FirewallHostRule) bool {
	raw := strings.ToLower(strings.TrimSpace(rule.Raw + " " + rule.Comment + " " + rule.Key))
	if strings.Contains(raw, "lite_plus") || strings.Contains(raw, "lite-plus:") {
		return true
	}
	line := strings.ToLower(strings.TrimSpace(rule.Raw))
	if strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy ") || strings.HasPrefix(line, "hook ") {
		return true
	}
	if strings.Contains(line, "hook") && strings.Contains(line, "priority") {
		return true
	}
	return false
}

func AttachKeepRules(intent v2.FirewallIntent, keep []v2.FirewallRule) v2.FirewallIntent {
	if !intent.DefaultDeny4 && !intent.DefaultDeny6 {
		return intent
	}
	seen := make(map[string]struct{}, len(intent.Rules))
	for _, rule := range intent.Rules {
		if !rule.Enabled || !strings.EqualFold(rule.Action, v2.FirewallActionAllow) {
			continue
		}
		seen[rule.Protocol+"/"+rule.Port+"/"+rule.Stack] = struct{}{}
	}
	extra := make([]v2.FirewallRule, 0, len(keep))
	for _, rule := range keep {
		if rule.Stack == v2.FirewallStackV4 && !intent.DefaultDeny4 {
			continue
		}
		if rule.Stack == v2.FirewallStackV6 && !intent.DefaultDeny6 {
			continue
		}
		key := rule.Protocol + "/" + rule.Port + "/" + rule.Stack
		if _, ok := seen[key]; ok {
			continue
		}
		extra = append(extra, rule)
		seen[key] = struct{}{}
	}
	if len(extra) == 0 {
		return intent
	}
	intent.Rules = append(extra, intent.Rules...)
	return intent
}

func DefaultDenyConflict(backend string, outer []string) bool {
	if backend == v2.FirewallBackendUFW || backend == v2.FirewallBackendFirewalld {
		return false
	}
	for _, name := range outer {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case v2.FirewallBackendUFW, v2.FirewallBackendFirewalld:
			return true
		}
	}
	return false
}
