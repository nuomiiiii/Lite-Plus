package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
)

// Independent Lite-Plus subscription renderer. Does not copy Clash / v2rayN / sing-box converters.

type Node struct {
	Name        string
	Protocol    string
	Host        string
	Port        int
	UUID        string
	Password    string
	Security    string
	Type        string
	Path        string
	HostHeader  string
	SNI         string
	Flow        string
	Fingerprint string
	PublicKey   string
	ShortID     string
	SpiderX     string
	ServiceName string
	ALPN        string
	Mode        string
	Cipher      string
}

func ParseExtraURLs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func UserNodes(user models.NodeUser, inbounds []models.Inbound, creds []models.Credential) []Node {
	return Assemble(user, inbounds, creds, nil, nil)
}

type nodeAddr struct {
	IPv4 string
	IPv6 string
}

func parseNodeHost(raw string) nodeAddr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nodeAddr{}
	}
	if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
		return nodeAddr{IPv6: raw}
	}
	return nodeAddr{IPv4: raw}
}

func stringHosts(hosts map[string]string) map[string]nodeAddr {
	if hosts == nil {
		return nil
	}
	out := make(map[string]nodeAddr, len(hosts))
	for id, host := range hosts {
		out[id] = parseNodeHost(host)
	}
	return out
}

func (a nodeAddr) forStack(stack string) string {
	v4 := strings.TrimSpace(a.IPv4)
	v6 := strings.TrimSpace(a.IPv6)
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv4":
		if v4 != "" {
			return v4
		}
		return v6
	default:
		if v6 != "" {
			return v6
		}
		return v4
	}
}

func Assemble(user models.NodeUser, inbounds []models.Inbound, creds []models.Credential, granted map[string]bool, nodeHosts map[string]string) []Node {
	return AssembleWithCerts(user, inbounds, creds, granted, nodeHosts, nil)
}

type certDomainIndex struct {
	byID   map[string]string
	byNode map[string]string
}

func indexCertDomains(certs []models.Certificate) certDomainIndex {
	idx := certDomainIndex{byID: map[string]string{}, byNode: map[string]string{}}
	now := time.Now().UTC()
	for _, cert := range certs {
		if !strings.EqualFold(strings.TrimSpace(cert.Status), models.CertIssued) {
			continue
		}
		domain := strings.TrimSpace(cert.Domain)
		if domain == "" {
			continue
		}
		if cert.NotAfter != nil && !cert.NotAfter.After(now) {
			continue
		}
		idx.byID[cert.ID] = domain
		if _, ok := idx.byNode[cert.NodeUUID]; !ok {
			idx.byNode[cert.NodeUUID] = domain
		}
	}
	return idx
}

func (idx certDomainIndex) domainFor(nodeUUID, certID string) string {
	if idx.byID != nil {
		if domain := strings.TrimSpace(idx.byID[certID]); domain != "" {
			return domain
		}
	}
	if idx.byNode != nil {
		return strings.TrimSpace(idx.byNode[nodeUUID])
	}
	return ""
}

func AssembleWithCerts(user models.NodeUser, inbounds []models.Inbound, creds []models.Credential, granted map[string]bool, nodeHosts map[string]string, certs []models.Certificate) []Node {
	return assembleWithAddrs(user, inbounds, creds, granted, stringHosts(nodeHosts), certs)
}

func assembleWithAddrs(user models.NodeUser, inbounds []models.Inbound, creds []models.Credential, granted map[string]bool, nodeHosts map[string]nodeAddr, certs []models.Certificate) []Node {
	var uuid, password string
	now := time.Now().UTC()
	for _, c := range creds {
		if !c.Enabled {
			continue
		}
		if c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
			continue
		}
		secret := c.SecretMaterial
		if secret == "" {
			secret = c.UUID
		}
		if c.UUID != "" && uuid == "" {
			uuid = c.UUID
		}
		if password == "" && secret != "" {
			password = secret
		}
	}
	if password == "" {
		password = uuid
	}
	certDomains := indexCertDomains(certs)
	ordered := append([]models.Inbound(nil), inbounds...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].SortIndex != ordered[j].SortIndex {
			return ordered[i].SortIndex < ordered[j].SortIndex
		}
		return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
	})
	var nodes []Node
	for _, in := range ordered {
		if !in.Enabled {
			continue
		}
		if granted != nil && !granted[in.ID] {
			continue
		}
		cfg := inboundcfg.Parse(in.SettingsJSON)
		var addrs nodeAddr
		if nodeHosts != nil {
			addrs = nodeHosts[in.NodeUUID]
		}
		host, port, ok := shareAddress(in, cfg, addrs, certDomains)
		if !ok {
			continue
		}
		security := strings.ToLower(strings.TrimSpace(cfg.Security))
		if security == "" {
			security = "none"
		}
		transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
		if transport == "" {
			transport = "tcp"
		}
		flow := shareFlow(in, cfg, user, transport, security)
		path, hostHeader, serviceName, mode := shareTransportFields(transport, cfg)
		sni := cfg.SNI
		if sni == "" && security == "reality" {
			sni = inboundcfg.DestHost(cfg.RealityDest)
			if sni == "" {
				sni = cfg.RealityServerNames
			}
		}
		nodes = append(nodes, Node{
			Name:        shareName(in),
			Protocol:    in.Protocol,
			Host:        host,
			Port:        port,
			UUID:        uuid,
			Password:    password,
			Security:    security,
			Type:        transport,
			Path:        path,
			HostHeader:  hostHeader,
			SNI:         sni,
			Flow:        flow,
			Fingerprint: cfg.Fingerprint,
			PublicKey:   cfg.RealityPublicKey,
			ShortID:     cfg.RealityShortID,
			SpiderX:     cfg.SpiderX,
			ServiceName: serviceName,
			ALPN:        cfg.ALPN,
			Mode:        mode,
			Cipher:      cfg.SSMethod,
		})
	}
	return nodes
}

func shareFlow(in models.Inbound, cfg inboundcfg.Settings, user models.NodeUser, transport, security string) string {
	if strings.EqualFold(strings.TrimSpace(in.Core), models.CoreSingBox) {
		return ""
	}
	if transport != "tcp" && transport != "raw" {
		return ""
	}
	if security != "tls" && security != "reality" {
		return ""
	}
	flow := cfg.Flow
	if strings.TrimSpace(user.Flow) != "" {
		flow = user.Flow
	}
	return flow
}

func shareTransportFields(transport string, cfg inboundcfg.Settings) (path, hostHeader, serviceName, mode string) {
	switch transport {
	case "ws":
		return cfg.WSPath, cfg.WSHost, "", ""
	case "grpc":
		return "", "", cfg.GRPCService, ""
	case "httpupgrade":
		return cfg.HTTPPath, cfg.HTTPHost, "", ""
	case "xhttp":
		return cfg.HTTPPath, cfg.HTTPHost, "", cfg.HTTPMode
	default:
		return "", "", "", ""
	}
}

func shareName(in models.Inbound) string {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = strings.TrimSpace(in.ID)
	}
	return name
}

func shareAddress(in models.Inbound, cfg inboundcfg.Settings, addrs nodeAddr, certs certDomainIndex) (string, int, bool) {
	strategy := inboundcfg.NormalizeShareStrategy(cfg.ShareStrategy)
	if cfg.ExcludeFromSub {
		strategy = "none"
	}
	if strategy == "none" {
		return "", 0, false
	}
	host := ""
	switch strategy {
	case "listen":
		host = strings.TrimSpace(in.Listen)
	case "other":
		host = strings.TrimSpace(cfg.PublicHost)
	default:
		host = certs.domainFor(in.NodeUUID, cfg.CertID)
		if host == "" {
			host = addrs.forStack(cfg.Stack)
		}
	}
	port := in.Port
	if cfg.PublicPort > 0 && cfg.PublicPort <= 65535 {
		port = cfg.PublicPort
	}
	host = canonicalShareHost(host)
	if wildcardHost(host) || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func canonicalShareHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	lower := strings.ToLower(host)
	switch {
	case strings.HasPrefix(lower, "https://"):
		host = host[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		host = host[len("http://"):]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end > 1 {
			host = host[1:end]
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			return ip.String()
		}
		return h
	}
	return strings.TrimSuffix(host, ":")
}

func shareHostPort(host string, port int) string {
	return net.JoinHostPort(canonicalShareHost(host), fmt.Sprintf("%d", port))
}

func wildcardHost(host string) bool {
	return inboundcfg.IsWildcardListen(host)
}

func Render(format string, nodes []Node, extra []string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "clash":
		return RenderClash(nodes, extra), "text/yaml; charset=utf-8", nil
	case "sing-box", "singbox":
		body, err := RenderSingBox(nodes, extra)
		return body, "application/json; charset=utf-8", err
	case "", "xray", "v2ray", "v2rayn", "base64":
		return RenderV2RayBase64(nodes, extra), "text/plain; charset=utf-8", nil
	default:
		return "", "", fmt.Errorf("unsupported format %q", format)
	}
}

func RenderClash(nodes []Node, extra []string) string {
	nodes, extra = mergeExtraNodes(nodes, extra)
	var b strings.Builder
	b.WriteString("# Lite-Plus subscription\n")
	b.WriteString("proxies:\n")
	for _, n := range nodes {
		b.WriteString(clashProxy(n))
	}
	if len(extra) > 0 {
		b.WriteString("# extra\n")
		for _, u := range extra {
			b.WriteString("# " + u + "\n")
		}
	}
	return b.String()
}

func clashProxy(n Node) string {
	kind := clashType(n.Protocol)
	var b strings.Builder
	fmt.Fprintf(&b, "  - name: %q\n    type: %s\n    server: %s\n    port: %d\n    udp: true\n", n.Name, kind, n.Host, n.Port)
	switch kind {
	case "ss":
		cipher := n.Cipher
		if cipher == "" {
			cipher = "aes-128-gcm"
		}
		fmt.Fprintf(&b, "    cipher: %s\n    password: %s\n", cipher, yamlQuote(n.Password))
	case "trojan", "hysteria2", "anytls":
		fmt.Fprintf(&b, "    password: %s\n", yamlQuote(n.Password))
	case "tuic":
		fmt.Fprintf(&b, "    uuid: %s\n    password: %s\n", n.UUID, yamlQuote(n.Password))
	default:
		fmt.Fprintf(&b, "    uuid: %s\n", n.UUID)
		if n.Flow != "" {
			fmt.Fprintf(&b, "    flow: %s\n", n.Flow)
		}
	}
	if n.Type != "" && n.Type != "tcp" {
		fmt.Fprintf(&b, "    network: %s\n", n.Type)
	}
	useTLS := n.Security == "tls" || n.Security == "reality"
	if useTLS {
		b.WriteString("    tls: true\n")
		if n.SNI != "" {
			fmt.Fprintf(&b, "    servername: %s\n", n.SNI)
		}
		if n.Fingerprint != "" {
			fmt.Fprintf(&b, "    client-fingerprint: %s\n", n.Fingerprint)
		}
		if n.ALPN != "" {
			fmt.Fprintf(&b, "    alpn: [%s]\n", n.ALPN)
		}
	}
	if n.Security == "reality" {
		b.WriteString("    reality-opts:\n")
		fmt.Fprintf(&b, "      public-key: %s\n", n.PublicKey)
		fmt.Fprintf(&b, "      short-id: %s\n", n.ShortID)
	}
	switch n.Type {
	case "ws":
		b.WriteString("    ws-opts:\n")
		fmt.Fprintf(&b, "      path: %s\n", orDefault(n.Path, "/"))
		if n.HostHeader != "" {
			b.WriteString("      headers:\n")
			fmt.Fprintf(&b, "        Host: %s\n", n.HostHeader)
		}
	case "grpc":
		svc := n.ServiceName
		if svc == "" {
			svc = "gun"
		}
		b.WriteString("    grpc-opts:\n")
		fmt.Fprintf(&b, "      grpc-service-name: %s\n", svc)
	case "httpupgrade", "xhttp":
		b.WriteString("    ws-opts:\n")
		fmt.Fprintf(&b, "      path: %s\n", orDefault(n.Path, "/"))
		if n.HostHeader != "" {
			b.WriteString("      headers:\n")
			fmt.Fprintf(&b, "        Host: %s\n", n.HostHeader)
		}
	}
	return b.String()
}

func yamlQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

func clashType(p string) string {
	switch strings.ToLower(p) {
	case "vmess":
		return "vmess"
	case "trojan":
		return "trojan"
	case "shadowsocks", "ss":
		return "ss"
	case "hysteria2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "anytls":
		return "anytls"
	default:
		return "vless"
	}
}

func singBoxType(p string) string {
	switch strings.ToLower(p) {
	case "vmess":
		return "vmess"
	case "trojan":
		return "trojan"
	case "shadowsocks", "ss":
		return "shadowsocks"
	case "hysteria2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "anytls":
		return "anytls"
	default:
		return "vless"
	}
}

func RenderSingBox(nodes []Node, extra []string) (string, error) {
	nodes, extra = mergeExtraNodes(nodes, extra)
	_ = extra
	var outs []map[string]any
	for _, n := range nodes {
		kind := singBoxType(n.Protocol)
		item := map[string]any{
			"type":        kind,
			"tag":         n.Name,
			"server":      n.Host,
			"server_port": n.Port,
		}
		switch kind {
		case "shadowsocks":
			method := n.Cipher
			if method == "" {
				method = "aes-128-gcm"
			}
			item["method"] = method
			item["password"] = n.Password
		case "trojan", "hysteria2", "anytls":
			item["password"] = n.Password
		case "tuic":
			if n.UUID != "" {
				item["uuid"] = n.UUID
			}
			if n.Password != "" {
				item["password"] = n.Password
			}
		default:
			if n.UUID != "" {
				item["uuid"] = n.UUID
			}
			if n.Password != "" && n.UUID == "" {
				item["password"] = n.Password
			}
			if n.Flow != "" {
				item["flow"] = n.Flow
			}
		}
		if transport := singBoxOutboundTransport(kind, n); transport != nil {
			item["transport"] = transport
		}
		if n.Security == "tls" || n.Security == "reality" {
			tls := map[string]any{"enabled": true}
			if n.SNI != "" {
				tls["server_name"] = n.SNI
			}
			if n.Fingerprint != "" {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
			}
			if n.ALPN != "" {
				tls["alpn"] = csvList(n.ALPN)
			}
			if n.Security == "reality" {
				tls["reality"] = map[string]any{"enabled": true, "public_key": n.PublicKey, "short_id": n.ShortID}
			}
			item["tls"] = tls
		}
		outs = append(outs, item)
	}
	payload := map[string]any{"outbounds": outs}
	b, err := json.MarshalIndent(payload, "", "  ")
	return string(b), err
}

func singBoxOutboundTransport(kind string, n Node) map[string]any {
	if kind == "hysteria2" || kind == "tuic" || kind == "anytls" {
		return nil
	}
	t := strings.ToLower(n.Type)
	switch t {
	case "", "tcp", "raw", "quic":
		return nil
	case "ws", "websocket":
		item := map[string]any{"type": "ws"}
		if n.Path != "" {
			item["path"] = n.Path
		}
		if n.HostHeader != "" {
			item["headers"] = map[string]any{"Host": n.HostHeader}
		}
		return item
	case "grpc":
		item := map[string]any{"type": "grpc"}
		if n.ServiceName != "" {
			item["service_name"] = n.ServiceName
		}
		return item
	case "httpupgrade":
		item := map[string]any{"type": "httpupgrade"}
		if n.Path != "" {
			item["path"] = n.Path
		}
		if n.HostHeader != "" {
			item["host"] = n.HostHeader
		}
		return item
	default:
		return map[string]any{"type": t}
	}
}

func RenderV2RayBase64(nodes []Node, extra []string) string {
	var lines []string
	for _, n := range nodes {
		scheme := strings.ToLower(n.Protocol)
		if scheme == "shadowsocks" {
			scheme = "ss"
		}
		if scheme == "vmess" {
			obj := map[string]any{
				"v":    "2",
				"ps":   n.Name,
				"add":  n.Host,
				"port": n.Port,
				"id":   n.UUID,
				"aid":  0,
				"net":  n.Type,
				"type": "none",
				"host": n.HostHeader,
				"path": n.Path,
				"tls":  n.Security,
				"sni":  n.SNI,
				"fp":   n.Fingerprint,
			}
			raw, _ := json.Marshal(obj)
			lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString(raw))
			continue
		}
		if scheme == "ss" {
			method := n.Cipher
			if method == "" {
				method = "aes-128-gcm"
			}
			userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + n.Password))
			u := url.URL{Scheme: "ss", Host: shareHostPort(n.Host, n.Port), User: url.User(userinfo)}
			u.Fragment = n.Name
			lines = append(lines, u.String())
			continue
		}
		id := n.UUID
		if scheme == "trojan" || scheme == "anytls" {
			id = n.Password
			if id == "" {
				id = n.UUID
			}
		}
		u := url.URL{
			Scheme: scheme,
			Host:   shareHostPort(n.Host, n.Port),
			User:   url.User(id),
		}
		q := u.Query()
		if scheme == "vless" {
			q.Set("encryption", "none")
		}
		if n.Security != "" {
			q.Set("security", n.Security)
		}
		if scheme != "anytls" && n.Type != "" {
			q.Set("type", n.Type)
		}
		if n.Path != "" {
			q.Set("path", n.Path)
		}
		if n.HostHeader != "" {
			q.Set("host", n.HostHeader)
		}
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		if n.Fingerprint != "" {
			q.Set("fp", n.Fingerprint)
		}
		if n.PublicKey != "" {
			q.Set("pbk", n.PublicKey)
		}
		if n.ShortID != "" {
			q.Set("sid", n.ShortID)
		}
		if n.SpiderX != "" {
			q.Set("spx", n.SpiderX)
		}
		if n.ServiceName != "" {
			q.Set("serviceName", n.ServiceName)
		}
		if n.ALPN != "" {
			q.Set("alpn", n.ALPN)
		}
		if n.Mode != "" {
			q.Set("mode", n.Mode)
		}
		u.RawQuery = q.Encode()
		u.Fragment = n.Name
		lines = append(lines, u.String())
	}
	lines = append(lines, extra...)
	raw := strings.Join(lines, "\n")
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func DecodeShareLinks(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(body); err == nil && looksLikeLinks(string(decoded)) {
		body = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(body); err == nil && looksLikeLinks(string(decoded)) {
		body = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(body); err == nil && looksLikeLinks(string(decoded)) {
		body = string(decoded)
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "://") {
			out = append(out, line)
		}
	}
	return out
}

func looksLikeLinks(s string) bool {
	return strings.Contains(s, "://")
}

func csvList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
