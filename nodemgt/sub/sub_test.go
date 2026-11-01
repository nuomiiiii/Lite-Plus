package sub

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
)

func TestRenderFormats(t *testing.T) {
	nodes := UserNodes(models.NodeUser{Username: "alice"}, []models.Inbound{{
		Name: "in1", Protocol: "vless", Listen: "1.2.3.4", Port: 443, Enabled: true,
		SettingsJSON: `{"security":"none","transport":"tcp","share_strategy":"other","public_host":"node.example.com"}`,
	}}, []models.Credential{{UUID: "u-1", Enabled: true}})
	if len(nodes) != 1 || nodes[0].Host != "node.example.com" {
		t.Fatalf("public host: %+v", nodes)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil || !strings.Contains(clash, "in1") || strings.Contains(clash, "alice-in1") {
		t.Fatalf("clash: %v %s", err, clash)
	}
	if strings.Contains(clash, "tls: true") {
		t.Fatalf("plain inbound must not force tls: %s", clash)
	}
	body, _, err := Render("xray", nodes, nil)
	if err != nil || body == "" {
		t.Fatalf("xray: %v", err)
	}
	v2ray, _, err := Render("v2ray", nodes, nil)
	if err != nil || v2ray != body {
		t.Fatalf("v2ray alias: %v", err)
	}
	links := DecodeShareLinks(body)
	if len(links) == 0 {
		t.Fatal("decode")
	}
}

func TestShareNameUsesInboundNameForAllProtocols(t *testing.T) {
	user := models.NodeUser{Username: "免流"}
	creds := []models.Credential{{UUID: "u", Enabled: true}}
	settings := `{"share_strategy":"other","public_host":"node.example.com","security":"none","transport":"ws","ws_path":"/ws"}`
	for _, proto := range []string{"vless", "vmess", "trojan", "shadowsocks", "http", "hysteria2", "tuic", "anytls"} {
		in := models.Inbound{
			ID: proto + "-id", Name: "US_LAX_" + proto, Protocol: proto,
			Listen: "0.0.0.0", Port: 443, Enabled: true, SettingsJSON: settings,
		}
		nodes := Assemble(user, []models.Inbound{in}, creds, map[string]bool{in.ID: true}, nil)
		if len(nodes) != 1 {
			t.Fatalf("%s: want 1 node, got %+v", proto, nodes)
		}
		if nodes[0].Name != in.Name {
			t.Fatalf("%s: name %q, want inbound name %q", proto, nodes[0].Name, in.Name)
		}
		if strings.Contains(nodes[0].Name, user.Username+"-") {
			t.Fatalf("%s: username leaked into share name: %q", proto, nodes[0].Name)
		}
		raw, _, err := Render("v2ray", nodes, nil)
		if err != nil {
			t.Fatal(err)
		}
		link := DecodeShareLinks(raw)[0]
		if strings.HasPrefix(link, "vmess://") {
			payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
			if err != nil {
				t.Fatalf("%s: decode vmess: %v", proto, err)
			}
			if strings.Contains(string(payload), user.Username+"-") {
				t.Fatalf("%s: vmess ps still prefixes username: %s", proto, payload)
			}
		} else if strings.Contains(link, user.Username+"-") {
			t.Fatalf("%s: share link still prefixes username: %s", proto, link)
		}
	}
	emptyName := Assemble(user, []models.Inbound{{
		ID: "fallback-id", Protocol: "vmess", Listen: "1.2.3.4", Port: 443, Enabled: true,
		SettingsJSON: settings,
	}}, creds, map[string]bool{"fallback-id": true}, nil)
	if len(emptyName) != 1 || emptyName[0].Name != "fallback-id" {
		t.Fatalf("empty inbound name should fall back to id: %+v", emptyName)
	}
}

func TestHTTPShareUsesUsernamePassword(t *testing.T) {
	user := models.NodeUser{Username: "免流"}
	in := models.Inbound{
		ID: "http-in", Name: "US_HTTP", Protocol: "http",
		Listen: "0.0.0.0", Port: 8080, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"proxy.example.com","security":"none","transport":"tcp"}`,
	}
	nodes := Assemble(user, []models.Inbound{in}, []models.Credential{{UUID: "u-1", SecretMaterial: "secret", Enabled: true}}, map[string]bool{"http-in": true}, nil)
	if len(nodes) != 1 || nodes[0].Protocol != "http" || nodes[0].Username != "免流" || nodes[0].Password != "secret" {
		t.Fatalf("http node: %+v", nodes)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	if !strings.HasPrefix(link, "http://") || !strings.Contains(link, "secret") || strings.Contains(link, "免流-US_HTTP") {
		t.Fatalf("http share link: %s", link)
	}
	parsed, ok := NodeFromShareLink(link)
	if !ok || parsed.Protocol != "http" || parsed.Username != "免流" || parsed.Password != "secret" || parsed.Name != "US_HTTP" {
		t.Fatalf("parse http share: %+v", parsed)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "type: http") || !strings.Contains(clash, "udp: false") || strings.Contains(clash, "uuid:") {
		t.Fatalf("clash http: %s", clash)
	}
	sing, _, err := Render("sing-box", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sing, `"type": "http"`) || !strings.Contains(sing, `"username": "免流"`) || strings.Contains(sing, `"transport"`) {
		t.Fatalf("sing-box http: %s", sing)
	}
}

func TestSSShareUsesMethodPassword(t *testing.T) {
	user := models.NodeUser{Username: "免流"}
	in := models.Inbound{
		ID: "ss-in", Name: "US_SS", Protocol: "shadowsocks",
		Listen: "0.0.0.0", Port: 8388, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"ss.example.com","ss_method":"aes-128-gcm","security":"none","transport":"tcp"}`,
	}
	nodes := Assemble(user, []models.Inbound{in}, []models.Credential{{UUID: "u-1", SecretMaterial: "secret", Enabled: true}}, map[string]bool{"ss-in": true}, nil)
	if len(nodes) != 1 || nodes[0].Protocol != "shadowsocks" || nodes[0].Password != "secret" || nodes[0].Cipher != "aes-128-gcm" {
		t.Fatalf("ss node: %+v", nodes)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	if !strings.HasPrefix(link, "ss://") || strings.Contains(link, "免流-US_SS") {
		t.Fatalf("ss share link: %s", link)
	}
	parsed, ok := NodeFromShareLink(link)
	if !ok || parsed.Protocol != "shadowsocks" || parsed.Password != "secret" || parsed.Cipher != "aes-128-gcm" || parsed.Name != "US_SS" {
		t.Fatalf("parse ss share: %+v from %s", parsed, link)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "type: ss") || !strings.Contains(clash, "cipher: aes-128-gcm") || !strings.Contains(clash, "secret") {
		t.Fatalf("clash ss: %s", clash)
	}
	sing, _, err := Render("sing-box", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sing, `"type": "shadowsocks"`) || !strings.Contains(sing, `"method": "aes-128-gcm"`) || !strings.Contains(sing, `"password": "secret"`) {
		t.Fatalf("sing-box ss: %s", sing)
	}
}

func TestSSShareDoesNotLeakListenNetwork(t *testing.T) {
	user := models.NodeUser{Username: "alice"}
	in := models.Inbound{
		ID: "ss-in", Name: "US_SS", Protocol: "shadowsocks",
		Listen: "0.0.0.0", Port: 8388, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"ss.example.com","ss_method":"aes-128-gcm","ss_network":"tcp,udp","transport":"tcp,udp","security":"none"}`,
	}
	nodes := Assemble(user, []models.Inbound{in}, []models.Credential{{UUID: "u-1", SecretMaterial: "secret", Enabled: true}}, map[string]bool{"ss-in": true}, nil)
	if len(nodes) != 1 || nodes[0].Type != "tcp" {
		t.Fatalf("ss share type must stay tcp, got %+v", nodes)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clash, "network: tcp,udp") {
		t.Fatalf("clash leaked ss listen network: %s", clash)
	}
	sing, _, err := Render("sing-box", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sing, `"type": "tcp,udp"`) {
		t.Fatalf("sing-box leaked ss listen network: %s", sing)
	}
}

func TestSS2022ShareUsesCombinedPSK(t *testing.T) {
	user := models.NodeUser{Username: "alice"}
	in := models.Inbound{
		ID: "ss-2022", Name: "US_SS2022", Protocol: "shadowsocks",
		Listen: "0.0.0.0", Port: 8388, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"ss.example.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA==","security":"none","transport":"tcp"}`,
	}
	nodes := Assemble(user, []models.Inbound{in}, []models.Credential{{UUID: "u-1", SecretMaterial: "secret", Enabled: true}}, map[string]bool{"ss-2022": true}, nil)
	want := inboundcfg.SS2022SharePassword("AAAAAAAAAAAAAAAAAAAAAA==", "secret", "ss-2022", "2022-blake3-aes-128-gcm")
	if len(nodes) != 1 || nodes[0].Password != want {
		t.Fatalf("ss2022 node password %q want %q", nodes[0].Password, want)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	if !strings.Contains(link, "ss://2022-blake3-aes-128-gcm:") {
		t.Fatalf("ss2022 share must keep plaintext method: %s", link)
	}
	if strings.Contains(link, base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+want))) {
		t.Fatalf("ss2022 share must not use SIP002 base64 userinfo: %s", link)
	}
	if !strings.Contains(link, "%3A") {
		t.Fatalf("ss2022 combined PSK colon must be percent-encoded: %s", link)
	}
	parsed, ok := NodeFromShareLink(link)
	if !ok || parsed.Password != want || parsed.Cipher != "2022-blake3-aes-128-gcm" {
		t.Fatalf("parse ss2022: %+v from %s", parsed, link)
	}
}

func TestAssembleGrantsSortAndReality(t *testing.T) {
	user := models.NodeUser{Username: "bob", Flow: "xtls-rprx-vision"}
	inbounds := []models.Inbound{
		{ID: "later", Name: "b", Protocol: "vless", Listen: "0.0.0.0", Port: 443, Enabled: true, SortIndex: 2,
			SettingsJSON: `{"share_strategy":"other","public_host":"b.example.com","security":"reality","transport":"tcp","reality_public_key":"pk","reality_short_id":"abcd","fingerprint":"chrome"}`},
		{ID: "first", Name: "a", Protocol: "vless", Listen: "0.0.0.0", Port: 8443, Enabled: true, SortIndex: 1,
			SettingsJSON: `{"share_strategy":"other","public_host":"a.example.com","security":"reality","transport":"tcp","reality_public_key":"pk","reality_short_id":"abcd"}`},
		{ID: "skip", Name: "c", Protocol: "vless", Listen: "10.0.0.1", Port: 443, Enabled: true, SortIndex: 3,
			SettingsJSON: `{"exclude_from_sub":true,"public_host":"c.example.com"}`},
		{ID: "wild", Name: "d", Protocol: "vless", Listen: "0.0.0.0", Port: 443, Enabled: true, SortIndex: 4,
			SettingsJSON: `{"security":"none"}`},
	}
	granted := map[string]bool{"later": true, "first": true, "skip": true, "wild": true}
	nodes := Assemble(user, inbounds, []models.Credential{{UUID: "cred", Enabled: true}}, granted, nil)
	if len(nodes) != 2 {
		t.Fatalf("want 2 shareable granted nodes, got %+v", nodes)
	}
	if nodes[0].Name != "a" || nodes[1].Name != "b" {
		t.Fatalf("order %+v", nodes)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "reality-opts") || !strings.Contains(clash, "public-key: pk") {
		t.Fatalf("reality clash: %s", clash)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(raw)
	if !strings.Contains(string(decoded), "pbk=pk") || !strings.Contains(string(decoded), "flow=xtls-rprx-vision") {
		t.Fatalf("share link %s", decoded)
	}
}

func TestAssembleUsesNodeAddressWhenListenIsWildcard(t *testing.T) {
	in := models.Inbound{
		ID: "n", NodeUUID: "node-1", Name: "edge", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true, SortIndex: 1,
	}
	nodes := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"})
	if len(nodes) != 1 || nodes[0].Host != "203.0.113.9" {
		t.Fatalf("node address fallback: %+v", nodes)
	}
	none := in
	none.SettingsJSON = `{"share_strategy":"none"}`
	if got := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{none}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"}); len(got) != 0 {
		t.Fatalf("none strategy leaked: %+v", got)
	}
	specified := in
	specified.SettingsJSON = `{"share_strategy":"specified"}`
	if got := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{specified}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"}); len(got) != 0 {
		t.Fatalf("specified without host leaked: %+v", got)
	}
	other := in
	other.SettingsJSON = `{"share_strategy":"other","public_host":"share.example.com","public_port":8443}`
	gotOther := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{other}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"})
	if len(gotOther) != 1 || gotOther[0].Host != "share.example.com" || gotOther[0].Port != 8443 {
		t.Fatalf("other uses custom host and public port: %+v", gotOther)
	}
	listenOK := in
	listenOK.Listen = "198.51.100.10"
	listenOK.SettingsJSON = `{"share_strategy":"listen","public_host":"ignored.example.com"}`
	gotListen := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{listenOK}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"})
	if len(gotListen) != 1 || gotListen[0].Host != "198.51.100.10" || gotListen[0].Port != 443 {
		t.Fatalf("listen uses inbound address: %+v", gotListen)
	}
	listenWild := in
	listenWild.SettingsJSON = `{"share_strategy":"listen"}`
	if got := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{listenWild}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, map[string]string{"node-1": "203.0.113.9"}); len(got) != 0 {
		t.Fatalf("wildcard listen leaked: %+v", got)
	}
}

func TestRenderSingBoxUsesParserFields(t *testing.T) {
	nodes := []Node{
		{Name: "audit-ws", Protocol: "vless", Host: "127.0.0.1", Port: 443, UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Type: "ws", Path: "/audit", HostHeader: "audit.test"},
		{Name: "audit-grpc", Protocol: "vless", Host: "127.0.0.1", Port: 443, UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Type: "grpc", ServiceName: "audit"},
		{Name: "audit-hy2", Protocol: "hysteria2", Host: "127.0.0.1", Port: 443, Password: "audit-secret", Type: "quic", Security: "tls", SNI: "audit.test"},
	}
	for _, node := range nodes {
		body, err := RenderSingBox([]Node{node}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, `"extra"`) || strings.Contains(body, `"host"`) {
			t.Fatalf("unsupported field in %s: %s", node.Name, body)
		}
		if node.Type == "ws" && !strings.Contains(body, `"headers"`) {
			t.Fatalf("ws missing headers: %s", body)
		}
		if node.Type == "grpc" && !strings.Contains(body, `"service_name"`) {
			t.Fatalf("grpc missing service_name: %s", body)
		}
		if node.Protocol == "hysteria2" && strings.Contains(body, `"transport"`) {
			t.Fatalf("hysteria2 must not set transport: %s", body)
		}
	}
	clash := RenderClash([]Node{{Name: "audit-hy2", Protocol: "hysteria2", Host: "127.0.0.1", Port: 443, Password: "audit-secret", Type: "quic", Security: "tls", SNI: "audit.test"}}, nil)
	if !strings.Contains(clash, `password: "audit-secret"`) || strings.Contains(clash, "uuid:") {
		t.Fatalf("clash hy2: %s", clash)
	}
}

func TestAssemblePrefersIssuedCertDomain(t *testing.T) {
	in := models.Inbound{
		ID: "n", NodeUUID: "node-1", Name: "edge", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true, SortIndex: 1,
		SettingsJSON: `{"share_strategy":"node"}`,
	}
	creds := []models.Credential{{UUID: "u", Enabled: true}}
	granted := map[string]bool{"n": true}
	hosts := map[string]string{"node-1": "203.0.113.9"}
	issued := []models.Certificate{{
		ID: "cert-1", NodeUUID: "node-1", Domain: "vpn.example.com", Status: models.CertIssued,
	}}
	got := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{in}, creds, granted, hosts, issued)
	if len(got) != 1 || got[0].Host != "vpn.example.com" || got[0].Name != "edge" {
		t.Fatalf("issued cert domain: %+v", got)
	}
	pending := []models.Certificate{{
		ID: "cert-1", NodeUUID: "node-1", Domain: "vpn.example.com", Status: "pending",
	}}
	gotPending := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{in}, creds, granted, hosts, pending)
	if len(gotPending) != 1 || gotPending[0].Host != "203.0.113.9" {
		t.Fatalf("pending cert must keep node IP: %+v", gotPending)
	}
	bound := in
	bound.SettingsJSON = `{"share_strategy":"node","cert_id":"cert-bound"}`
	mixed := []models.Certificate{
		{ID: "cert-other", NodeUUID: "node-1", Domain: "other.example.com", Status: models.CertIssued},
		{ID: "cert-bound", NodeUUID: "node-1", Domain: "bound.example.com", Status: models.CertIssued},
	}
	gotBound := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{bound}, creds, granted, hosts, mixed)
	if len(gotBound) != 1 || gotBound[0].Host != "bound.example.com" {
		t.Fatalf("inbound cert_id domain: %+v", gotBound)
	}
	shared := in
	shared.SettingsJSON = `{"share_strategy":"node","cert_id":"cert-root"}`
	root := []models.Certificate{{
		ID: "cert-root", NodeUUID: "node-1", Domain: "abc.com", ShareDomain: "hk.abc.com",
		CoverWildcard: true, Status: models.CertIssued,
	}}
	gotShare := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{shared}, creds, granted, hosts, root)
	if len(gotShare) != 1 || gotShare[0].Host != "hk.abc.com" {
		t.Fatalf("node share domain: %+v", gotShare)
	}
	custom := in
	custom.SettingsJSON = `{"share_strategy":"node","cert_id":"cert-root","tls_domain":"us.abc.com"}`
	gotTLS := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{custom}, creds, granted, hosts, root)
	if len(gotTLS) != 1 || gotTLS[0].Host != "us.abc.com" {
		t.Fatalf("inbound tls_domain: %+v", gotTLS)
	}
}

func TestAssembleNodeAddressFollowsStack(t *testing.T) {
	creds := []models.Credential{{UUID: "u", Enabled: true}}
	addrs := map[string]nodeAddr{"node-1": {IPv4: "203.0.113.9", IPv6: "2001:db8::1"}}
	user := models.NodeUser{Username: "alice"}
	inbound := func(id, stack, proto string) models.Inbound {
		return models.Inbound{
			ID: id, NodeUUID: "node-1", Name: id, Protocol: proto,
			Listen: "0.0.0.0,::", Port: 443, Enabled: true,
			SettingsJSON: `{"share_strategy":"node","stack":"` + stack + `"}`,
		}
	}
	v6 := assembleWithAddrs(user, []models.Inbound{inbound("v6", "ipv6", "vless")}, creds, map[string]bool{"v6": true}, addrs, nil)
	if len(v6) != 1 || v6[0].Host != "2001:db8::1" {
		t.Fatalf("ipv6 stack: %+v", v6)
	}
	dual := assembleWithAddrs(user, []models.Inbound{inbound("dual", "dual", "shadowsocks")}, creds, map[string]bool{"dual": true}, addrs, nil)
	if len(dual) != 1 || dual[0].Host != "2001:db8::1" {
		t.Fatalf("dual stack: %+v", dual)
	}
	empty := assembleWithAddrs(user, []models.Inbound{inbound("empty", "", "vless")}, creds, map[string]bool{"empty": true}, addrs, nil)
	if len(empty) != 1 || empty[0].Host != "2001:db8::1" {
		t.Fatalf("empty stack is dual: %+v", empty)
	}
	v4 := assembleWithAddrs(user, []models.Inbound{inbound("v4", "ipv4", "vless")}, creds, map[string]bool{"v4": true}, addrs, nil)
	if len(v4) != 1 || v4[0].Host != "203.0.113.9" {
		t.Fatalf("ipv4 stack: %+v", v4)
	}
	fallback := assembleWithAddrs(user, []models.Inbound{inbound("fb", "ipv6", "vless")}, creds, map[string]bool{"fb": true}, map[string]nodeAddr{"node-1": {IPv4: "203.0.113.9"}}, nil)
	if len(fallback) != 1 || fallback[0].Host != "203.0.113.9" {
		t.Fatalf("ipv6 stack without ipv6 falls back: %+v", fallback)
	}
	mixed := assembleWithAddrs(user, []models.Inbound{
		inbound("a", "ipv4", "vless"),
		inbound("b", "ipv6", "shadowsocks"),
	}, creds, map[string]bool{"a": true, "b": true}, addrs, nil)
	if len(mixed) != 2 || mixed[0].Host != "203.0.113.9" || mixed[1].Host != "2001:db8::1" {
		t.Fatalf("same node both stacks: %+v", mixed)
	}
}

func TestRealityShareUsesServerNamesNotLeftoverSNI(t *testing.T) {
	in := models.Inbound{
		ID: "n", NodeUUID: "node-1", Name: "US_01", Protocol: "vless",
		Listen: "0.0.0.0", Port: 36325, Enabled: true, SortIndex: 1,
		SettingsJSON: `{
			"share_strategy":"other","public_host":"ppfla.8787837.xyz",
			"security":"reality","transport":"tcp","flow":"xtls-rprx-vision",
			"sni":"ppfla.8787837.xyz","tls_domain":"ppfla.8787837.xyz",
			"reality_dest":"addons.mozilla.org:443","reality_server_names":"addons.mozilla.org",
			"fingerprint":"edge","reality_public_key":"pk","reality_short_id":"7035f478","spider_x":"/"
		}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 {
		t.Fatalf("nodes: %+v", nodes)
	}
	if nodes[0].SNI != "addons.mozilla.org" {
		t.Fatalf("share sni %q", nodes[0].SNI)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	if !strings.Contains(link, "sni=addons.mozilla.org") {
		t.Fatalf("share link kept leftover sni: %s", link)
	}
	if strings.Contains(link, "sni=ppfla.8787837.xyz") {
		t.Fatalf("share link leaked leftover sni: %s", link)
	}
}

func TestTCPRealityShareOmitsOtherTransportDefaults(t *testing.T) {
	in := models.Inbound{
		ID: "n", NodeUUID: "node-1", Name: "US_02", Protocol: "vless",
		Listen: "0.0.0.0", Port: 32800, Enabled: true, SortIndex: 1,
		SettingsJSON: `{
			"share_strategy":"other","public_host":"ppflac.8787837.xyz",
			"security":"reality","transport":"tcp","flow":"xtls-rprx-vision",
			"fingerprint":"edge","reality_public_key":"pk","reality_short_id":"sid",
			"spider_x":"/","sni":"www.swift.org",
			"ws_path":"/","grpc_service":"gun","http_mode":"auto","http_path":"/"
		}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 {
		t.Fatalf("nodes: %+v", nodes)
	}
	if nodes[0].Path != "" || nodes[0].ServiceName != "" || nodes[0].Mode != "" {
		t.Fatalf("tcp share leaked other transports: %+v", nodes[0])
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	for _, leak := range []string{"serviceName=", "mode=", "path="} {
		if strings.Contains(link, leak) {
			t.Fatalf("tcp reality link leaked %s: %s", leak, link)
		}
	}
	if !strings.Contains(link, "type=tcp") || !strings.Contains(link, "security=reality") || !strings.Contains(link, "flow=xtls-rprx-vision") || !strings.Contains(link, "encryption=none") {
		t.Fatalf("tcp reality link missing core fields: %s", link)
	}
	sing, _, err := Render("sing-box", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sing, `"fingerprint": "edge"`) {
		t.Fatalf("sing-box reality missing utls fingerprint: %s", sing)
	}
}

func TestShareLinkKeepsDomainOutOfBrackets(t *testing.T) {
	in := models.Inbound{
		ID: "n", NodeUUID: "node-1", Name: "US_02", Protocol: "vless",
		Listen: "0.0.0.0", Port: 32800, Enabled: true, SortIndex: 1,
		SettingsJSON: `{"share_strategy":"node","security":"reality","transport":"tcp","flow":"xtls-rprx-vision"}`,
	}
	creds := []models.Credential{{UUID: "ef3f5268-d1d2-445b-8d19-a47a9bd98b53", Enabled: true}}
	granted := map[string]bool{"n": true}
	issued := []models.Certificate{{
		ID: "cert-1", NodeUUID: "node-1", Domain: "ppflac.8787837.xyz", Status: models.CertIssued,
	}}
	nodes := AssembleWithCerts(models.NodeUser{Username: "alice"}, []models.Inbound{in}, creds, granted, nil, issued)
	if len(nodes) != 1 || nodes[0].Host != "ppflac.8787837.xyz" || nodes[0].Port != 32800 {
		t.Fatalf("share host: %+v", nodes)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	links := DecodeShareLinks(raw)
	if len(links) != 1 {
		t.Fatalf("links: %v", links)
	}
	if strings.Contains(links[0], "[ppflac.8787837.xyz]") || strings.Contains(links[0], "]:32800") {
		t.Fatalf("domain must not use IPv6 brackets: %s", links[0])
	}
	if !strings.Contains(links[0], "@ppflac.8787837.xyz:32800?") {
		t.Fatalf("want domain:port without extra colon: %s", links[0])
	}

	bracketed := in
	bracketed.SettingsJSON = `{"share_strategy":"other","public_host":"[ppflac.8787837.xyz]"}`
	got := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{bracketed}, creds, granted, nil)
	if len(got) != 1 || got[0].Host != "ppflac.8787837.xyz" {
		t.Fatalf("unwrap bracketed domain: %+v", got)
	}

	v6 := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{{
		ID: "n", NodeUUID: "node-1", Name: "v6", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"2001:db8::10"}`,
	}}, creds, granted, nil)
	if len(v6) != 1 || v6[0].Host != "2001:db8::10" {
		t.Fatalf("ipv6 host: %+v", v6)
	}
	v6raw, _, err := Render("v2ray", v6, nil)
	if err != nil {
		t.Fatal(err)
	}
	v6links := DecodeShareLinks(v6raw)
	if len(v6links) != 1 || !strings.Contains(v6links[0], "@[2001:db8::10]:443?") {
		t.Fatalf("ipv6 must keep brackets: %v", v6links)
	}
}

func TestAssembleWithoutGrantSkipsOthers(t *testing.T) {
	nodes := Assemble(models.NodeUser{Username: "x"}, []models.Inbound{{
		ID: "no", Name: "hidden", Protocol: "vless", Listen: "1.1.1.1", Port: 443, Enabled: true,
	}}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"yes": true}, nil)
	if len(nodes) != 0 {
		t.Fatalf("ungranted inbound leaked: %+v", nodes)
	}
}

func TestShareKeepsVisionForSingBox(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreSingBox, Name: "sb", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"sb.example.com","security":"reality","transport":"tcp","flow":"xtls-rprx-vision"}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice", Flow: "xtls-rprx-vision"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("sing-box share must emit vision: %+v", nodes)
	}
}

func TestShareOmitsUserVisionOnAnyTLS(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreSingBox, Name: "anytls-in", Protocol: "anytls",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"any.example.com","security":"reality","transport":"tcp"}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice", Flow: "xtls-rprx-vision"}, []models.Inbound{in}, []models.Credential{{UUID: "u", SecretMaterial: "any-secret", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Flow != "" {
		t.Fatalf("anytls share must not emit vision: %+v", nodes)
	}
}

func TestShareNormalizesSingBoxUdp443Vision(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreSingBox, Name: "sb", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"sb.example.com","security":"reality","transport":"tcp"}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice", Flow: "xtls-rprx-vision-udp443"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("sing-box share must map udp443 to vision: %+v", nodes)
	}
}

func TestShareKeepsXrayUdp443(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreXray, Name: "xray", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"xray.example.com","security":"tls","transport":"tcp"}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice", Flow: "xtls-rprx-vision-udp443"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Flow != "xtls-rprx-vision-udp443" {
		t.Fatalf("xray share must keep udp443: %+v", nodes)
	}
}

func TestShareOmitsUserVisionOnWS(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreXray, Name: "ws", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{"share_strategy":"other","public_host":"ws.example.com","security":"tls","transport":"ws","ws_path":"/vless"}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice", Flow: "xtls-rprx-vision"}, []models.Inbound{in}, []models.Credential{{UUID: "u", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Flow != "" {
		t.Fatalf("ws share must not emit vision: %+v", nodes)
	}
}

func TestAnyTLSRealityShare(t *testing.T) {
	in := models.Inbound{
		ID: "n", Core: models.CoreSingBox, Name: "anytls-in", Protocol: "anytls",
		Listen: "0.0.0.0", Port: 443, Enabled: true,
		SettingsJSON: `{
			"share_strategy":"other","public_host":"any.example.com",
			"security":"reality","transport":"tcp","fingerprint":"chrome",
			"reality_public_key":"pk","reality_short_id":"abcd",
			"sni":"www.swift.org","alpn":"h2,http/1.1"
		}`,
	}
	nodes := Assemble(models.NodeUser{Username: "alice"}, []models.Inbound{in}, []models.Credential{{UUID: "u", SecretMaterial: "any-secret", Enabled: true}}, map[string]bool{"n": true}, nil)
	if len(nodes) != 1 || nodes[0].Protocol != "anytls" || nodes[0].Password != "any-secret" {
		t.Fatalf("anytls nodes: %+v", nodes)
	}
	raw, _, err := Render("v2ray", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := DecodeShareLinks(raw)[0]
	if !strings.HasPrefix(link, "anytls://") || !strings.Contains(link, "any-secret") || !strings.Contains(link, "security=reality") || !strings.Contains(link, "pbk=pk") || !strings.Contains(link, "sid=abcd") {
		t.Fatalf("anytls link: %s", link)
	}
	if strings.Contains(link, "type=") || strings.Contains(link, "encryption=") {
		t.Fatalf("anytls link leaked vless fields: %s", link)
	}
	sing, _, err := Render("sing-box", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sing, `"type": "anytls"`) || !strings.Contains(sing, `"password": "any-secret"`) || strings.Contains(sing, `"transport"`) {
		t.Fatalf("sing-box anytls: %s", sing)
	}
	if !strings.Contains(sing, `"public_key": "pk"`) {
		t.Fatalf("sing-box anytls reality: %s", sing)
	}
	clash, _, err := Render("clash", nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "type: anytls") || !strings.Contains(clash, `password: "any-secret"`) || !strings.Contains(clash, "public-key: pk") {
		t.Fatalf("clash anytls: %s", clash)
	}
}

func TestRenderClashSingBoxFromExtras(t *testing.T) {
	extra := []string{
		"vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@ext.example:443?encryption=none&security=tls&type=tcp&sni=ext.example#home",
		"anytls://any-secret@any.example:443?security=reality&pbk=pk&sid=abcd#any",
		"not-a-share-link",
	}
	clash, _, err := Render("clash", nil, extra)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "type: vless") || !strings.Contains(clash, "server: ext.example") || !strings.Contains(clash, "name: \"home\"") {
		t.Fatalf("clash extra vless: %s", clash)
	}
	if !strings.Contains(clash, "type: anytls") || !strings.Contains(clash, `password: "any-secret"`) || !strings.Contains(clash, "public-key: pk") {
		t.Fatalf("clash extra anytls: %s", clash)
	}
	if strings.Contains(clash, "# vless://") || strings.Contains(clash, "# anytls://") {
		t.Fatalf("parsed extras still comments: %s", clash)
	}
	if !strings.Contains(clash, "# not-a-share-link") {
		t.Fatalf("unknown extra missing: %s", clash)
	}
	sing, _, err := Render("sing-box", nil, extra)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sing, `"outbounds": null`) || strings.Contains(sing, `"outbounds":null`) {
		t.Fatalf("sing-box dropped extras: %s", sing)
	}
	if !strings.Contains(sing, `"type": "vless"`) || !strings.Contains(sing, `"server": "ext.example"`) {
		t.Fatalf("sing-box extra vless: %s", sing)
	}
	if !strings.Contains(sing, `"type": "anytls"`) || !strings.Contains(sing, `"password": "any-secret"`) || !strings.Contains(sing, `"public_key": "pk"`) {
		t.Fatalf("sing-box extra anytls: %s", sing)
	}
}

func TestNodeFromShareLinkKeepsLiteralPercentPassword(t *testing.T) {
	trojan := "trojan://pa%2541ss@external.example:443#trojan_literal_percent"
	n, ok := NodeFromShareLink(trojan)
	if !ok || n.Password != "pa%41ss" {
		t.Fatalf("trojan password=%q ok=%v", n.Password, ok)
	}
	anytls := "anytls://part%252Fname@external.example:443#anytls_literal_percent"
	n, ok = NodeFromShareLink(anytls)
	if !ok || n.Password != "part%2Fname" {
		t.Fatalf("anytls password=%q ok=%v", n.Password, ok)
	}
	tuic := "tuic://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:part%252Fname@external.example:443?security=tls#tuic_literal_percent"
	n, ok = NodeFromShareLink(tuic)
	if !ok || n.UUID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" || n.Password != "part%2Fname" {
		t.Fatalf("tuic uuid=%q password=%q ok=%v", n.UUID, n.Password, ok)
	}
}

func TestClashQuotesPasswordValues(t *testing.T) {
	for _, pass := range []string{"alpha: beta", "#secret", `say "hi"`} {
		clash := RenderClash([]Node{{
			Name: "n", Protocol: "trojan", Host: "h.example", Port: 443, Password: pass,
		}}, nil)
		if clashPassword(clash) != pass {
			t.Fatalf("password %q clash=%s", pass, clash)
		}
	}
}

func TestHysteria2AndTUICShareLinksRoundTrip(t *testing.T) {
	hy2 := Node{
		Name: "node-hy2", Protocol: "hysteria2", Host: "hy2.example.com", Port: 443,
		Password: "hy2-secret", Type: "quic", Security: "tls", SNI: "hy2.example.com",
	}
	tuic := Node{
		Name: "node-tuic", Protocol: "tuic", Host: "tuic.example.com", Port: 443,
		UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Password: "tuic-secret",
		Type: "quic", Security: "tls", SNI: "tuic.example.com",
	}
	raw, err := base64.StdEncoding.DecodeString(RenderV2RayBase64([]Node{hy2, tuic}, nil))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, "type=quic") {
		t.Fatalf("hy2/tuic share must omit type=quic: %s", body)
	}
	var hy2Link, tuicLink string
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, "hysteria2://"):
			hy2Link = line
		case strings.HasPrefix(line, "tuic://"):
			tuicLink = line
		}
	}
	if hy2Link == "" || !strings.Contains(hy2Link, "hy2-secret@") {
		t.Fatalf("hy2 link: %s", body)
	}
	gotHy2, ok := NodeFromShareLink(hy2Link)
	if !ok || gotHy2.Protocol != "hysteria2" || gotHy2.Password != "hy2-secret" || gotHy2.Host != "hy2.example.com" {
		t.Fatalf("parse hy2 %+v ok=%v from %s", gotHy2, ok, hy2Link)
	}
	if tuicLink == "" || !strings.Contains(tuicLink, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:tuic-secret@") {
		t.Fatalf("tuic link: %s", body)
	}
	gotTuic, ok := NodeFromShareLink(tuicLink)
	if !ok || gotTuic.Protocol != "tuic" || gotTuic.UUID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" || gotTuic.Password != "tuic-secret" {
		t.Fatalf("parse tuic %+v ok=%v from %s", gotTuic, ok, tuicLink)
	}
}

func TestClashTuicIncludesPassword(t *testing.T) {
	n, ok := NodeFromShareLink("tuic://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:simple-secret@external.example:443?security=tls#tuic_control")
	if !ok {
		t.Fatal("parse tuic")
	}
	clash := RenderClash([]Node{n}, nil)
	if !strings.Contains(clash, "type: tuic") {
		t.Fatalf("type: %s", clash)
	}
	if clashPassword(clash) != "simple-secret" {
		t.Fatalf("tuic password clash=%s", clash)
	}
}

func clashPassword(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "password:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "password:"))
		if strings.HasPrefix(rest, `"`) {
			if unquoted, err := strconv.Unquote(rest); err == nil {
				return unquoted
			}
		}
		if i := strings.Index(rest, " #"); i >= 0 {
			rest = rest[:i]
		}
		return rest
	}
	return ""
}
