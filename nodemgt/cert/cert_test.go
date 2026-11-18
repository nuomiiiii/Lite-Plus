package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestACMEAccountRequiresEmail(t *testing.T) {
	if _, err := acmeAccount(""); err == nil {
		t.Fatal("empty email should fail")
	}
	if _, err := acmeAccount("  mailto:  "); err == nil {
		t.Fatal("blank mailto should fail")
	}
	want := []string{"mailto:ops@example.com"}
	got, err := acmeAccount("ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Contact, want) {
		t.Fatalf("Contact = %v; want %v", got.Contact, want)
	}
	got, err = acmeAccount(" mailto:ops@example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Contact, want) {
		t.Fatalf("prefixed Contact = %v; want %v", got.Contact, want)
	}
}

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("www.api.example.com")
	want := []string{"www.api.example.com", "api.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if zoneCandidates("localhost") != nil {
		t.Fatal("single label should be empty")
	}
}

func TestTxtRecordNameIsRelativeToZone(t *testing.T) {
	got := txtRecordName("test.8787837.xyz", "8787837.xyz")
	if got != "_acme-challenge.test" {
		t.Fatalf("got %s", got)
	}
	if txtRecordName("8787837.xyz", "8787837.xyz") != "_acme-challenge" {
		t.Fatal("apex")
	}
	if txtRecordName("*.8787837.xyz", "8787837.xyz") != "_acme-challenge" {
		t.Fatal("wildcard")
	}
}

func TestIssueNamesCoversApexAndWildcard(t *testing.T) {
	got := IssueNames("abc.com", true)
	want := []string{"abc.com", "*.abc.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if !reflect.DeepEqual(IssueNames("hk.abc.com", false), []string{"hk.abc.com"}) {
		t.Fatal("subdomain")
	}
	if !reflect.DeepEqual(IssueNames("*.abc.com", false), []string{"abc.com", "*.abc.com"}) {
		t.Fatal("wildcard input")
	}
	if !DefaultCoverWildcard("abc.com") || DefaultCoverWildcard("hk.abc.com") {
		t.Fatal("default cover")
	}
	if UsableShareHost("abc.com", "hk.abc.com") != "hk.abc.com" {
		t.Fatal("share domain")
	}
	if UsableShareHost("*.abc.com", "") != "abc.com" {
		t.Fatal("wildcard share fallback")
	}
	if !HostCovered("abc.com", "hk.abc.com") || !HostCovered("abc.com", "abc.com") {
		t.Fatal("covered")
	}
	if HostCovered("abc.com", "a.hk.abc.com") || HostCovered("abc.com", "other.com") {
		t.Fatal("not covered")
	}
}

func TestIssueRootRequiresCloudflare(t *testing.T) {
	_, _, err := IssueRoot(context.Background(), RootIssue{Domain: "abc.com", Email: "ops@example.com"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "cloudflare") {
		t.Fatalf("err %v", err)
	}
}

func TestIssueRootLocalCoversWildcard(t *testing.T) {
	keyPEM, issued, err := IssueRoot(context.Background(), RootIssue{Domain: "abc.com", TestCA: true})
	if err != nil {
		t.Fatal(err)
	}
	if issued.ChainPEM == "" || keyPEM == "" {
		t.Fatal("missing material")
	}
	block, _ := pem.Decode([]byte(issued.ChainPEM))
	if block == nil {
		t.Fatal("leaf pem")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("abc.com"); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("hk.abc.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(issued.ChainPEM), []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
}

func TestCSRNamesMatchAllowsApexAndWildcard(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "abc.com"}, DNSNames: []string{"abc.com", "*.abc.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err := CSRNamesMatch(csrPEM, []string{"abc.com", "*.abc.com"}); err != nil {
		t.Fatal(err)
	}
	if err := CSRNamesMatch(csrPEM, []string{"abc.com"}); err == nil {
		t.Fatal("missing wildcard must fail")
	}
}

func TestWaitTXTSeesValue(t *testing.T) {
	prevLookup, prevSettle, prevPoll := lookupTXT, txtSettle, txtPoll
	t.Cleanup(func() {
		lookupTXT, txtSettle, txtPoll = prevLookup, prevSettle, prevPoll
	})
	txtSettle = 0
	txtPoll = 0
	lookupTXT = func(context.Context, string) ([]string, error) {
		return []string{"token-value"}, nil
	}
	if err := waitTXT(context.Background(), "_acme-challenge.test.example.com", "token-value"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveZoneLooksUpApex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		if name != "example.com" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result":  []map[string]string{{"id": "zone-1", "name": "example.com"}},
		})
	}))
	t.Cleanup(srv.Close)
	prev := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = prev })
	id, name, err := resolveZone(context.Background(), "tok", "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != "zone-1" || name != "example.com" {
		t.Fatalf("zone %s %s", id, name)
	}
}

func TestCreateDNS01RecordsKeepsSiblingTXT(t *testing.T) {
	var posts []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		posts = append(posts, body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result":  map[string]string{"id": "rec-" + string(rune('1'+len(posts)-1))},
		})
	}))
	t.Cleanup(srv.Close)
	prev := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = prev })
	pending := []pendingChal{
		{name: "_acme-challenge", val: "token-apex"},
		{name: "_acme-challenge", val: "token-wildcard"},
	}
	if err := createDNS01Records(context.Background(), Cloudflare{APIToken: "tok", ZoneID: "zone-1"}, pending); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 {
		t.Fatalf("posts %d", len(posts))
	}
	if posts[0]["content"] == posts[1]["content"] {
		t.Fatal("wildcard and apex must keep distinct TXT values")
	}
	if posts[0]["name"] != "_acme-challenge" || posts[1]["name"] != "_acme-challenge" {
		t.Fatal("both records belong on the apex challenge name")
	}
	if pending[0].recID == "" || pending[1].recID == "" || pending[0].recID == pending[1].recID {
		t.Fatalf("ids %s %s", pending[0].recID, pending[1].recID)
	}
}

func TestIssueLocalTestCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "nodemgt.test"}, DNSNames: []string{"nodemgt.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	got, err := IssueLocalTestCA("nodemgt.test", csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint == "" || got.ChainPEM == "" {
		t.Fatal("missing cert")
	}
	if got.Issuer != "lite-nodemgt-test-ca" {
		t.Fatalf("issuer %s", got.Issuer)
	}
}

func TestValidateDomainRejectsTraversalAndUnsafeNames(t *testing.T) {
	valid := []string{
		"abc.com",
		"*.abc.com",
		"sub-1.hk.abc.com.",
		"_acme-challenge.abc.com",
	}
	for _, d := range valid {
		if err := ValidateDomain(d); err != nil {
			t.Fatalf("expected %q to be valid, got %v", d, err)
		}
	}

	invalid := []string{
		"",
		"../../evil",
		"../../evil.com",
		"abc.com/../../evil",
		`abc.com\..\..\evil`,
		"a..b.com",
		"-abc.com",
		"abc-.com",
		"localhost",
		"foo*bar.com",
		"*.*.abc.com",
		"abc .com",
		"abc\x00.com",
		strings.Repeat("a", 64) + ".com",
		"127.0.0.1",
		"1.2.3.4",
		"[::1]",
		"_acme-challenge.com",
		"abc.123",
		"abc.c",
	}
	for _, d := range invalid {
		if err := ValidateDomain(d); err == nil {
			t.Fatalf("expected %q to be rejected", d)
		}
		if names := IssueNames(d, true); names != nil {
			t.Fatalf("expected IssueNames(%q) to return nil, got %v", d, names)
		}
		if key := FileKey(d); key != "cert" {
			t.Fatalf("expected FileKey(%q) to sanitize to cert, got %q", d, key)
		}
	}
}
