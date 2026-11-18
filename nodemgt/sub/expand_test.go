package sub

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

func TestExpandExtrasShareLinkAndRemoteSub(t *testing.T) {
	resetExtraCache()
	prev := allowLoopbackForTest
	allowLoopbackForTest = true
	t.Cleanup(func() { allowLoopbackForTest = prev })
	payload := base64.StdEncoding.EncodeToString([]byte("vless://remote@host:443#node"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()
	expired := time.Now().UTC().Add(-time.Hour)
	links, status := ExpandExtras([]models.UserExtraLink{
		{ID: "l1", Kind: models.ExtraLinkKindLink, Value: "vless://alice@a.example:443", Remark: "home", Enabled: true},
		{ID: "l2", Kind: models.ExtraLinkKindLink, Value: "vless://off@a.example:443", Enabled: false},
		{ID: "l3", Kind: models.ExtraLinkKindLink, Value: "vless://old@a.example:443", Enabled: true, ExpiresAt: &expired},
		{ID: "s1", Kind: models.ExtraLinkKindSubscription, Value: srv.URL, NamePrefix: "ext-", Enabled: true},
	}, "trojan://plain@b.example:443", time.Now().UTC())
	if len(status) != 1 || status[0].ID != "s1" || status[0].Err != "" {
		t.Fatalf("fetch status: %+v", status)
	}
	joined := strings.Join(links, "\n")
	if !strings.Contains(joined, "home") {
		t.Fatalf("remark missing: %s", joined)
	}
	if !strings.Contains(joined, "ext-node") && !strings.Contains(joined, "ext-") {
		t.Fatalf("prefix missing: %s", joined)
	}
	if strings.Contains(joined, "off@") || strings.Contains(joined, "old@") {
		t.Fatalf("disabled/expired leaked: %s", joined)
	}
	if !strings.Contains(joined, "trojan://plain@b.example:443") {
		t.Fatalf("extra_urls missing: %s", joined)
	}
}

func TestExpandExtraURLsFetchesHTTP(t *testing.T) {
	resetExtraCache()
	prev := allowLoopbackForTest
	allowLoopbackForTest = true
	t.Cleanup(func() { allowLoopbackForTest = prev })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ss://abc@host:8388#remote"))
	}))
	defer srv.Close()
	links, _ := ExpandExtras(nil, srv.URL+"\n# comment\nvless://local@host:443", time.Now().UTC())
	joined := strings.Join(links, "\n")
	if !strings.Contains(joined, "ss://abc@host:8388") {
		t.Fatalf("fetched extra url missing: %s", joined)
	}
	if !strings.Contains(joined, "vless://local@host:443") {
		t.Fatalf("share extra url missing: %s", joined)
	}
}

func resetExtraCache() {
	extraCache.mu.Lock()
	extraCache.items = map[string]extraCacheEntry{}
	extraCache.mu.Unlock()
}

func TestExpandBlocksPrivateAndLoopbackSSRF(t *testing.T) {
	resetExtraCache()
	prev := allowLoopbackForTest
	allowLoopbackForTest = false
	t.Cleanup(func() { allowLoopbackForTest = prev })

	for _, blocked := range []string{
		"http://127.0.0.1:8080/sub",
		"http://localhost:8080/sub",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/sub",
		"http://100.64.0.1/sub",
		"http://[::ffff:127.0.0.1]/sub",
		"http://[64:ff9b::7f00:1]/sub",
		"http://[64:ff9b:1::7f00:1]/sub",
		"http://[2001::1]/sub",
		"http://[2002:7f00:1::1]/sub",
		"http://[fe80::1]/sub",
		"http://[fd00::1]/sub",
	} {
		links, status := ExpandExtras([]models.UserExtraLink{
			{ID: "ssrf", Kind: models.ExtraLinkKindSubscription, Value: blocked, Enabled: true},
		}, "", time.Now().UTC())
		if len(links) != 0 {
			t.Fatalf("%s unexpectedly returned links: %v", blocked, links)
		}
		if len(status) != 1 || status[0].Err == "" {
			t.Fatalf("%s expected SSRF block error, got %+v", blocked, status)
		}
	}
}

func TestExpandNegativeCachesFailedFetches(t *testing.T) {
	resetExtraCache()
	prev := allowLoopbackForTest
	allowLoopbackForTest = true
	t.Cleanup(func() { allowLoopbackForTest = prev })

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, st1 := ExpandExtras([]models.UserExtraLink{{ID: "s1", Kind: models.ExtraLinkKindSubscription, Value: srv.URL, Enabled: true}}, "", time.Now().UTC())
	_, st2 := ExpandExtras([]models.UserExtraLink{{ID: "s1", Kind: models.ExtraLinkKindSubscription, Value: srv.URL, Enabled: true}}, "", time.Now().UTC())
	if hits != 1 {
		t.Fatalf("negative cache should prevent immediate retry, hits=%d", hits)
	}
	if len(st1) != 1 || st1[0].Err == "" || len(st2) != 1 || st2[0].Err == "" {
		t.Fatalf("expected cached error status: st1=%+v st2=%+v", st1, st2)
	}
}
