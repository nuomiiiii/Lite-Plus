package sub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"golang.org/x/sync/singleflight"
)

const (
	extraFetchTimeout     = 6 * time.Second
	extraFetchMaxBody     = 2 << 20
	extraFetchCache       = 5 * time.Minute
	extraFetchNegCacheTTL = 30 * time.Second
	extraCacheMaxEntries  = 512
)

var (
	errBlockedFetchAddress = errors.New("private or reserved fetch address is blocked")
	allowLoopbackForTest   bool
	extraFlight            singleflight.Group
)

var blockedFetchPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type FetchStatus struct {
	ID  string
	At  time.Time
	Err string
}

type extraCacheEntry struct {
	until    time.Time
	negUntil time.Time
	lastErr  string
	links    []string
}

var extraCache = struct {
	mu    sync.Mutex
	items map[string]extraCacheEntry
}{items: map[string]extraCacheEntry{}}

func isBlockedFetchAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	unmapped := addr.Unmap()
	if allowLoopbackForTest && unmapped.IsLoopback() {
		return false
	}
	if unmapped.IsLoopback() || unmapped.IsPrivate() || unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() || unmapped.IsMulticast() || unmapped.IsUnspecified() {
		return true
	}
	for _, p := range blockedFetchPrefixes {
		if p.Contains(unmapped) {
			return true
		}
	}
	return false
}

func safeExtraDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	cleanHost := strings.Trim(host, "[]")
	if cleanHost == "" {
		return nil, errBlockedFetchAddress
	}
	var addrs []netip.Addr
	if parsed, err := netip.ParseAddr(cleanHost); err == nil {
		if isBlockedFetchAddr(parsed) {
			return nil, errBlockedFetchAddress
		}
		addrs = []netip.Addr{parsed.Unmap()}
	} else {
		if !allowLoopbackForTest && (strings.EqualFold(cleanHost, "localhost") || strings.HasSuffix(strings.ToLower(cleanHost), ".localhost")) {
			return nil, errBlockedFetchAddress
		}
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", cleanHost)
		if err != nil || len(resolved) == 0 {
			if err != nil {
				return nil, err
			}
			return nil, errBlockedFetchAddress
		}
		for _, candidate := range resolved {
			if isBlockedFetchAddr(candidate) {
				return nil, errBlockedFetchAddress
			}
			addrs = append(addrs, candidate.Unmap())
		}
	}
	dialer := &net.Dialer{Timeout: extraFetchTimeout}
	var lastErr error
	for _, ip := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errBlockedFetchAddress
}

var extraHTTPClient = &http.Client{
	Timeout: extraFetchTimeout,
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           safeExtraDialContext,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: extraFetchTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          16,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if err := guardFetchURL(req.URL); err != nil {
			return err
		}
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

func ExpandExtras(links []models.UserExtraLink, extraURLs string, at time.Time) ([]string, []FetchStatus) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var out []string
	var status []FetchStatus
	for _, row := range links {
		if !row.Enabled {
			continue
		}
		if row.ExpiresAt != nil && !row.ExpiresAt.After(at) {
			continue
		}
		value := strings.TrimSpace(row.Value)
		if value == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(row.Kind))
		if kind == models.ExtraLinkKindSubscription || looksLikeHTTP(value) && kind != models.ExtraLinkKindLink {
			fetched, fetchErr := fetchRemoteShareLinks(value)
			status = append(status, FetchStatus{ID: row.ID, At: at, Err: fetchErr})
			for _, link := range fetched {
				out = append(out, applyNamePrefix(applyRemarkToLink(link, ""), row.NamePrefix))
			}
			continue
		}
		out = append(out, applyRemarkToLink(value, row.Remark))
	}
	for _, line := range ParseExtraURLs(extraURLs) {
		if looksLikeHTTP(line) {
			fetched, _ := fetchRemoteShareLinks(line)
			out = append(out, fetched...)
			continue
		}
		out = append(out, line)
	}
	return out, status
}

func looksLikeHTTP(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func guardFetchURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("empty url")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if !allowLoopbackForTest && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return errBlockedFetchAddress
	}
	if parsed, err := netip.ParseAddr(host); err == nil && isBlockedFetchAddr(parsed) {
		return errBlockedFetchAddress
	}
	return nil
}

type flightResult struct {
	links []string
	err   string
}

func evictExtraCacheLocked(now time.Time) {
	for k, v := range extraCache.items {
		if !now.Before(v.until) && !now.Before(v.negUntil) {
			delete(extraCache.items, k)
		}
	}
	for len(extraCache.items) >= extraCacheMaxEntries {
		var oldestKey string
		var oldestUntil time.Time
		for k, v := range extraCache.items {
			exp := v.until
			if v.negUntil.After(exp) {
				exp = v.negUntil
			}
			if oldestKey == "" || exp.Before(oldestUntil) {
				oldestKey = k
				oldestUntil = exp
			}
		}
		if oldestKey == "" {
			break
		}
		delete(extraCache.items, oldestKey)
	}
}

func fetchRemoteShareLinks(raw string) ([]string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err.Error()
	}
	if err := guardFetchURL(u); err != nil {
		return nil, err.Error()
	}
	key := u.String()
	now := time.Now()
	extraCache.mu.Lock()
	if hit, ok := extraCache.items[key]; ok {
		if now.Before(hit.until) {
			links := append([]string(nil), hit.links...)
			extraCache.mu.Unlock()
			return links, ""
		}
		if now.Before(hit.negUntil) {
			links := append([]string(nil), hit.links...)
			errMsg := hit.lastErr
			extraCache.mu.Unlock()
			return links, errMsg
		}
	}
	extraCache.mu.Unlock()

	val, _, _ := extraFlight.Do(key, func() (any, error) {
		links, errMsg := doFetchRemoteShareLinks(key)
		return flightResult{links: links, err: errMsg}, nil
	})
	res, _ := val.(flightResult)
	return append([]string(nil), res.links...), res.err
}

func doFetchRemoteShareLinks(key string) ([]string, string) {
	now := time.Now()
	extraCache.mu.Lock()
	if hit, ok := extraCache.items[key]; ok {
		if now.Before(hit.until) {
			links := append([]string(nil), hit.links...)
			extraCache.mu.Unlock()
			return links, ""
		}
		if now.Before(hit.negUntil) {
			links := append([]string(nil), hit.links...)
			errMsg := hit.lastErr
			extraCache.mu.Unlock()
			return links, errMsg
		}
	}
	extraCache.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, key, nil)
	if err != nil {
		return nil, err.Error()
	}
	req.Header.Set("User-Agent", "Lite-Plus")
	resp, err := extraHTTPClient.Do(req)
	if err != nil {
		return cachedOrError(key, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cachedOrError(key, fmt.Sprintf("status %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, extraFetchMaxBody+1))
	if err != nil {
		return cachedOrError(key, err.Error())
	}
	if len(body) > extraFetchMaxBody {
		return cachedOrError(key, "response too large")
	}
	links := DecodeShareLinks(string(body))
	if len(links) == 0 {
		text := strings.TrimSpace(string(body))
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			links = DecodeShareLinks(string(decoded))
		}
	}
	extraCache.mu.Lock()
	evictExtraCacheLocked(time.Now())
	extraCache.items[key] = extraCacheEntry{
		until: time.Now().Add(extraFetchCache),
		links: append([]string(nil), links...),
	}
	extraCache.mu.Unlock()
	return links, ""
}

func cachedOrError(key, errMsg string) ([]string, string) {
	now := time.Now()
	extraCache.mu.Lock()
	defer extraCache.mu.Unlock()
	evictExtraCacheLocked(now)
	var staleLinks []string
	if hit, ok := extraCache.items[key]; ok && len(hit.links) > 0 {
		staleLinks = append([]string(nil), hit.links...)
	}
	extraCache.items[key] = extraCacheEntry{
		negUntil: now.Add(extraFetchNegCacheTTL),
		lastErr:  errMsg,
		links:    staleLinks,
	}
	return append([]string(nil), staleLinks...), errMsg
}

func applyRemarkToLink(link, remark string) string {
	link = strings.TrimSpace(link)
	remark = strings.TrimSpace(remark)
	if link == "" || remark == "" {
		return link
	}
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return applyVmessName(link, func(name string) string { return remark })
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	u.Fragment = remark
	return u.String()
}

func applyNamePrefix(link, prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return link
	}
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return applyVmessName(link, func(name string) string { return prefix + name })
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	u.Fragment = prefix + u.Fragment
	return u.String()
}

func applyVmessName(link string, next func(string) string) string {
	raw := strings.TrimSpace(strings.TrimPrefix(link, "vmess://"))
	if raw == "" {
		return link
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(raw); err != nil {
				return link
			}
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return link
	}
	name, _ := obj["ps"].(string)
	obj["ps"] = next(name)
	out, err := json.Marshal(obj)
	if err != nil {
		return link
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(out)
}
