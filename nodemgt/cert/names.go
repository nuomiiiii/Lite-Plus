package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// ValidateDomain strictly validates a DNS domain or leftmost wildcard (*.example.com).
func ValidateDomain(domain string) error {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c == '/' || c == '\\' || c == 0 || c == 0x7f || (c < 0x20 && c != ' ' && c != '\t' && c != '\n' && c != '\r') {
			return fmt.Errorf("invalid domain")
		}
	}
	d := NormalizeDomain(domain)
	if d == "" || len(d) > 253 {
		return fmt.Errorf("invalid domain")
	}
	if strings.Contains(d, "..") || strings.ContainsAny(d, "/\\ \t\r\n") {
		return fmt.Errorf("invalid domain")
	}
	if net.ParseIP(d) != nil || net.ParseIP(strings.Trim(d, "[]")) != nil {
		return fmt.Errorf("invalid domain")
	}
	allowUnderscoreFirst := false
	host := d
	if strings.HasPrefix(host, "*.") {
		host = strings.TrimPrefix(host, "*.")
	} else if strings.HasPrefix(host, "_acme-challenge.") {
		allowUnderscoreFirst = true
	}
	if host == "" || strings.Contains(host, "*") || net.ParseIP(host) != nil {
		return fmt.Errorf("invalid domain")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("invalid domain")
	}
	if labels[0] == "_acme-challenge" && len(labels) < 3 {
		return fmt.Errorf("invalid domain")
	}
	for idx, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return fmt.Errorf("invalid domain")
		}
		if idx == 0 && allowUnderscoreFirst && label == "_acme-challenge" {
			continue
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid domain")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return fmt.Errorf("invalid domain")
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return fmt.Errorf("invalid domain")
	}
	hasAlpha := false
	for i := 0; i < len(tld); i++ {
		if tld[i] >= 'a' && tld[i] <= 'z' {
			hasAlpha = true
			break
		}
	}
	if !hasAlpha {
		return fmt.Errorf("invalid domain")
	}
	return nil
}

func FileKey(domain string) string {
	if ValidateDomain(domain) != nil {
		return "cert"
	}
	d := strings.TrimPrefix(NormalizeDomain(domain), "*.")
	var b strings.Builder
	b.Grow(len(d))
	for i := 0; i < len(d); i++ {
		ch := d[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			b.WriteByte(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" || strings.Contains(out, "..") {
		return "cert"
	}
	return out
}

func ApexOf(domain string) string {
	return strings.TrimPrefix(NormalizeDomain(domain), "*.")
}

func DefaultCoverWildcard(domain string) bool {
	if ValidateDomain(domain) != nil {
		return false
	}
	d := NormalizeDomain(domain)
	if d == "" {
		return false
	}
	if strings.HasPrefix(d, "*.") {
		return true
	}
	return strings.Count(d, ".") == 1
}

func IssueNames(domain string, coverWildcard bool) []string {
	if ValidateDomain(domain) != nil {
		return nil
	}
	d := NormalizeDomain(domain)
	if d == "" {
		return nil
	}
	if strings.HasPrefix(d, "*.") {
		apex := strings.TrimPrefix(d, "*.")
		if apex == "" {
			return nil
		}
		return uniqueNames(apex, "*."+apex)
	}
	if coverWildcard {
		return uniqueNames(d, "*."+d)
	}
	return []string{d}
}

func CommonName(names []string) string {
	for _, n := range uniqueNames(names...) {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	if len(names) == 0 {
		return ""
	}
	return ApexOf(names[0])
}

func ChallengeHost(domain string) string {
	return "_acme-challenge." + ApexOf(domain)
}

func RootDomain(domain string) string {
	return ApexOf(domain)
}

func HostCovered(root, host string) bool {
	root = RootDomain(root)
	host = NormalizeDomain(host)
	if root == "" || host == "" {
		return false
	}
	if host == root {
		return true
	}
	suffix := "." + root
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	rest := strings.TrimSuffix(host, suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

func UsableShareHost(domain, shareDomain string) string {
	if s := NormalizeDomain(shareDomain); s != "" && !strings.HasPrefix(s, "*.") {
		return s
	}
	d := NormalizeDomain(domain)
	if strings.HasPrefix(d, "*.") {
		return strings.TrimPrefix(d, "*.")
	}
	return d
}

func uniqueNames(names ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = NormalizeDomain(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func nameSetEqual(got, want []string) bool {
	left := uniqueNames(got...)
	right := uniqueNames(want...)
	if len(left) != len(right) {
		return false
	}
	seen := map[string]struct{}{}
	for _, n := range left {
		seen[n] = struct{}{}
	}
	for _, n := range right {
		if _, ok := seen[n]; !ok {
			return false
		}
	}
	return true
}

func cnAllowed(cn string, want []string) bool {
	cn = NormalizeDomain(cn)
	if cn == "" {
		return true
	}
	for _, n := range uniqueNames(want...) {
		if n == cn {
			return true
		}
		if strings.HasPrefix(n, "*.") && ApexOf(n) == cn {
			return true
		}
	}
	return false
}

func CSRNamesMatch(csrPEM string, names []string) error {
	want := uniqueNames(names...)
	if len(want) == 0 {
		return fmt.Errorf("domain required")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	if !cnAllowed(csr.Subject.CommonName, want) {
		return fmt.Errorf("csr cn")
	}
	got := csr.DNSNames
	if len(got) == 0 && strings.TrimSpace(csr.Subject.CommonName) != "" {
		got = []string{csr.Subject.CommonName}
	}
	if !nameSetEqual(got, want) {
		return fmt.Errorf("csr san")
	}
	return nil
}
