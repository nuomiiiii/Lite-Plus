package v2

import (
	"testing"
	"time"
)

func TestNormalizeProtectionIP(t *testing.T) {
	got, ok := NormalizeProtectionIP(" 203.0.113.8 ")
	if !ok || got != "203.0.113.8" {
		t.Fatalf("%q %v", got, ok)
	}
	if _, ok := NormalizeProtectionIP("nope"); ok {
		t.Fatal("invalid")
	}
	if ProtectionIPFamily("2001:db8::1") != "v6" {
		t.Fatal("v6")
	}
	if !ValidProtectionLogFormat(ProtectionLogSSHD) || ValidProtectionLogFormat("regex") {
		t.Fatal("log format")
	}
	if !IsProtectionJournalPath("journal:sshd") || IsProtectionJournalPath("/var/log/auth.log") {
		t.Fatal("journal path")
	}
}

func TestProtectionBanExpiryPermanent(t *testing.T) {
	if NormalizeProtectionBanSec(0) != ProtectionDefaultBanSec || NormalizeProtectionBanSec(-8) != ProtectionBanPermanentSec || NormalizeProtectionBanSec(120) != 120 {
		t.Fatal("normalize")
	}
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	if !ProtectionBanNever(ProtectionBanExpiry(now, ProtectionBanPermanentSec)) {
		t.Fatal("never")
	}
	got := ProtectionBanExpiry(now, 600)
	if !got.Equal(now.Add(600 * time.Second)) {
		t.Fatalf("%s", got)
	}
}

func TestCheckProtectionSSHSources(t *testing.T) {
	sshd := ProtectionLogSource{ID: "s1", Format: ProtectionLogSSHD, Path: ProtectionJournalSSHD, BindPort: "12560"}
	ok := ProtectionConfig{
		Sources:  []ProtectionLogSource{sshd},
		Policies: []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "12560", SourceID: "s1", RequestWindowSec: 60, RequestThreshold: 3}},
	}
	if err := CheckProtectionSSHSources(ok); err != nil {
		t.Fatal(err)
	}
	dup := ok
	dup.Sources = []ProtectionLogSource{sshd, {ID: "s2", Format: ProtectionLogSSHD, Path: "/var/log/auth.log", BindPort: "12560"}}
	if err := CheckProtectionSSHSources(dup); err == nil {
		t.Fatal("duplicate sshd")
	}
	mismatch := ok
	mismatch.Policies[0].Port = "22"
	if err := CheckProtectionSSHSources(mismatch); err == nil {
		t.Fatal("linked port mismatch")
	}
	auto := ProtectionConfig{
		Sources:  []ProtectionLogSource{sshd},
		Policies: []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "22", RequestWindowSec: 60, RequestThreshold: 3}},
	}
	if err := CheckProtectionSSHSources(auto); err == nil {
		t.Fatal("auto ssh-only port mismatch")
	}
	nginx := ProtectionLogSource{ID: "n1", Format: ProtectionLogNginxCombined, Path: "/var/log/nginx/access.log", BindProtocol: "tcp", BindPort: "443"}
	mixedHTTP := ProtectionConfig{
		Sources:  []ProtectionLogSource{sshd, nginx},
		Policies: []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "443", RequestWindowSec: 60, RequestThreshold: 20}},
	}
	if err := CheckProtectionSSHSources(mixedHTTP); err != nil {
		t.Fatal(err)
	}
	mixedDead := mixedHTTP
	mixedDead.Policies = []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "22", RequestWindowSec: 60, RequestThreshold: 3}}
	if err := CheckProtectionSSHSources(mixedDead); err == nil {
		t.Fatal("auto mixed ssh mismatch")
	}
	caddy := ProtectionLogSource{ID: "c1", Format: ProtectionLogCaddyJSON, Path: "/var/log/caddy/access.log", BindProtocol: "tcp", BindPort: "443"}
	mixedJSON := ProtectionConfig{
		Sources:  []ProtectionLogSource{sshd, caddy},
		Policies: []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "443", RequestWindowSec: 60, RequestThreshold: 20}},
	}
	if err := CheckProtectionSSHSources(mixedJSON); err != nil {
		t.Fatal(err)
	}
	emptyCaddy := ProtectionLogSource{ID: "c1", Format: ProtectionLogCaddyJSON, Path: "/var/log/caddy/access.log"}
	mixedEmpty := ProtectionConfig{
		Sources:  []ProtectionLogSource{sshd, emptyCaddy},
		Policies: []ProtectionPolicy{{ID: "p1", Protocol: "tcp", Port: "22", RequestWindowSec: 60, RequestThreshold: 3}},
	}
	if err := CheckProtectionSSHSources(mixedEmpty); err == nil {
		t.Fatal("empty HTTP bind must not cover SSH mismatch")
	}
}
