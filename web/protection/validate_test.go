package protection

import (
	"testing"

	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func TestNormalizeConfigRejectsRelativeLogPath(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: "access.log",
		}},
	})
	if err == nil {
		t.Fatal("relative path")
	}
}

func TestNormalizeConfigAcceptsLinuxAbsPath(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: "/var/log/nginx/access.log",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeConfigRejectsWindowsLogPath(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: `C:\logs\access.log`,
		}},
	})
	if err == nil {
		t.Fatal("windows path")
	}
}

func TestNormalizeConfigRejectsCombinedWithoutBind(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogNginxCombined, Path: "/var/log/nginx/access.log",
		}},
	})
	if err == nil {
		t.Fatal("combined bind")
	}
}

func TestNormalizeConfigRejectsInvalidBindAddr(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", BindAddr: "not-an-ip",
		}},
	})
	if err == nil {
		t.Fatal("bind addr")
	}
}

func TestNormalizeConfigDefaultsObserveAndBanDuration(t *testing.T) {
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Whitelist: []string{"203.0.113.1", "203.0.113.1"},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Protocol: "TCP", Port: "443",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Whitelist) != 1 || cfg.Policies[0].Mode != v2.ProtectionModeObserve || cfg.Policies[0].BanDurationSec != v2.ProtectionDefaultBanSec {
		t.Fatalf("%+v", cfg)
	}
}

func TestNormalizeConfigKeepsZeroPathThreshold(t *testing.T) {
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", Paths: []string{"/wp-login.php"}, PathThreshold: 0, PathWindowSec: 0,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies[0].PathThreshold != 0 || cfg.Policies[0].PathWindowSec != 0 {
		t.Fatalf("zero path threshold must stay disabled, got %+v", cfg.Policies[0])
	}
}

func TestNormalizeConfigKeepsPermanentBanDuration(t *testing.T) {
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", BanDurationSec: v2.ProtectionBanPermanentSec,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies[0].BanDurationSec != v2.ProtectionBanPermanentSec {
		t.Fatalf("permanent ban must stay -1, got %+v", cfg.Policies[0])
	}
	cfg, err = NormalizeConfig(v2.ProtectionConfig{
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", BanDurationSec: -30,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies[0].BanDurationSec != v2.ProtectionBanPermanentSec {
		t.Fatalf("any negative ban duration is permanent, got %+v", cfg.Policies[0])
	}
}

func TestNormalizeConfigRejectsOutOfRangePort(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "70000",
		}},
	})
	if err == nil {
		t.Fatal("port range")
	}
}

func TestNormalizeConfigRequiresSourceBindForAddrLogPolicy(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: "/var/log/caddy/access.log",
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", BindAddr: "192.0.2.10", SourceID: "s1",
			RequestWindowSec: 60, RequestThreshold: 10,
		}},
	})
	if err == nil {
		t.Fatal("caddy source without bind_addr")
	}
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: "/var/log/caddy/access.log", BindAddr: "192.0.2.10",
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", BindAddr: "192.0.2.10", SourceID: "s1",
			RequestWindowSec: 60, RequestThreshold: 10,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[0].BindAddr != "192.0.2.10" {
		t.Fatalf("%+v", cfg.Sources[0])
	}
}

func TestNormalizeConfigAcceptsSSHDJournalSource(t *testing.T) {
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "12560",
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "12560", SourceID: "s1", Mode: v2.ProtectionModeEnforce,
			RequestWindowSec: 60, RequestThreshold: 3, Paths: []string{"/admin"}, PathThreshold: 8, PathWindowSec: 60,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[0].BindProtocol != v2.FirewallProtoTCP || cfg.Sources[0].DeployMode != v2.ProtectionDeployDirect {
		t.Fatalf("%+v", cfg.Sources[0])
	}
	if len(cfg.Policies[0].Paths) != 0 || cfg.Policies[0].PathThreshold != 0 {
		t.Fatalf("sshd policies must drop path rules: %+v", cfg.Policies[0])
	}
}

func TestNormalizeConfigRejectsDuplicateSSHDSources(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{
			{ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "12560"},
			{ID: "s2", Format: v2.ProtectionLogSSHD, Path: "/var/log/auth.log", BindPort: "12560"},
		},
	})
	if err == nil {
		t.Fatal("duplicate sshd")
	}
}

func TestNormalizeConfigAllowsSSHDPortMismatchForWhitelist(t *testing.T) {
	cfg, err := NormalizeConfig(v2.ProtectionConfig{
		Whitelist: []string{"192.0.2.8"},
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "12560",
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "22", SourceID: "s1", RequestWindowSec: 60, RequestThreshold: 3,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Whitelist) != 1 || cfg.Whitelist[0] != "192.0.2.8" {
		t.Fatalf("whitelist dropped: %+v", cfg.Whitelist)
	}
}

func TestNormalizeConfigRejectsSSHDWithoutPort(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogSSHD, Path: "/var/log/auth.log",
		}},
	})
	if err == nil {
		t.Fatal("sshd bind port")
	}
}

func TestNormalizeConfigRejectsSSHDProxy(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "22", DeployMode: v2.ProtectionDeployProxy,
		}},
	})
	if err == nil {
		t.Fatal("sshd proxy")
	}
}

func TestNormalizeConfigRejectsProxyEnforce(t *testing.T) {
	_, err := NormalizeConfig(v2.ProtectionConfig{
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogCaddyJSON, Path: "/var/log/caddy/access.log", DeployMode: v2.ProtectionDeployProxy,
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Port: "443", Mode: v2.ProtectionModeEnforce, SourceID: "s1",
		}},
	})
	if err == nil {
		t.Fatal("proxy enforce")
	}
}
