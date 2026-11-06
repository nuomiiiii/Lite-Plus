package jsonrpc

import (
	"strings"
	"testing"
)

func settingsBool(v bool) *bool       { return &v }
func settingsInt(v int) *int          { return &v }
func settingsString(v string) *string { return &v }

func TestNodemgtSettingsChangedIgnoresUnchangedFormFields(t *testing.T) {
	prev := nodemgtSettingsSnapshot{
		ListenPort:      8443,
		PublicPort:      443,
		Path:            "/sub/",
		PublicHost:      "example.com",
		ReuseHTTPS:      true,
		PublishName:     true,
		PublishUserinfo: true,
	}
	got := nodemgtSettingsChanged(nodemgtSettingsPatch{
		SubListenPort:      settingsInt(8443),
		SubPublicPort:      settingsInt(443),
		SubPath:            settingsString("/sub"),
		SubPublicHost:      settingsString("example.com"),
		SubReuseHTTPS:      settingsBool(true),
		SubPublishName:     settingsBool(true),
		SubPublishUserinfo: settingsBool(true),
	}, prev)
	if len(got) != 0 {
		t.Fatalf("unchanged form save logged %v", got)
	}
}

func TestNodemgtSettingsChangedKeepsOnlyEditedKeys(t *testing.T) {
	prev := nodemgtSettingsSnapshot{
		ListenPort:      8443,
		Path:            "/sub/",
		PublishName:     true,
		PublishUserinfo: false,
	}
	got := nodemgtSettingsChanged(nodemgtSettingsPatch{
		SubListenPort:      settingsInt(8443),
		SubPath:            settingsString("/v2/"),
		SubPublishName:     settingsBool(true),
		SubPublishUserinfo: settingsBool(true),
	}, prev)
	if strings.Join(got, ",") != "sub_path,sub_publish_userinfo" {
		t.Fatalf("got %v", got)
	}
}

func TestNodemgtSettingsChangedSkipsSameSecretAndEmptyClear(t *testing.T) {
	prev := nodemgtSettingsSnapshot{Token: "secret", Email: "a@example.com"}
	same := nodemgtSettingsChanged(nodemgtSettingsPatch{
		CFAPIToken: "secret",
		ACMEEmail:  settingsString("a@example.com"),
	}, prev)
	if len(same) != 0 {
		t.Fatalf("same issuer logged %v", same)
	}
	cleared := nodemgtSettingsChanged(nodemgtSettingsPatch{ClearIssuer: settingsBool(true)}, prev)
	if strings.Join(cleared, ",") != "clear_issuer" {
		t.Fatalf("clear issuer got %v", cleared)
	}
	alreadyEmpty := nodemgtSettingsChanged(nodemgtSettingsPatch{ClearIssuer: settingsBool(true)}, nodemgtSettingsSnapshot{})
	if len(alreadyEmpty) != 0 {
		t.Fatalf("empty issuer clear logged %v", alreadyEmpty)
	}
}
