package dbcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuomiiiii/lite/cmd/flags"
)

func TestResolveDefaultHTTPListenUsesPlusPortOnFreshDir(t *testing.T) {
	dir := t.TempDir()
	if got := ResolveDefaultHTTPListen(dir); got != defaultPlusHTTPListen {
		t.Fatalf("fresh dir = %q, want %q", got, defaultPlusHTTPListen)
	}
}

func TestResolveDefaultHTTPListenKeepsCustomMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".http-listen"), []byte("127.0.0.1:18080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveDefaultHTTPListen(dir); got != "127.0.0.1:18080" {
		t.Fatalf("custom marker = %q, want 127.0.0.1:18080", got)
	}
}

func TestResolveDefaultHTTPListenReadsLiteLegacyMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".legacy-http-listen"), []byte("0.0.0.0:19090\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveDefaultHTTPListen(dir); got != "0.0.0.0:19090" {
		t.Fatalf("lite marker = %q, want the stored address", got)
	}
}

func TestResolveDefaultHTTPListenReadsCustomLiteEnvPort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lite.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lite.env"), []byte("LISTEN_PORT=12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveDefaultHTTPListen(dir); got != "0.0.0.0:12345" {
		t.Fatalf("lite.env = %q, want 0.0.0.0:12345", got)
	}
}

func TestResolveDefaultHTTPListenDoesNotJumpExistingLiteDBToPlusDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lite.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ResolveDefaultHTTPListen(dir)
	if got == defaultPlusHTTPListen {
		t.Fatalf("existing lite.db jumped to Plus default %q", got)
	}
	if got != "0.0.0.0:27777" {
		t.Fatalf("unspecified Lite data = %q, want Lite's previous unspecified listen", got)
	}
}

func TestResolveDefaultHTTPListenKeepsPlusSchemaOnPlusDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lite.db"), []byte("CREATE TABLE nodemgt_inbounds (id text);"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ResolveDefaultHTTPListen(dir)
	if got != defaultPlusHTTPListen {
		t.Fatalf("Plus schema without marker = %q, want %q", got, defaultPlusHTTPListen)
	}
}

func TestRememberHTTPListenPersistsCustomAddress(t *testing.T) {
	dir := t.TempDir()
	if err := RememberHTTPListen(dir, "127.0.0.1:9443"); err != nil {
		t.Fatal(err)
	}
	if got := ResolveDefaultHTTPListen(dir); got != "127.0.0.1:9443" {
		t.Fatalf("remembered = %q", got)
	}
}

func TestAlignStagedMainDatabaseIgnoresKomariDatabase(t *testing.T) {
	dir := t.TempDir()
	previous := flags.DatabaseFile
	t.Cleanup(func() { flags.DatabaseFile = previous })
	flags.DatabaseFile = filepath.Join(dir, "lite.db")
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "komari.db"), []byte("komari"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := alignStagedMainDatabase(stage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("komari.db must not be adopted as lite.db, target=%s err=%v", target, err)
	}
	komari, err := os.ReadFile(filepath.Join(stage, "komari.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(komari) != "komari" {
		t.Fatalf("komari.db changed: %q", komari)
	}
}

func TestAlignStagedMainDatabaseKeepsLiteDatabase(t *testing.T) {
	dir := t.TempDir()
	previous := flags.DatabaseFile
	t.Cleanup(func() { flags.DatabaseFile = previous })
	flags.DatabaseFile = filepath.Join(dir, "lite.db")
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "lite.db"), []byte("lite"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := alignStagedMainDatabase(stage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "lite" {
		t.Fatalf("lite.db = %q", got)
	}
}
