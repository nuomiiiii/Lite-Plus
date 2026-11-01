package dbcore

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/nuomiiiii/lite/cmd/flags"
)

const (
	httpListenMarker       = ".http-listen"
	legacyHTTPListenMarker = ".legacy-http-listen"
	liteEnvFileName        = "lite.env"
	defaultPlusHTTPListen  = "0.0.0.0:28777"
)

func normalizeDataDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return dataDir
	}
	if strings.TrimSpace(flags.DatabaseFile) != "" {
		dir := filepath.Dir(flags.DatabaseFile)
		if dir != "" && dir != "." {
			return dir
		}
	}
	return filepath.Join(".", "data")
}

func existingLiteDatabase(dataDir string) bool {
	return fileExists(filepath.Join(dataDir, "lite.db"))
}

func existingPlusDatabase(dataDir string) bool {
	raw, err := os.ReadFile(filepath.Join(dataDir, "lite.db"))
	if err != nil {
		return false
	}
	return bytes.Contains(raw, []byte("nodemgt_inbounds")) || bytes.Contains(raw, []byte("client_firewall_intents"))
}

// ResolveDefaultHTTPListen returns the HTTP listen address when -l / LITE_LISTEN
// are unset.
//
// New installs use 28777. An existing Lite data directory keeps whatever listen
// address was actually persisted (marker, lite.env). That value may be custom;
// Plus never substitutes 28777 over it.
func ResolveDefaultHTTPListen(dataDir string) string {
	dataDir = normalizeDataDir(dataDir)
	if addr, ok := readHTTPListenMarker(dataDir); ok {
		return addr
	}
	if addr, ok := readListenFromLiteEnv(dataDir); ok {
		return addr
	}
	if existingPlusDatabase(dataDir) {
		return defaultPlusHTTPListen
	}
	if existingLiteDatabase(dataDir) {
		// Lite was started without a persisted listen record. Keep the listen
		// Lite used in that situation instead of jumping to Plus 28777.
		return "0.0.0.0:27777"
	}
	return defaultPlusHTTPListen
}

// RememberHTTPListen stores the listen address this process actually uses so a
// later default-port change does not move an existing instance.
func RememberHTTPListen(dataDir, listen string) error {
	dataDir = normalizeDataDir(dataDir)
	addr, err := normalizeHTTPListenAddr(listen)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, httpListenMarker), []byte(addr+"\n"), 0o600)
}

func readHTTPListenMarker(dataDir string) (string, bool) {
	for _, name := range []string{httpListenMarker, legacyHTTPListenMarker} {
		content, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil {
			continue
		}
		addr, err := normalizeHTTPListenAddr(string(content))
		if err != nil {
			continue
		}
		return addr, true
	}
	return "", false
}

func readListenFromLiteEnv(dataDir string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(dataDir, liteEnvFileName))
	if err != nil {
		return "", false
	}
	port := ""
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) != "LISTEN_PORT" {
			continue
		}
		port = strings.Trim(strings.TrimSpace(value), `"'`)
		break
	}
	if port == "" {
		return "", false
	}
	addr, err := normalizeHTTPListenAddr(port)
	if err != nil {
		return "", false
	}
	return addr, true
}

func normalizeHTTPListenAddr(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty listen address")
	}
	if !strings.Contains(s, ":") {
		s = "0.0.0.0:" + s
	} else if strings.HasPrefix(s, ":") {
		s = "0.0.0.0" + s
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, port), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
