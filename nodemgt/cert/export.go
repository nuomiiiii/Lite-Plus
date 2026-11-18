package cert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RootTLSDir(domain string) string {
	name := FileKey(domain)
	if name == "" || name == "cert" {
		name = "root"
	}
	return filepath.Join("data", "tls", "root", name)
}

func WriteRootFiles(domain, chainPEM, keyPEM string) (certPath, keyPath string, err error) {
	if err := ValidateDomain(domain); err != nil {
		return "", "", fmt.Errorf("invalid domain: %w", err)
	}
	chainPEM = strings.TrimSpace(chainPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if chainPEM == "" || keyPEM == "" {
		return "", "", fmt.Errorf("root certificate is not issued")
	}
	baseRootDir := filepath.Join("data", "tls", "root")
	dir := RootTLSDir(domain)
	rel, err := filepath.Rel(baseRootDir, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", fmt.Errorf("invalid root certificate directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	nativeCert := filepath.Join(dir, "fullchain.pem")
	nativeKey := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(nativeCert, []byte(chainPEM+"\n"), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(nativeKey, []byte(keyPEM+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return "./" + filepath.ToSlash(nativeCert), "./" + filepath.ToSlash(nativeKey), nil
}
