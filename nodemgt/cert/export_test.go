package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRootFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	certPath, keyPath, err := WriteRootFiles("ABC.com", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "-----BEGIN PRIVATE KEY-----\nMIIK\n-----END PRIVATE KEY-----")
	if err != nil {
		t.Fatal(err)
	}
	want := "./data/tls/root/abc.com/fullchain.pem"
	if filepath.ToSlash(certPath) != want {
		t.Fatalf("cert path %q", certPath)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatalf("key file: %s", raw)
	}
}

func TestWriteRootFilesRequiresIssuedMaterial(t *testing.T) {
	if _, _, err := WriteRootFiles("abc.com", "", "key"); err == nil {
		t.Fatal("empty chain must fail")
	}
}
