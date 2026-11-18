package secretcrypt

import (
	"testing"

	"github.com/nuomiiiii/lite/utils/instancekey"
)

func TestSealAndOpenCachesAEADAndTracksKeyChange(t *testing.T) {
	cleanup1 := instancekey.SetupTempFileForTest()
	enc1, err := Seal("secret-one")
	if err != nil {
		cleanup1()
		t.Fatal(err)
	}
	got1, err := Open(enc1)
	if err != nil || got1 != "secret-one" {
		cleanup1()
		t.Fatalf("got %q, err %v", got1, err)
	}
	cleanup1()

	cleanup2 := instancekey.SetupTempFileForTest()
	defer cleanup2()

	if _, err := Open(enc1); err == nil {
		t.Fatal("ciphertext from previous instance key should fail to decrypt under rotated key")
	}
	enc2, err := Seal("secret-two")
	if err != nil {
		t.Fatal(err)
	}
	got2, err := Open(enc2)
	if err != nil || got2 != "secret-two" {
		t.Fatalf("got %q, err %v", got2, err)
	}
}
