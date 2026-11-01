package dbcore

import (
	"path/filepath"
	"testing"

	"github.com/nuomiiiii/lite/cmd/flags"
	"github.com/nuomiiiii/lite/pkg/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPreserveLegacyHTTPSListenFillsMissingKey(t *testing.T) {
	dir := t.TempDir()
	previousDB := flags.DatabaseFile
	previousInstance := instance
	previousExisted := dbFileExistedAtStartup
	t.Cleanup(func() {
		flags.DatabaseFile = previousDB
		instance = previousInstance
		dbFileExistedAtStartup = previousExisted
	})
	flags.DatabaseFile = filepath.Join(dir, "lite.db")
	dbFileExistedAtStartup = true

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	instance = db
	config.SetDb(db)

	if err := preserveLegacyHTTPSListen(); err != nil {
		t.Fatal(err)
	}
	got, err := config.GetAs[string](config.HTTPSListenKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != legacyLiteHTTPSListen {
		t.Fatalf("missing HTTPS listen filled with %q, want %s", got, legacyLiteHTTPSListen)
	}

	if err := config.Set(config.HTTPSListenKey, ":9443"); err != nil {
		t.Fatal(err)
	}
	if err := preserveLegacyHTTPSListen(); err != nil {
		t.Fatal(err)
	}
	got, err = config.GetAs[string](config.HTTPSListenKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != ":9443" {
		t.Fatalf("existing HTTPS listen overwritten: %q", got)
	}
}

func TestPreserveLegacyHTTPSListenSkipsNewInstall(t *testing.T) {
	dir := t.TempDir()
	previousDB := flags.DatabaseFile
	previousInstance := instance
	previousExisted := dbFileExistedAtStartup
	t.Cleanup(func() {
		flags.DatabaseFile = previousDB
		instance = previousInstance
		dbFileExistedAtStartup = previousExisted
	})
	flags.DatabaseFile = filepath.Join(dir, "lite.db")
	dbFileExistedAtStartup = false

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	instance = db
	config.SetDb(db)

	if err := preserveLegacyHTTPSListen(); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&config.ConfigItem{}).Where("key = ?", config.HTTPSListenKey).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("new install must not pre-fill HTTPS listen")
	}
}
