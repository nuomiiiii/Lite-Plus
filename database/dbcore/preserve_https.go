package dbcore

import "github.com/nuomiiiii/lite/pkg/config"

const legacyLiteHTTPSListen = ":36888"

// preserveLegacyHTTPSListen keeps Lite's HTTPS listen when an existing data
// directory has never stored https_listen. GetManyAs would otherwise insert
// Plus's new-install default :37888.
func preserveLegacyHTTPSListen() error {
	if instance == nil || !dbFileExistedAtStartup {
		return nil
	}
	var count int64
	if err := instance.Model(&config.ConfigItem{}).Where("key = ?", config.HTTPSListenKey).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return config.Set(config.HTTPSListenKey, legacyLiteHTTPSListen)
}
