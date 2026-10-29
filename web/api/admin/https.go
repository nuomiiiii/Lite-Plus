package admin

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nuomiiiii/lite/database/auditlog"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/nodemgt/cert"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/subhttp"
	"github.com/nuomiiiii/lite/pkg/config"
	"github.com/nuomiiiii/lite/utils/httpsserver"
	"github.com/nuomiiiii/lite/web/api"
)

func GetHTTPSSettings(c *gin.Context) {
	settings, err := httpsserver.LoadSettings()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to load HTTPS settings: "+err.Error())
		return
	}
	api.RespondSuccess(c, gin.H{"settings": settings, "status": httpsserver.Default.Status()})
}

func UpdateHTTPSSettings(c *gin.Context) {
	var requested httpsserver.Settings
	if err := c.ShouldBindJSON(&requested); err != nil {
		api.RespondError(c, http.StatusBadRequest, "Invalid HTTPS settings: "+err.Error())
		return
	}
	normalized, err := httpsserver.Normalize(requested)
	if err != nil {
		api.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	previous, err := httpsserver.LoadSettings()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to load current HTTPS settings: "+err.Error())
		return
	}
	if normalized.Enabled {
		if err := httpsserver.Default.Apply(normalized); err != nil {
			api.RespondError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := config.SetMany(normalized.ConfigMap()); err != nil {
			_ = httpsserver.Default.Apply(previous)
			api.RespondError(c, http.StatusInternalServerError, "Failed to save HTTPS settings: "+err.Error())
			return
		}
	} else {
		if err := config.SetMany(normalized.ConfigMap()); err != nil {
			api.RespondError(c, http.StatusInternalServerError, "Failed to save HTTPS settings: "+err.Error())
			return
		}
		if err := httpsserver.Default.DisableAfterResponse(normalized, time.Second); err != nil {
			_ = config.SetMany(previous.ConfigMap())
			api.RespondError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.Header("Strict-Transport-Security", "max-age=0")
		c.Header("Connection", "close")
	}
	_ = subhttp.Reload()
	uuid, _ := c.Get("uuid")
	auditlog.Event(c.ClientIP(), fmt.Sprint(uuid), "warn", "audit.https_update", nil)
	api.RespondSuccess(c, gin.H{
		"settings":     normalized,
		"status":       httpsserver.Default.Status(),
		"http_origin":  httpsserver.Default.HTTPOrigin(c.Request),
		"https_origin": httpsserver.Default.HTTPSOrigin(c.Request),
	})
}

func ReloadHTTPSCertificate(c *gin.Context) {
	if err := httpsserver.Default.ReloadCertificate(); err != nil {
		api.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	_ = subhttp.Reload()
	uuid, _ := c.Get("uuid")
	auditlog.Event(c.ClientIP(), fmt.Sprint(uuid), "info", "audit.https_reload", nil)
	api.RespondSuccess(c, gin.H{"status": httpsserver.Default.Status()})
}

func ReuseRootCertificate(c *gin.Context) {
	var requested struct {
		ID string `json:"id"`
	}
	_ = c.ShouldBindJSON(&requested)
	st := store.New(dbcore.GetDBInstance())
	rows, err := st.ListRootCerts()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	var issued []models.RootCertificate
	for _, row := range rows {
		if strings.EqualFold(row.Status, models.CertIssued) {
			issued = append(issued, row)
		}
	}
	if len(issued) == 0 {
		api.RespondError(c, http.StatusBadRequest, "no issued root certificate")
		return
	}
	picked := issued[0]
	if id := strings.TrimSpace(requested.ID); id != "" {
		found := false
		for _, row := range issued {
			if row.ID == id {
				picked = row
				found = true
				break
			}
		}
		if !found {
			api.RespondError(c, http.StatusBadRequest, "root certificate is not issued")
			return
		}
	} else if len(issued) > 1 {
		choices := make([]gin.H, 0, len(issued))
		for _, row := range issued {
			choices = append(choices, gin.H{
				"id":        row.ID,
				"domain":    row.Domain,
				"issuer":    row.Issuer,
				"not_after": row.NotAfter,
			})
		}
		api.RespondSuccess(c, gin.H{"need_pick": true, "certs": choices})
		return
	}
	keyPEM, err := secretcrypt.Open(picked.KeyPEM)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	certPath, keyPath, err := cert.WriteRootFiles(picked.Domain, picked.ChainPEM, keyPEM)
	if err != nil {
		api.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	settings, err := httpsserver.LoadSettings()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to load HTTPS settings: "+err.Error())
		return
	}
	settings.CertificatePath = certPath
	settings.PrivateKeyPath = keyPath
	normalized, err := httpsserver.Normalize(settings)
	if err != nil {
		api.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	previous, err := httpsserver.LoadSettings()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if normalized.Enabled {
		if err := httpsserver.Default.Apply(normalized); err != nil {
			api.RespondError(c, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := config.SetMany(normalized.ConfigMap()); err != nil {
		if normalized.Enabled {
			_ = httpsserver.Default.Apply(previous)
		}
		api.RespondError(c, http.StatusInternalServerError, "Failed to save HTTPS settings: "+err.Error())
		return
	}
	_ = subhttp.Reload()
	uuid, _ := c.Get("uuid")
	auditlog.Event(c.ClientIP(), fmt.Sprint(uuid), "info", "audit.https_reuse_root", map[string]string{"domain": picked.Domain})
	api.RespondSuccess(c, gin.H{
		"settings":     normalized,
		"status":       httpsserver.Default.Status(),
		"http_origin":  httpsserver.Default.HTTPOrigin(c.Request),
		"https_origin": httpsserver.Default.HTTPSOrigin(c.Request),
		"domain":       picked.Domain,
	})
}
