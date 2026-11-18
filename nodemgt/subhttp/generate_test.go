package subhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dbmodels "github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/sub"
	"github.com/nuomiiiii/lite/nodemgt/subtpl"
	"github.com/nuomiiiii/lite/utils/instancekey"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func subscriptionFixture(t *testing.T) (*store.Store, models.Subscription) {
	t.Helper()
	cleanup := instancekey.SetupTempFileForTest()
	t.Cleanup(cleanup)
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	st := store.New(db)
	require.NoError(t, st.Migrate())
	require.NoError(t, db.AutoMigrate(&dbmodels.Client{}))
	user := models.NodeUser{NodeUUID: "n1", Username: "alice", Status: models.UserActive}
	require.NoError(t, st.UpsertUser(&user))
	_, _, err = st.IssueCredential(user.ID, "password", "test-password", nil)
	require.NoError(t, err)
	for _, name := range []string{"allowed", "forbidden"} {
		in := models.Inbound{ID: name, NodeUUID: "n1", Core: "xray", Name: name, Protocol: "trojan", Port: 443, Enabled: true,
			SettingsJSON: fmt.Sprintf(`{"share_strategy":"other","public_host":"%s.example.com","security":"tls","sni":"%s.example.com"}`, name, name)}
		require.NoError(t, st.UpsertInbound(&in))
	}
	require.NoError(t, st.ReplaceGrants(user.ID, []string{"allowed"}))
	row, err := st.EnsureSubscription(user.ID)
	require.NoError(t, err)
	return st, *row
}

func publicSubscription(st *store.Store, token, query, ua string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/sub/"+token+query, nil)
	c.Request.Header.Set("User-Agent", ua)
	Write(c, st, token)
	return w
}

func TestPublicDeliveryMatchesPreviewAndRespectsGrants(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st, row := subscriptionFixture(t)
	row.AutoDetect = true
	require.NoError(t, st.UpsertSubscription(&row))
	for _, tc := range []struct{ ua, client string }{{"Loon/3", "loon"}, {"mihomo/1.19", "mihomo"}, {"sing-box/1.14", "sing-box"}, {"Surge/5", "surge"}} {
		w := publicSubscription(st, row.Token, "", tc.ua)
		require.Equal(t, 200, w.Code, w.Body.String())
		require.Equal(t, tc.client, w.Header().Get("X-Subscription-Client"))
		doc, err := Generate(st, row, GenerateRequest{UserAgent: tc.ua})
		require.NoError(t, err)
		require.Equal(t, doc.Body, w.Body.String())
		require.Contains(t, doc.Body, "allowed.example.com")
		require.NotContains(t, doc.Body, "forbidden.example.com")
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Equal(t, "User-Agent", w.Header().Get("Vary"))
	}
	w := publicSubscription(st, row.Token, "?target=loon&format=clash", "mihomo/1.19")
	require.Equal(t, 200, w.Code)
	require.Equal(t, "loon", w.Header().Get("X-Subscription-Client"))
}

func TestServePanelUsesListenPortIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st, row := subscriptionFixture(t)
	path := "/sub/" + row.Token
	panel := func(port int, host string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, path, nil)
		c.Request.Host = host
		c.Request.Header.Set("User-Agent", "mihomo/1.19")
		servePanel(c, st, Config{ListenPort: port, Path: "/sub/"})
		return w
	}
	served := panel(0, "127.0.0.1:28777")
	require.Equal(t, 200, served.Code, served.Body.String())
	require.NotEmpty(t, served.Header().Get("X-Subscription-Client"))
	require.NotEqual(t, "not found", served.Body.String())
	for _, host := range []string{"127.0.0.1:28777", "[::1]:28777", "127.0.0.1:37888", "[::1]:37888"} {
		blocked := panel(2096, host)
		require.Equal(t, http.StatusNotFound, blocked.Code, host)
		require.Equal(t, "not found", blocked.Body.String(), host)
		require.Empty(t, blocked.Header().Get("X-Subscription-Client"), host)
	}
}

func TestOldSubscriptionBytesAndTokenSurviveEdits(t *testing.T) {
	st, row := subscriptionFixture(t)
	user, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	nodes, err := sub.ForUser(st, *user)
	require.NoError(t, err)
	want, _, err := sub.Render(row.Format, nodes, nil)
	require.NoError(t, err)
	doc, err := Generate(st, row, GenerateRequest{UserAgent: "Loon/3"})
	require.NoError(t, err)
	require.Equal(t, want, doc.Body)
	oldToken := row.Token
	row.Token = ""
	row.AutoDetect = true
	require.NoError(t, st.UpsertSubscription(&row))
	require.Equal(t, oldToken, row.Token)
	_, err = st.GetSubscriptionByToken(oldToken)
	require.NoError(t, err)
	for _, format := range []string{"clash", "sing-box", "base64"} {
		doc, err := Generate(st, row, GenerateRequest{Format: format, UserAgent: "Loon/3"})
		require.NoError(t, err)
		want, _, err := sub.Render(format, nodes, nil)
		require.NoError(t, err)
		require.Equal(t, want, doc.Body)
	}
}

func TestSubscriptionDeniesDisabledExpiredAndRevokedAccess(t *testing.T) {
	st, row := subscriptionFixture(t)
	row.Enabled = false
	require.NoError(t, st.UpsertSubscription(&row))
	require.Equal(t, 404, publicSubscription(st, row.Token, "?target=loon", "").Code)
	row.Enabled = true
	require.NoError(t, st.UpsertSubscription(&row))
	require.NoError(t, st.SetUserStatus(row.UserID, models.UserDisabled))
	disabledResp := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, 404, disabledResp.Code)
	require.Equal(t, "not found", disabledResp.Body.String())
	require.NoError(t, st.SetUserStatus(row.UserID, models.UserActive))
	past := time.Now().Add(-time.Minute)
	require.NoError(t, st.DB().Model(&models.NodeUser{}).Where("id = ?", row.UserID).Update("expires_at", past).Error)
	expiredResp := publicSubscription(st, row.Token, "?target=sing-box", "")
	require.Equal(t, 404, expiredResp.Code)
	require.Equal(t, "not found", expiredResp.Body.String())
	loaded, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	require.Equal(t, models.UserExpired, loaded.Status)
	invalidResp := publicSubscription(st, "invalid-token", "?target=loon", "")
	require.Equal(t, 404, invalidResp.Code)
	require.Equal(t, "not found", invalidResp.Body.String())
}

func TestTemplateBindingPrecedenceAndUpdates(t *testing.T) {
	st, row := subscriptionFixture(t)
	plan := models.Plan{Name: "test-plan"}
	require.NoError(t, st.UpsertPlan(&plan))
	require.NoError(t, st.SaveAssignment(&models.Assignment{UserID: row.UserID, PlanID: plan.ID, StartsAt: time.Now().Add(-time.Minute), OperationID: uuid.NewString()}))
	templates := []models.SubscriptionTemplate{}
	for _, scope := range []string{"global", "plan", "subscription"} {
		tpl := subtpl.DefaultTemplate("clash")
		tpl.ID = ""
		tpl.Name = scope
		tpl.Content = "# " + scope + "\n" + tpl.Content
		require.NoError(t, st.UpsertSubscriptionTemplate(&tpl))
		templates = append(templates, tpl)
		scopeID := ""
		if scope == "plan" {
			scopeID = plan.ID
		}
		if scope == "subscription" {
			scopeID = row.ID
		}
		require.NoError(t, st.SetSubscriptionTemplateBinding(&models.SubscriptionTemplateBinding{Scope: scope, ScopeID: scopeID, Client: "mihomo", TemplateID: tpl.ID}))
		doc, err := Generate(st, row, GenerateRequest{Target: "mihomo"})
		require.NoError(t, err)
		require.Equal(t, tpl.ID, doc.TemplateID)
	}
	require.ErrorIs(t, st.DeleteSubscriptionTemplate(templates[2].ID), store.ErrConflict)
	require.NoError(t, st.SetSubscriptionTemplateBinding(&models.SubscriptionTemplateBinding{Scope: "subscription", ScopeID: row.ID, Client: "mihomo"}))
	doc, err := Generate(st, row, GenerateRequest{Target: "mihomo"})
	require.NoError(t, err)
	require.Equal(t, templates[1].ID, doc.TemplateID)
	updated := templates[1]
	updated.Content = strings.ReplaceAll(updated.Content, "MATCH,PROXY", "DOMAIN-SUFFIX,emby.example,PROXY\n  - MATCH,PROXY")
	require.NoError(t, st.UpsertSubscriptionTemplate(&updated))
	require.Equal(t, uint64(2), updated.Revision)
	doc, err = Generate(st, row, GenerateRequest{Target: "mihomo"})
	require.NoError(t, err)
	require.Contains(t, doc.Body, "emby.example")
	wrong := models.SubscriptionTemplateBinding{Scope: "global", Client: "loon", TemplateID: updated.ID}
	require.ErrorIs(t, st.SetSubscriptionTemplateBinding(&wrong), store.ErrInvalid)
}

func TestLegacyClashFormatKeepsNodeListWhenATemplateIsBound(t *testing.T) {
	st, row := subscriptionFixture(t)
	tpl := subtpl.DefaultTemplate("clash")
	tpl.ID = ""
	tpl.Name = "starred"
	require.NoError(t, st.UpsertSubscriptionTemplate(&tpl))
	require.NoError(t, st.SetSubscriptionTemplateBinding(&models.SubscriptionTemplateBinding{
		Scope: "global", Client: "clash", TemplateID: tpl.ID,
	}))
	require.NoError(t, st.SetSubscriptionTemplateBinding(&models.SubscriptionTemplateBinding{
		Scope: "global", Client: "mihomo", TemplateID: tpl.ID,
	}))
	user, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	nodes, err := sub.ForUser(st, *user)
	require.NoError(t, err)
	want, _, err := sub.Render("clash", nodes, nil)
	require.NoError(t, err)
	doc, err := Generate(st, row, GenerateRequest{Format: "clash"})
	require.NoError(t, err)
	require.Equal(t, want, doc.Body)
	require.Empty(t, doc.TemplateID)
	targeted, err := Generate(st, row, GenerateRequest{Target: "mihomo"})
	require.NoError(t, err)
	require.Equal(t, tpl.ID, targeted.TemplateID)
	require.NotEqual(t, want, targeted.Body)

	// Saved subscription Format="clash" or "sing-box" must apply custom bound templates when no explicit ?format= override is given.
	row.Format = "clash"
	require.NoError(t, st.UpsertSubscription(&row))
	savedClash, err := Generate(st, row, GenerateRequest{})
	require.NoError(t, err)
	require.Equal(t, tpl.ID, savedClash.TemplateID)

	singTpl := subtpl.DefaultTemplate("sing-box")
	singTpl.ID = ""
	singTpl.Name = "custom-sing"
	require.NoError(t, st.UpsertSubscriptionTemplate(&singTpl))
	require.NoError(t, st.SetSubscriptionTemplateBinding(&models.SubscriptionTemplateBinding{
		Scope: "global", Client: "sing-box", TemplateID: singTpl.ID,
	}))
	row.Format = "sing-box"
	require.NoError(t, st.UpsertSubscription(&row))
	savedSing, err := Generate(st, row, GenerateRequest{})
	require.NoError(t, err)
	require.Equal(t, singTpl.ID, savedSing.TemplateID)
}

func TestAutomaticShareHostUsesTheSameStoreAsGrants(t *testing.T) {
	for _, tc := range []struct {
		name, ipv4, ipv6, want string
	}{
		{"ipv4", "203.0.113.9", "", "203.0.113.9"},
		{"ipv6", "", "2001:db8::9", "2001:db8::9"},
		{"dual", "203.0.113.9", "2001:db8::9", "2001:db8::9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, row := subscriptionFixture(t)
			require.NoError(t, st.DB().Create(&dbmodels.Client{UUID: "n1", IPv4: tc.ipv4, IPv6: tc.ipv6}).Error)
			require.NoError(t, st.DB().Model(&models.Inbound{}).Where("id = ?", "allowed").Update("settings_json", `{"security":"tls","sni":"allowed.example.com"}`).Error)
			doc, err := Generate(st, row, GenerateRequest{Target: "mihomo"})
			require.NoError(t, err)
			require.Contains(t, doc.Body, tc.want)
			require.NotContains(t, doc.Body, "forbidden.example.com")
			if tc.ipv6 != "" {
				require.NotContains(t, doc.Body, "203.0.113.9")
			}
		})
	}
}
