package subhttp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/sub"
	"github.com/nuomiiiii/lite/utils/httpsserver"
)

type Config struct {
	ListenPort int
	PublicPort int
	Path       string
	PublicHost string
	Domain     string
	CertPath   string
	KeyPath    string
	ReuseHTTPS bool
}

func (cfg Config) TLS() bool {
	return strings.TrimSpace(cfg.CertPath) != "" && strings.TrimSpace(cfg.KeyPath) != ""
}

func (cfg Config) shareHost() string {
	return strings.TrimSpace(cfg.PublicHost)
}

func (cfg Config) ValidateTLS() error {
	certPath := strings.TrimSpace(cfg.CertPath)
	keyPath := strings.TrimSpace(cfg.KeyPath)
	if cfg.ReuseHTTPS && (certPath == "" || keyPath == "") {
		return fmt.Errorf("built-in https certificate required")
	}
	if certPath == "" && keyPath == "" {
		return nil
	}
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("subscription certificate and private key paths are required")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("subscription certificate: %w", err)
	}
	return nil
}

func settingOn(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func PanelCertificate() (certPath, keyPath string, domains []string) {
	settings, err := httpsserver.LoadSettings()
	if err != nil {
		return "", "", []string{}
	}
	certPath = strings.TrimSpace(settings.CertificatePath)
	keyPath = strings.TrimSpace(settings.PrivateKeyPath)
	if certPath != "" {
		if names, err := httpsserver.CertificateDomains(certPath); err == nil {
			domains = names
		}
	}
	if domains == nil {
		domains = []string{}
	}
	return certPath, keyPath, domains
}

func applyPanelHTTPS(cfg *Config, reuse bool, certPath, keyPath string, domains []string) {
	cfg.ReuseHTTPS = reuse
	if !reuse {
		cfg.CertPath = ""
		cfg.KeyPath = ""
		cfg.Domain = ""
		return
	}
	cfg.CertPath = strings.TrimSpace(certPath)
	cfg.KeyPath = strings.TrimSpace(keyPath)
	if domain := FirstShareDomain(domains); domain != "" {
		cfg.Domain = domain
	}
}

func FirstShareDomain(domains []string) string {
	var wildcard string
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.EqualFold(domain, "localhost") {
			continue
		}
		if strings.HasPrefix(domain, "*.") {
			if wildcard == "" {
				wildcard = strings.TrimPrefix(domain, "*.")
			}
			continue
		}
		return domain
	}
	return wildcard
}

var (
	mu      sync.Mutex
	running *http.Server
)

func NormalizePath(raw string) string {
	path := strings.TrimSpace(raw)
	path = strings.ReplaceAll(path, "\\", "/")
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

func TokenFromPath(reqPath, prefix string) (string, bool) {
	prefix = NormalizePath(prefix)
	path := reqPath
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	rest := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

func PublicURL(cfg Config, token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	path := NormalizePath(cfg.Path) + token
	host := cfg.shareHost()
	if host == "" {
		return path
	}
	scheme := "http"
	if cfg.TLS() {
		scheme = "https"
	}
	switch {
	case strings.HasPrefix(strings.ToLower(host), "https://"):
		scheme = "https"
		host = host[len("https://"):]
	case strings.HasPrefix(strings.ToLower(host), "http://"):
		if !cfg.TLS() {
			scheme = "http"
		}
		host = host[len("http://"):]
	}
	host = strings.TrimSuffix(host, "/")
	if port := publicSharePort(cfg); port > 0 && !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%d", host, port)
	}
	return scheme + "://" + host + path
}

func publicSharePort(cfg Config) int {
	if cfg.PublicPort > 0 && cfg.PublicPort <= 65535 {
		return cfg.PublicPort
	}
	if cfg.ListenPort > 0 && cfg.ListenPort <= 65535 {
		return cfg.ListenPort
	}
	return 0
}

func LoadConfig(st *store.Store) (Config, error) {
	path, err := EnsurePath(st)
	if err != nil {
		return Config{}, err
	}
	portRaw, _ := st.GetSetting("sub_listen_port")
	port, _ := strconv.Atoi(strings.TrimSpace(portRaw))
	publicRaw, _ := st.GetSetting("sub_public_port")
	publicPort, _ := strconv.Atoi(strings.TrimSpace(publicRaw))
	host, _ := st.GetSetting("sub_public_host")
	reuseRaw, _ := st.GetSetting("sub_reuse_https")
	legacyCert, _ := st.GetSetting("sub_cert_path")
	legacyKey, _ := st.GetSetting("sub_key_path")
	reuse := settingOn(reuseRaw) || (strings.TrimSpace(legacyCert) != "" && strings.TrimSpace(legacyKey) != "")
	panelCert, panelKey, panelDomains := PanelCertificate()
	cfg := Config{
		ListenPort: port,
		PublicPort: publicPort,
		Path:       path,
		PublicHost: strings.TrimSpace(host),
	}
	applyPanelHTTPS(&cfg, reuse, panelCert, panelKey, panelDomains)
	return cfg, nil
}

func Reload() error {
	return Start()
}

func EnsurePath(st *store.Store) (string, error) {
	path, err := st.GetSetting("sub_path")
	if err != nil && err != store.ErrNotFound {
		return "", err
	}
	path = NormalizePath(path)
	if path == "/" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		path = NormalizePath("/" + hex.EncodeToString(buf))
		if err := st.SetSetting("sub_path", path); err != nil {
			return "", err
		}
	}
	return path, nil
}

func dedicatedListen(cfg Config) bool {
	return cfg.ListenPort > 0 && cfg.ListenPort <= 65535
}

func Gate() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/system-assets") {
			c.Next()
			return
		}
		st := store.New(dbcore.GetDBInstance())
		cfg, err := LoadConfig(st)
		if err != nil {
			c.Next()
			return
		}
		servePanel(c, st, cfg)
	}
}

func servePanel(c *gin.Context, st *store.Store, cfg Config) {
	token, ok := TokenFromPath(c.Request.URL.Path, cfg.Path)
	if !ok {
		c.Next()
		return
	}
	if dedicatedListen(cfg) {
		c.String(http.StatusNotFound, "not found")
		c.Abort()
		return
	}
	Write(c, st, token)
	c.Abort()
}

func Write(c *gin.Context, st *store.Store, token string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Vary", "User-Agent")
	c.Header("X-Content-Type-Options", "nosniff")
	row, err := st.GetSubscriptionByToken(token)
	if err != nil || !row.Enabled {
		c.String(http.StatusNotFound, "not found")
		return
	}
	doc, err := Generate(st, *row, GenerateRequest{Target: c.Query("target"), Format: c.Query("format"), UserAgent: c.Request.UserAgent()})
	if err != nil {
		c.String(http.StatusNotFound, "Subscription unavailable")
		return
	}
	metadata, err := loadSubscriptionMetadata(st, row.UserID, time.Now().UTC())
	if err != nil {
		c.String(http.StatusNotFound, "Subscription unavailable")
		return
	}
	c.Header("Content-Disposition", metadata.contentDisposition)
	if metadata.userInfo != "" {
		c.Header("Subscription-Userinfo", metadata.userInfo)
	}
	c.Header("X-Subscription-Client", doc.Client)
	c.Data(http.StatusOK, doc.ContentType, []byte(doc.Body))
}

func ExpandedExtras(st *store.Store, userID, extraURLs string) []string {
	if st == nil {
		return sub.ParseExtraURLs(extraURLs)
	}
	links, err := st.ListUserExtraLinks(userID)
	if err != nil {
		links = nil
	}
	out, status := sub.ExpandExtras(links, extraURLs, time.Now().UTC())
	for _, row := range status {
		if row.ID == "" {
			continue
		}
		_ = st.RecordUserExtraLinkFetch(row.ID, row.Err, row.At)
	}
	return out
}

func Start() error {
	st := store.New(dbcore.GetDBInstance())
	cfg, err := LoadConfig(st)
	if err != nil {
		return err
	}
	return Apply(cfg)
}

func Apply(cfg Config) error {
	if dedicatedListen(cfg) {
		if err := cfg.ValidateTLS(); err != nil {
			return err
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if err := stopLocked(context.Background()); err != nil {
		return err
	}
	if !dedicatedListen(cfg) {
		return nil
	}
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.NoRoute(func(c *gin.Context) {
		st := store.New(dbcore.GetDBInstance())
		loaded, err := LoadConfig(st)
		if err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		token, ok := TokenFromPath(c.Request.URL.Path, loaded.Path)
		if !ok {
			c.String(http.StatusNotFound, "not found")
			return
		}
		Write(c, st, token)
	})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ListenPort),
		Handler:           engine,
		ReadHeaderTimeout: 8 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLS() {
			err = srv.ListenAndServeTLS(cfg.CertPath, cfg.KeyPath)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(150 * time.Millisecond):
	}
	running = srv
	return nil
}

func Shutdown(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	return stopLocked(ctx)
}

func stopLocked(ctx context.Context) error {
	if running == nil {
		return nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}
	err := running.Shutdown(ctx)
	running = nil
	return err
}
