package jsonrpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/database/accounts"
	"github.com/nuomiiiii/lite/database/clients"
	"github.com/nuomiiiii/lite/database/dbcore"
	"github.com/nuomiiiii/lite/nodemgt/cert"
	"github.com/nuomiiiii/lite/nodemgt/control"
	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/ops"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/subhttp"
	"github.com/nuomiiiii/lite/nodemgt/subtpl"
	"github.com/nuomiiiii/lite/pkg/rpc"
	logger "github.com/nuomiiiii/lite/utils/log"
	"github.com/nuomiiiii/lite/web/firewall"
	"gorm.io/gorm"
)

func init() {
	reg("nodemgt.inbound.list", nodemgtInboundList, "List nodemgt inbounds")
	reg("nodemgt.inbound.upsert", nodemgtInboundUpsert, "Create or update a nodemgt inbound")
	reg("nodemgt.inbound.reorder", nodemgtInboundReorder, "Reorder nodemgt inbounds for subscription")
	reg("nodemgt.inbound.delete", nodemgtInboundDelete, "Delete a nodemgt inbound")
	reg("nodemgt.outbound.list", nodemgtOutboundList, "List nodemgt outbounds")
	reg("nodemgt.outbound.upsert", nodemgtOutboundUpsert, "Create or update a nodemgt outbound")
	reg("nodemgt.outbound.delete", nodemgtOutboundDelete, "Delete a nodemgt outbound")
	reg("nodemgt.route.list", nodemgtRouteList, "List nodemgt routes")
	reg("nodemgt.route.upsert", nodemgtRouteUpsert, "Create or update a nodemgt route")
	reg("nodemgt.route.delete", nodemgtRouteDelete, "Delete a nodemgt route")
	reg("nodemgt.user.list", nodemgtUserList, "List node users")
	reg("nodemgt.user.upsert", nodemgtUserUpsert, "Create or update a node user")
	reg("nodemgt.user.delete", nodemgtUserDelete, "Delete a node user")
	reg("nodemgt.user.setStatus", nodemgtUserSetStatus, "Enable, disable, or expire a node user")
	reg("nodemgt.user.clearIPs", nodemgtUserClearIPs, "Clear recorded client IPs for a node user")
	reg("nodemgt.credential.issue", nodemgtCredentialIssue, "Issue node-user credentials")
	reg("nodemgt.credential.rotate", nodemgtCredentialRotate, "Rotate node-user credentials")
	reg("nodemgt.credential.revoke", nodemgtCredentialRevoke, "Revoke node-user credentials")
	reg("nodemgt.plan.list", nodemgtPlanList, "List plans")
	reg("nodemgt.plan.upsert", nodemgtPlanUpsert, "Create or update a plan")
	reg("nodemgt.plan.delete", nodemgtPlanDelete, "Delete a plan")
	reg("nodemgt.assignment.assign", nodemgtAssign, "Assign a plan to a node user")
	reg("nodemgt.assignment.renew", nodemgtRenew, "Renew a node-user assignment")
	reg("nodemgt.assignment.topup", nodemgtTopup, "Add quota to a node user")
	reg("nodemgt.assignment.modify", nodemgtModify, "Modify quota, rate, devices, or expiry")
	reg("nodemgt.cert.list", nodemgtCertList, "List certificates")
	reg("nodemgt.cert.request", nodemgtCertRequest, "Request a certificate")
	reg("nodemgt.cert.renew", nodemgtCertRequest, "Renew a certificate")
	reg("nodemgt.cert.delete", nodemgtCertDelete, "Delete a certificate")
	reg("nodemgt.cert.set_auto_renew", nodemgtCertSetAutoRenew, "Set certificate auto-renew")
	reg("nodemgt.root_cert.list", nodemgtRootCertList, "List root certificates")
	reg("nodemgt.root_cert.issue", nodemgtRootCertIssue, "Issue a root domain certificate")
	reg("nodemgt.root_cert.delete", nodemgtRootCertDelete, "Delete a root certificate")
	reg("nodemgt.root_cert.set_auto_renew", nodemgtRootCertSetAutoRenew, "Set root certificate auto-renew")
	reg("nodemgt.subscription.list", nodemgtSubList, "List subscriptions")
	reg("nodemgt.subscription.upsert", nodemgtSubUpsert, "Create or update a subscription")
	reg("nodemgt.subscription.delete", nodemgtSubDelete, "Delete a subscription")
	reg("nodemgt.subscription.preview", nodemgtSubPreview, "Preview a subscription payload")
	reg("nodemgt.audit.list", nodemgtAuditList, "List nodemgt audit events")
	reg("nodemgt.control.sync", nodemgtControlSync, "Push pending nodemgt control commands")
	reg("nodemgt.control.status", nodemgtControlStatus, "Latest nodemgt control delivery per node")
	reg("nodemgt.diag.status", nodemgtDiagStatus, "nodemgt diagnostics")
	reg("nodemgt.settings.get", nodemgtSettingsGet, "Get nodemgt certificate issuer settings")
	reg("nodemgt.settings.set", nodemgtSettingsSet, "Save nodemgt certificate issuer settings")
	reg("nodemgt.node.list", nodemgtNodeList, "List node dial-stack profiles")
	reg("nodemgt.node.upsert", nodemgtNodeUpsert, "Save a node's outbound IP stack")
}

func nodemgtST() *store.Store { return store.New(dbcore.GetDBInstance()) }

func nodemgtOps() *ops.Service { return ops.New(nodemgtST()) }

func nodemgtErr(err error) *rpc.JsonRpcError {
	if err == nil {
		return nil
	}
	code := rpc.InternalError
	switch {
	case errors.Is(err, store.ErrNotFound):
		code = rpc.InvalidParams
	case errors.Is(err, store.ErrInvalid), errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrQuota), errors.Is(err, store.ErrUserDisabled), errors.Is(err, store.ErrUserExpired):
		code = rpc.InvalidParams
	}
	return rpc.MakeError(code, err.Error(), nil)
}

func nodemgtActor(ctx context.Context) string {
	u, _ := auditActor(ctx)
	if u == "" {
		return "admin"
	}
	return nodemgtActorName(u)
}

func nodemgtActorName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "admin"
	}
	if user, err := accounts.GetUserByUUID(id); err == nil && strings.TrimSpace(user.Username) != "" {
		return user.Username
	}
	return id
}

func nodemgtPush(st *store.Store, nodeUUID string) {
	nodemgtPushNodes(st, nodeUUID)
}

func nodemgtPushNodes(_ *store.Store, nodeUUIDs ...string) {
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(nodeUUIDs))
	for _, id := range nodeUUIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if _, err := clients.GetClientByUUID(id); err != nil {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	go pushNodemgtPending(append([]string(nil), ids...))
}

func pushNodemgtPending(nodeUUIDs []string) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Errorf("nodemgt", "push pending: %v", rec)
		}
	}()
	st := store.New(dbcore.GetDBInstance())
	for _, id := range nodeUUIDs {
		if err := control.EnqueueApplyConfig(st, id); err != nil {
			logger.Warnf("nodemgt", "enqueue apply %s: %v", id, err)
			continue
		}
		_ = control.PushPending(st, id)
	}
}

func nodemgtShouldClearPlan(planID string, hadPlan bool) bool {
	return strings.TrimSpace(planID) == "" && hadPlan
}

func nodemgtPushUser(st *store.Store, userID string) {
	ids, err := st.NodeIDsForUser(userID)
	if err != nil {
		return
	}
	nodemgtPushNodes(st, ids...)
}

func nodemgtDeliveryStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case models.CmdSent:
		return "sent"
	case models.CmdApplied:
		return "applied"
	case models.CmdFailed:
		return "failed"
	case models.CmdPending, "":
		return "saved"
	default:
		return status
	}
}

func nodemgtCommandView(cmd models.ControlCommand) map[string]any {
	return map[string]any{
		"node_uuid":    cmd.NodeUUID,
		"operation_id": cmd.OperationID,
		"kind":         cmd.Kind,
		"status":       nodemgtDeliveryStatus(cmd.Status),
		"last_error":   cmd.LastError,
		"updated_at":   cmd.UpdatedAt,
		"created_at":   cmd.CreatedAt,
	}
}

func nodemgtInboundList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListInbounds(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, inboundView(row))
	}
	return out, nil
}

type inboundUpsertParams struct {
	ID                 string `json:"id"`
	NodeUUID           string `json:"node_uuid"`
	Core               string `json:"core"`
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Listen             string `json:"listen"`
	Port               int    `json:"port"`
	Enabled            *bool  `json:"enabled"`
	Stack              string `json:"stack"`
	PublicHost         string `json:"public_host"`
	PublicPort         int    `json:"public_port"`
	Flow               string `json:"flow"`
	Transport          string `json:"transport"`
	Security           string `json:"security"`
	SNI                string `json:"sni"`
	TLSDomain          string `json:"tls_domain"`
	ALPN               string `json:"alpn"`
	CertID             string `json:"cert_id"`
	RealityDest        string `json:"reality_dest"`
	RealityServerNames string `json:"reality_server_names"`
	RealityPrivateKey  string `json:"reality_private_key"`
	RealityShortID     string `json:"reality_short_id"`
	RealityPublicKey   string `json:"reality_public_key"`
	WSPath             string `json:"ws_path"`
	WSHost             string `json:"ws_host"`
	GRPCService        string `json:"grpc_service"`
	GRPCMulti          *bool  `json:"grpc_multi"`
	HTTPPath           string `json:"http_path"`
	HTTPHost           string `json:"http_host"`
	HTTPMode           string `json:"http_mode"`
	TCPHeader          string `json:"tcp_header"`
	TCPHost            string `json:"tcp_host"`
	SSMethod           string `json:"ss_method"`
	UDPFragment        *bool  `json:"udp_fragment"`
	Accounts           []inboundcfg.ProxyAccount `json:"accounts"`
	AllowTransparent   *bool                     `json:"allow_transparent"`
	Fingerprint        string `json:"fingerprint"`
	SpiderX            string `json:"spider_x"`
	Sniffing           *bool  `json:"sniffing"`
	DestOverride       string `json:"dest_override"`
	RouteOnly          *bool  `json:"route_only"`
	SortIndex          *int   `json:"sort_index"`
	ExcludeFromSub     *bool  `json:"exclude_from_sub"`
	ShareStrategy      string `json:"share_strategy"`
	FirewallAllow      *bool  `json:"firewall_allow"`
	Grant              string `json:"grant"`
	PageID             string `json:"page_id"`
}

const defaultRealityDest = "addons.mozilla.org:443"

func fillRealityInboundDefaults(p *inboundUpsertParams) error {
	p.Transport = "tcp"
	if strings.TrimSpace(p.RealityDest) == "" {
		p.RealityDest = defaultRealityDest
	}
	if strings.TrimSpace(p.Fingerprint) == "" {
		p.Fingerprint = "chrome"
	}
	if strings.TrimSpace(p.RealityServerNames) == "" {
		p.RealityServerNames = inboundcfg.DestHost(p.RealityDest)
	}
	if strings.TrimSpace(p.RealityPrivateKey) == "" || strings.TrimSpace(p.RealityPublicKey) == "" {
		priv, pub, err := inboundcfg.GenerateRealityKeys()
		if err != nil {
			return err
		}
		p.RealityPrivateKey, p.RealityPublicKey = priv, pub
	}
	return nil
}

func resolveInboundSortIndex(id string, requested *int, existing *models.Inbound, next func() int) int {
	if requested != nil {
		return *requested
	}
	if existing != nil {
		return existing.SortIndex
	}
	if strings.TrimSpace(id) == "" {
		return next()
	}
	return 0
}

func nodemgtInboundUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p inboundUpsertParams
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.NodeUUID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "name and node required", nil)
	}
	if p.Protocol == "" {
		p.Protocol = "vless"
	}
	if p.Core == "" {
		p.Core = inboundcfg.DefaultCore(p.Protocol)
	}
	if strings.EqualFold(p.Protocol, "anytls") {
		p.Core = models.CoreSingBox
		p.Transport = inboundcfg.DefaultTransport(p.Protocol)
		if strings.TrimSpace(p.Security) == "" || strings.EqualFold(p.Security, "none") {
			p.Security = inboundcfg.DefaultSecurity(p.Protocol)
		}
	}
	if strings.EqualFold(p.Protocol, "http") {
		p.Transport = inboundcfg.DefaultTransport(p.Protocol)
		if strings.EqualFold(p.Security, "reality") || strings.TrimSpace(p.Security) == "" {
			p.Security = "none"
		}
		p.TCPHeader = ""
	}
	if strings.EqualFold(p.Protocol, "shadowsocks") {
		p.Transport = inboundcfg.NormalizeSSNetwork(p.Transport)
		if strings.EqualFold(p.Security, "reality") || strings.TrimSpace(p.Security) == "" {
			p.Security = "none"
		}
		p.TCPHeader = ""
	}
	if strings.EqualFold(p.Protocol, "shadowsocks") && strings.TrimSpace(p.SSMethod) == "" {
		p.SSMethod = inboundcfg.DefaultSSMethod()
	}
	if p.Port <= 0 {
		p.Port = 443
	}
	if p.Port > 65535 {
		return nil, rpc.MakeError(rpc.InvalidParams, "invalid inbound port", nil)
	}
	if p.Stack == "" {
		p.Stack = "ipv4"
	}
	if p.Transport == "" {
		p.Transport = inboundcfg.DefaultTransport(p.Protocol)
	}
	if p.Security == "tls" && strings.TrimSpace(p.CertID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "certificate required", nil)
	}
	ssPassword := ""
	if p.ID != "" {
		if existing, err := nodemgtST().GetInbound(p.ID); err == nil && existing != nil {
			old := inboundcfg.Parse(existing.SettingsJSON)
			ssPassword = old.SSPassword
			if strings.TrimSpace(p.RealityPrivateKey) == "" {
				p.RealityPrivateKey = old.RealityPrivateKey
			}
			if strings.TrimSpace(p.RealityPublicKey) == "" {
				p.RealityPublicKey = old.RealityPublicKey
			}
			if strings.TrimSpace(p.RealityShortID) == "" {
				p.RealityShortID = old.RealityShortID
			}
		}
	}
	if p.Security == "reality" {
		if err := fillRealityInboundDefaults(&p); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.Security == "reality" && strings.TrimSpace(p.RealityShortID) == "" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err == nil {
			p.RealityShortID = hex.EncodeToString(buf)
		}
	}
	if strings.TrimSpace(p.CertID) != "" && p.Security == "tls" {
		if issued, err := nodemgtST().GetCert(p.CertID); err == nil && issued != nil {
			if strings.TrimSpace(p.TLSDomain) == "" {
				p.TLSDomain = strings.TrimSpace(issued.ShareDomain)
			}
			if strings.TrimSpace(p.SNI) == "" {
				p.SNI = cert.UsableShareHost(issued.Domain, firstNonEmpty(p.TLSDomain, issued.ShareDomain))
			}
		}
	}
	sniffing := false
	if p.Sniffing != nil {
		sniffing = *p.Sniffing
	}
	destOverride := strings.TrimSpace(p.DestOverride)
	if sniffing && destOverride == "" {
		destOverride = inboundcfg.DefaultDestOverride()
	}
	routeOnly := sniffing
	if p.RouteOnly != nil {
		routeOnly = *p.RouteOnly
	}
	grpcMulti := false
	if p.GRPCMulti != nil {
		grpcMulti = *p.GRPCMulti
	}
	shareStrategy := inboundcfg.NormalizeShareStrategy(p.ShareStrategy)
	if p.ExcludeFromSub != nil && *p.ExcludeFromSub {
		shareStrategy = "none"
	}
	excludeFromSub := shareStrategy == "none"
	if shareStrategy == "other" && strings.TrimSpace(p.PublicHost) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "address required", nil)
	}
	publicHost := ""
	if shareStrategy == "other" {
		publicHost = strings.TrimSpace(p.PublicHost)
	}
	st := nodemgtST()
	var existing *models.Inbound
	if strings.TrimSpace(p.ID) != "" {
		if row, err := st.GetInbound(p.ID); err == nil {
			existing = row
		}
	}
	sortIndex := resolveInboundSortIndex(p.ID, p.SortIndex, existing, func() int {
		return st.NextInboundSortIndex("")
	})
	cfg := inboundcfg.Settings{
		Stack:              p.Stack,
		PublicHost:         publicHost,
		PublicPort:         p.PublicPort,
		Flow:               p.Flow,
		Transport:          p.Transport,
		Security:           p.Security,
		SNI:                p.SNI,
		TLSDomain:          strings.TrimSpace(p.TLSDomain),
		ALPN:               p.ALPN,
		CertID:             p.CertID,
		RealityDest:        p.RealityDest,
		RealityServerNames: p.RealityServerNames,
		RealityPrivateKey:  p.RealityPrivateKey,
		RealityShortID:     p.RealityShortID,
		RealityPublicKey:   p.RealityPublicKey,
		WSPath:             p.WSPath,
		WSHost:             p.WSHost,
		GRPCService:        p.GRPCService,
		GRPCMulti:          grpcMulti,
		HTTPPath:           p.HTTPPath,
		HTTPHost:           p.HTTPHost,
		HTTPMode:           p.HTTPMode,
		TCPHeader:          p.TCPHeader,
		TCPHost:            p.TCPHost,
		SSMethod:           p.SSMethod,
		SSPassword:         ssPassword,
		UDPFragment:        p.UDPFragment,
		Fingerprint:        p.Fingerprint,
		SpiderX:            p.SpiderX,
		Sniffing:           sniffing,
		DestOverride:       destOverride,
		RouteOnly:          routeOnly,
		ExcludeFromSub:     excludeFromSub,
		ShareStrategy:      shareStrategy,
	}
	if strings.EqualFold(p.Protocol, "shadowsocks") {
		cfg.SSNetwork = p.Transport
		cfg.Transport = "tcp"
	}
	if !strings.EqualFold(p.Core, models.CoreSingBox) || !inboundcfg.InboundListensUDP(p.Protocol, cfg) {
		cfg.UDPFragment = nil
	}
	if strings.EqualFold(p.Protocol, "http") {
		cfg.Accounts = inboundcfg.NormalizeAccounts(p.Accounts)
		if len(cfg.Accounts) == 0 {
			cfg.Accounts = []inboundcfg.ProxyAccount{inboundcfg.RandomProxyAccount()}
		}
		if p.AllowTransparent != nil {
			cfg.AllowTransparent = *p.AllowTransparent
		}
	}
	if inboundcfg.EffectiveRouteOnly(cfg) {
		cfg.RouteOnly = true
	}
	if strings.EqualFold(p.Security, "reality") {
		cfg.SNI = inboundcfg.ShareSNI(cfg)
	}
	if strings.EqualFold(p.Protocol, "shadowsocks") && inboundcfg.IsSS2022(cfg.SSMethod) && strings.TrimSpace(cfg.SSPassword) == "" {
		key, err := inboundcfg.GenerateSS2022Key(cfg.SSMethod)
		if err != nil {
			return nil, nodemgtErr(err)
		}
		cfg.SSPassword = key
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	row := models.Inbound{
		ID:           p.ID,
		NodeUUID:     p.NodeUUID,
		Core:         p.Core,
		Name:         p.Name,
		Protocol:     p.Protocol,
		Listen:       inboundcfg.ListenForStack(p.Stack, p.Listen),
		Port:         p.Port,
		SortIndex:    sortIndex,
		SettingsJSON: cfg.Marshal(),
		StreamJSON:   inboundcfg.StreamJSON(cfg, p.Protocol),
		Enabled:      enabled,
	}
	wasLinked := existing != nil && firewall.InboundLinked(existing.NodeUUID, existing.ID)
	op := firewall.PlannedInboundFirewallOp(wasLinked, p.FirewallAllow, existing, row, cfg)
	var expires time.Time
	var grantEpoch uint64
	var grantMeta *rpc.ContextMeta
	if op != firewall.InboundFirewallNone {
		_, clientErr := clients.GetClientByUUID(row.NodeUUID)
		nodePresent := clientErr == nil
		if op == firewall.InboundFirewallLink && enabled && nodePresent {
			if err := firewall.EnsureApplyAllowed(row.NodeUUID); err != nil {
				return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
			}
		}
		if nodePresent {
			meta, rpcErr := scheduledExecActor(ctx)
			if rpcErr != nil {
				return nil, rpcErr
			}
			grantMeta = meta
			expires, grantEpoch, rpcErr = consumeScheduledExecGrant(meta, p.Grant, p.PageID)
			if rpcErr != nil {
				return nil, rpcErr
			}
		}
	}
	if err := st.UpsertInbound(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.inbound.upsert", row.ID, row.Name)
	switch op {
	case firewall.InboundFirewallLink:
		if err := firewall.LinkInbound(row.NodeUUID, row); err != nil {
			return nil, nodemgtErr(err)
		}
	case firewall.InboundFirewallUnlink:
		if err := firewall.UnlinkInbound(row.NodeUUID, row.ID); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	nodemgtPush(st, row.NodeUUID)
	view := inboundView(row)
	if grantMeta != nil {
		return grantPayload(grantMeta.Principal.UserUUID, grantMeta.SessionToken, p.PageID, expires, grantEpoch, view), nil
	}
	return view, nil
}

func inboundView(row models.Inbound) map[string]any {
	s := inboundcfg.Parse(row.SettingsJSON)
	transport := s.Transport
	if strings.EqualFold(row.Protocol, "shadowsocks") {
		transport = inboundcfg.EffectiveSSNetwork(s)
	}
	view := map[string]any{
		"id":                   row.ID,
		"node_uuid":            row.NodeUUID,
		"core":                 row.Core,
		"name":                 row.Name,
		"protocol":             row.Protocol,
		"listen":               row.Listen,
		"port":                 row.Port,
		"sort_index":           row.SortIndex,
		"enabled":              row.Enabled,
		"revision":             row.Revision,
		"created_at":           row.CreatedAt,
		"updated_at":           row.UpdatedAt,
		"stack":                s.Stack,
		"public_host":          s.PublicHost,
		"public_port":          s.PublicPort,
		"flow":                 s.Flow,
		"transport":            transport,
		"security":             s.Security,
		"sni":                  s.SNI,
		"tls_domain":           s.TLSDomain,
		"alpn":                 s.ALPN,
		"cert_id":              s.CertID,
		"reality_dest":         s.RealityDest,
		"reality_server_names": s.RealityServerNames,
		"reality_short_id":     s.RealityShortID,
		"reality_public_key":   s.RealityPublicKey,
		"ws_path":              s.WSPath,
		"ws_host":              s.WSHost,
		"grpc_service":         s.GRPCService,
		"grpc_multi":           s.GRPCMulti,
		"http_path":            s.HTTPPath,
		"http_host":            s.HTTPHost,
		"http_mode":            s.HTTPMode,
		"tcp_header":           s.TCPHeader,
		"tcp_host":             s.TCPHost,
		"ss_method":            s.SSMethod,
		"ss_password":          s.SSPassword,
		"accounts":             s.Accounts,
		"allow_transparent":    s.AllowTransparent,
		"fingerprint":          s.Fingerprint,
		"spider_x":             s.SpiderX,
		"sniffing":             s.Sniffing,
		"dest_override":        s.DestOverride,
		"route_only":           inboundcfg.EffectiveRouteOnly(s),
		"exclude_from_sub":     s.ExcludeFromSub,
		"share_strategy":       s.ShareStrategy,
		"firewall_linked":      firewall.InboundLinked(row.NodeUUID, row.ID),
	}
	if strings.EqualFold(row.Core, models.CoreSingBox) && inboundcfg.InboundListensUDP(row.Protocol, s) {
		view["udp_fragment"] = inboundcfg.EffectiveUDPFragment(row.Protocol, s)
	}
	return view
}

func nodemgtInboundDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID     string `json:"id"`
		Grant  string `json:"grant"`
		PageID string `json:"page_id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	row, err := st.GetInbound(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	var expires time.Time
	var grantEpoch uint64
	var grantMeta *rpc.ContextMeta
	if firewall.InboundLinked(row.NodeUUID, row.ID) {
		if _, err := clients.GetClientByUUID(row.NodeUUID); err != nil {
			if err := firewall.UnlinkInbound(row.NodeUUID, row.ID); err != nil {
				return nil, nodemgtErr(err)
			}
		} else {
			meta, rpcErr := scheduledExecActor(ctx)
			if rpcErr != nil {
				return nil, rpcErr
			}
			grantMeta = meta
			expires, grantEpoch, rpcErr = consumeScheduledExecGrant(meta, p.Grant, p.PageID)
			if rpcErr != nil {
				return nil, rpcErr
			}
			if err := firewall.UnlinkInbound(row.NodeUUID, row.ID); err != nil {
				return nil, nodemgtErr(err)
			}
		}
	}
	if err := st.DeleteInbound(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.inbound.delete", p.ID, row.Name)
	nodemgtPush(st, row.NodeUUID)
	out := map[string]any{"ok": true}
	if grantMeta != nil {
		return grantPayload(grantMeta.Principal.UserUUID, grantMeta.SessionToken, p.PageID, expires, grantEpoch, out), nil
	}
	return out, nil
}

func nodemgtInboundReorder(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string   `json:"node_uuid"`
		IDs      []string `json:"ids"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if len(p.IDs) == 0 {
		return nil, rpc.MakeError(rpc.InvalidParams, "ids required", nil)
	}
	st := nodemgtST()
	if err := st.ReorderInbounds(p.NodeUUID, p.IDs); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.inbound.reorder", p.NodeUUID, "")
	if p.NodeUUID != "" {
		nodemgtPush(st, p.NodeUUID)
	}
	rows, err := st.ListInbounds(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, inboundView(row))
	}
	return out, nil
}

func nodemgtOutboundList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListOutbounds(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, outboundView(row))
	}
	return out, nil
}

func outboundView(row models.Outbound) map[string]any {
	var s struct {
		Address          string `json:"address"`
		Port             int    `json:"port"`
		Username         string `json:"username"`
		Password         string `json:"password"`
		UUID             string `json:"uuid"`
		Flow             string `json:"flow"`
		DomainStrategy   string `json:"domain_strategy"`
		Transport        string `json:"transport"`
		Security         string `json:"security"`
		SNI              string `json:"sni"`
		Fingerprint      string `json:"fingerprint"`
		WSPath           string `json:"ws_path"`
		WSHost           string `json:"ws_host"`
		GRPCService      string `json:"grpc_service"`
		SSMethod         string `json:"ss_method"`
		SSNetwork        string `json:"ss_network"`
		ViaOutbound      string `json:"via_outbound"`
		RealityPublicKey string `json:"reality_public_key"`
		RealityShortID   string `json:"reality_short_id"`
		SpiderX          string `json:"spider_x"`
		SourceInboundID  string `json:"source_inbound_id"`
	}
	_ = json.Unmarshal([]byte(row.SettingsJSON), &s)
	transport := s.Transport
	if strings.EqualFold(row.Protocol, "shadowsocks") {
		transport = inboundcfg.EffectiveSSNetwork(inboundcfg.Settings{Transport: s.Transport, SSNetwork: s.SSNetwork})
	}
	return map[string]any{
		"id":                 row.ID,
		"node_uuid":          row.NodeUUID,
		"core":               row.Core,
		"name":               row.Name,
		"protocol":           row.Protocol,
		"enabled":            row.Enabled,
		"revision":           row.Revision,
		"created_at":         row.CreatedAt,
		"updated_at":         row.UpdatedAt,
		"address":            s.Address,
		"dest_port":          s.Port,
		"username":           s.Username,
		"password":           s.Password,
		"uuid":               s.UUID,
		"flow":               s.Flow,
		"domain_strategy":    s.DomainStrategy,
		"transport":          transport,
		"security":           s.Security,
		"sni":                s.SNI,
		"fingerprint":        s.Fingerprint,
		"ws_path":            s.WSPath,
		"ws_host":            s.WSHost,
		"grpc_service":       s.GRPCService,
		"ss_method":          s.SSMethod,
		"via_outbound":       s.ViaOutbound,
		"reality_public_key": s.RealityPublicKey,
		"reality_short_id":   s.RealityShortID,
		"spider_x":           s.SpiderX,
		"source_inbound_id":  s.SourceInboundID,
		"settings_json":      row.SettingsJSON,
	}
}

func nodemgtOutboundUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		models.Outbound
		Address          string `json:"address"`
		DestPort         int    `json:"dest_port"`
		Username         string `json:"username"`
		Password         string `json:"password"`
		UUID             string `json:"uuid"`
		Flow             string `json:"flow"`
		DomainStrategy   string `json:"domain_strategy"`
		Transport        string `json:"transport"`
		Security         string `json:"security"`
		SNI              string `json:"sni"`
		Fingerprint      string `json:"fingerprint"`
		WSPath           string `json:"ws_path"`
		WSHost           string `json:"ws_host"`
		GRPCService      string `json:"grpc_service"`
		SSMethod         string `json:"ss_method"`
		ViaOutbound      string `json:"via_outbound"`
		RealityPublicKey string `json:"reality_public_key"`
		RealityShortID   string `json:"reality_short_id"`
		SpiderX          string `json:"spider_x"`
		SourceInboundID  string `json:"source_inbound_id"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.NodeUUID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "name and node required", nil)
	}
	if p.Protocol == "" {
		p.Protocol = "freedom"
	}
	if strings.EqualFold(p.Protocol, "anytls") {
		p.Core = models.CoreSingBox
		p.Transport = "tcp"
		if strings.TrimSpace(p.Security) == "" || strings.EqualFold(p.Security, "none") {
			p.Security = "tls"
		}
	}
	cfgMap := map[string]any{
		"address":            p.Address,
		"port":               p.DestPort,
		"username":           p.Username,
		"password":           p.Password,
		"uuid":               p.UUID,
		"flow":               p.Flow,
		"domain_strategy":    p.DomainStrategy,
		"transport":          p.Transport,
		"security":           p.Security,
		"sni":                p.SNI,
		"fingerprint":        p.Fingerprint,
		"ws_path":            p.WSPath,
		"ws_host":            p.WSHost,
		"grpc_service":       p.GRPCService,
		"via_outbound":       p.ViaOutbound,
		"reality_public_key": p.RealityPublicKey,
		"reality_short_id":   p.RealityShortID,
		"spider_x":           p.SpiderX,
		"source_inbound_id":  p.SourceInboundID,
	}
	if strings.EqualFold(p.Protocol, "shadowsocks") {
		method := strings.TrimSpace(p.SSMethod)
		if method == "" {
			method = inboundcfg.DefaultSSMethod()
		}
		cfgMap["ss_method"] = method
		cfgMap["ss_network"] = inboundcfg.NormalizeSSNetwork(p.Transport)
		cfgMap["transport"] = "tcp"
	}
	cfg, _ := json.Marshal(cfgMap)
	p.SettingsJSON = string(cfg)
	st := nodemgtST()
	if err := st.UpsertOutbound(&p.Outbound); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.outbound.upsert", p.ID, p.Name)
	nodemgtPush(st, p.NodeUUID)
	return outboundView(p.Outbound), nil
}

func nodemgtOutboundDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	row, err := st.GetOutbound(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.DeleteOutbound(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.outbound.delete", p.ID, row.Name)
	nodemgtPush(st, row.NodeUUID)
	return map[string]any{"ok": true}, nil
}

func nodemgtRouteList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListRoutes(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, routeView(row))
	}
	return out, nil
}

func routeView(row models.Route) map[string]any {
	var s struct {
		InboundID  string `json:"inbound_id"`
		OutboundID string `json:"outbound_id"`
		Domain     string `json:"domain"`
		IP         string `json:"ip"`
		Network    string `json:"network"`
		Protocol   string `json:"protocol"`
		Port       string `json:"port"`
		Source     string `json:"source"`
	}
	_ = json.Unmarshal([]byte(row.RuleJSON), &s)
	return map[string]any{
		"id":          row.ID,
		"node_uuid":   row.NodeUUID,
		"name":        row.Name,
		"priority":    row.Priority,
		"enabled":     row.Enabled,
		"revision":    row.Revision,
		"created_at":  row.CreatedAt,
		"updated_at":  row.UpdatedAt,
		"inbound_id":  s.InboundID,
		"outbound_id": s.OutboundID,
		"domain":      s.Domain,
		"ip":          s.IP,
		"network":     s.Network,
		"protocol":    s.Protocol,
		"port":        s.Port,
		"source":      s.Source,
		"rule_json":   row.RuleJSON,
	}
}

func nodemgtRouteUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		models.Route
		InboundID  string `json:"inbound_id"`
		OutboundID string `json:"outbound_id"`
		Domain     string `json:"domain"`
		IP         string `json:"ip"`
		Network    string `json:"network"`
		Protocol   string `json:"protocol"`
		Port       string `json:"port"`
		Source     string `json:"source"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.NodeUUID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "name and node required", nil)
	}
	if strings.TrimSpace(p.OutboundID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "outbound required", nil)
	}
	rule, _ := json.Marshal(map[string]any{
		"inbound_id":  p.InboundID,
		"outbound_id": p.OutboundID,
		"domain":      p.Domain,
		"ip":          p.IP,
		"network":     p.Network,
		"protocol":    p.Protocol,
		"port":        p.Port,
		"source":      p.Source,
	})
	p.RuleJSON = string(rule)
	row := p.Route
	st := nodemgtST()
	if err := st.UpsertRoute(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.route.upsert", row.ID, row.Name)
	nodemgtPush(st, row.NodeUUID)
	return routeView(row), nil
}

func nodemgtRouteDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	row, err := st.GetRoute(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.DeleteRoute(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.route.delete", p.ID, row.Name)
	nodemgtPush(st, row.NodeUUID)
	return map[string]any{"ok": true}, nil
}

func nodemgtUserList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	if _, err := nodemgtOps().SyncDueTrafficResets(time.Now().UTC()); err != nil {
		logger.Warnf("nodemgt", "traffic reset sync: %v", err)
	}
	rows, err := nodemgtST().ListUserViews(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return rows, nil
}

func parseOptionalJSONTime(raw json.RawMessage) (*time.Time, bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, false, nil
	}
	if trimmed == "null" {
		return nil, true, nil
	}
	var at time.Time
	if err := json.Unmarshal(raw, &at); err != nil {
		return nil, false, err
	}
	return &at, true, nil
}

func nodemgtUserUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		models.NodeUser
		ExpiresAt  json.RawMessage         `json:"expires_at"`
		InboundIDs []string                `json:"inbound_ids"`
		PlanID     string                  `json:"plan_id"`
		ExtraLinks *[]models.UserExtraLink `json:"extra_links"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	resetDay := p.TrafficResetDay
	if resetDay < 0 || resetDay > 31 {
		return nil, rpc.MakeError(rpc.InvalidParams, "traffic_reset_day must be 0-31", nil)
	}
	expires, expiresSet, err := parseOptionalJSONTime(p.ExpiresAt)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "invalid expires_at", nil)
	}
	db := dbcore.GetDBInstance()
	isNew := strings.TrimSpace(p.ID) == ""
	before, _ := store.New(db).NodeIDsForUser(p.ID)
	hadPlan := false
	if !isNew {
		if asg, err := store.New(db).ListAssignments(p.ID); err == nil {
			hadPlan = len(asg) > 0
		}
	}
	issuedSecret := ""
	actor := nodemgtActor(ctx)
	if txErr := db.Transaction(func(tx *gorm.DB) error {
		st := store.New(tx)
		if len(p.InboundIDs) > 0 {
			in, err := st.ListInbounds("")
			if err != nil {
				return err
			}
			byID := map[string]models.Inbound{}
			for _, row := range in {
				byID[row.ID] = row
			}
			if first, ok := byID[p.InboundIDs[0]]; ok {
				p.NodeUUID = first.NodeUUID
			}
		}
		planID := strings.TrimSpace(p.PlanID)
		if planID != "" {
			if plan, err := st.GetPlan(planID); err == nil && plan != nil {
				p.RateLimitBps = plan.RateLimitBps
			}
		}
		if err := st.SaveUserProfile(&p.NodeUser); err != nil {
			return err
		}
		if err := st.ReplaceGrants(p.ID, p.InboundIDs); err != nil {
			return err
		}
		svc := ops.New(st)
		if planID != "" {
			asg, _ := st.ListAssignments(p.ID)
			if len(asg) == 0 || asg[0].PlanID != planID {
				if _, err := svc.Assign(actor, p.ID, planID, "", time.Now().UTC()); err != nil {
					return err
				}
			}
		} else if nodemgtShouldClearPlan(planID, hadPlan) {
			if err := svc.Unassign(actor, p.ID, ""); err != nil {
				return err
			}
		}
		expiry := expires
		if !expiresSet {
			if user, err := st.GetUser(p.ID); err == nil {
				expiry = user.ExpiresAt
			}
		}
		if err := st.SetUserExpiryAndReset(p.ID, expiry, resetDay, time.Now().UTC()); err != nil {
			return err
		}
		if _, err := st.EnsureSubscription(p.ID); err != nil {
			return err
		}
		if p.ExtraLinks != nil {
			if err := st.ReplaceUserExtraLinks(p.ID, *p.ExtraLinks); err != nil {
				return err
			}
		}
		if isNew {
			_, secret, err := st.IssueCredential(p.ID, "uuid", "", nil)
			if err != nil {
				return err
			}
			issuedSecret = secret
		}
		return st.Audit(actor, "nodemgt.user.upsert", p.ID, p.Username)
	}); txErr != nil {
		return nil, nodemgtErr(txErr)
	}
	st := store.New(db)
	after, _ := st.NodeIDsForUser(p.ID)
	nodemgtPushNodes(st, append(append([]string{}, before...), after...)...)
	view, err := st.GetUserView(p.ID)
	if err != nil {
		return map[string]any{"id": p.ID, "secret": issuedSecret}, nil
	}
	return struct {
		store.UserView
		Secret string `json:"secret,omitempty"`
	}{UserView: *view, Secret: issuedSecret}, nil
}

func nodemgtUserClearIPs(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	if _, err := st.GetUser(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.ClearUserIPs(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.user.clearIPs", p.ID, "")
	return map[string]any{"ok": true}, nil
}

func nodemgtUserDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	user, err := st.GetUser(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	nodes, _ := st.NodeIDsForUser(p.ID)
	if err := st.DeleteUser(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.user.delete", p.ID, user.Username)
	nodemgtPushNodes(st, append(nodes, user.NodeUUID)...)
	return map[string]any{"ok": true}, nil
}

func nodemgtUserSetStatus(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID          string `json:"id"`
		Status      string `json:"status"`
		OperationID string `json:"operation_id"`
	}
	_ = req.BindParams(&p)
	if p.Status == models.UserDisabled {
		if err := nodemgtOps().Disable(nodemgtActor(ctx), p.ID, p.OperationID); err != nil {
			return nil, nodemgtErr(err)
		}
	} else if err := nodemgtST().SetUserStatus(p.ID, p.Status); err != nil {
		return nil, nodemgtErr(err)
	}
	user, err := nodemgtST().GetUser(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	nodemgtPushUser(nodemgtST(), user.ID)
	return user, nil
}

func nodemgtCredentialIssue(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		UserID string `json:"user_id"`
		Kind   string `json:"kind"`
		Secret string `json:"secret"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	kind := strings.TrimSpace(p.Kind)
	if kind == "" {
		kind = "uuid"
	}
	if strings.TrimSpace(p.Secret) == "" {
		if creds, err := st.ListCredentials(p.UserID); err == nil {
			for _, cred := range creds {
				if !cred.Enabled || !strings.EqualFold(cred.Kind, kind) {
					continue
				}
				plain, openErr := secretcrypt.Open(cred.SecretMaterial)
				if openErr != nil || strings.TrimSpace(plain) == "" {
					continue
				}
				return map[string]any{"credential": cred, "secret": plain}, nil
			}
		}
	}
	cred, secret, err := st.IssueCredential(p.UserID, kind, p.Secret, nil)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.credential.issue", cred.ID, p.UserID)
	nodemgtPushUser(st, p.UserID)
	return map[string]any{"credential": cred, "secret": secret}, nil
}

func nodemgtCredentialRotate(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	cred, secret, err := nodemgtST().RotateCredential(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	_ = nodemgtST().Audit(nodemgtActor(ctx), "nodemgt.credential.rotate", cred.ID, "")
	nodemgtPushUser(nodemgtST(), cred.UserID)
	return map[string]any{"credential": cred, "secret": secret}, nil
}

func nodemgtCredentialRevoke(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	cred, err := st.GetCredential(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.RevokeCredential(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.credential.revoke", p.ID, "")
	nodemgtPushUser(st, cred.UserID)
	return map[string]any{"ok": true}, nil
}

func nodemgtPlanList(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	rows, err := nodemgtST().ListPlans()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return rows, nil
}

func nodemgtPlanUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var row models.Plan
	if err := req.BindParams(&row); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	st := nodemgtST()
	prevDuration := 0
	if strings.TrimSpace(row.ID) != "" {
		if existing, err := st.GetPlan(row.ID); err == nil && existing != nil {
			prevDuration = existing.DurationDays
		}
	}
	if err := st.UpsertPlan(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	affected, err := nodemgtOps().ApplyPlanToAssignees(nodemgtActor(ctx), row.ID, "", time.Now().UTC(), prevDuration)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	for _, userID := range affected {
		nodemgtPushUser(st, userID)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.plan.upsert", row.ID, row.Name)
	return row, nil
}

func nodemgtPlanDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	affected, err := nodemgtOps().UnassignPlan(nodemgtActor(ctx), p.ID, "")
	if err != nil {
		return nil, nodemgtErr(err)
	}
	for _, userID := range affected {
		nodemgtPushUser(st, userID)
	}
	if err := st.DeletePlan(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{"ok": true}, nil
}

func nodemgtAssign(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		UserID      string `json:"user_id"`
		PlanID      string `json:"plan_id"`
		OperationID string `json:"operation_id"`
	}
	_ = req.BindParams(&p)
	asg, err := nodemgtOps().Assign(nodemgtActor(ctx), p.UserID, p.PlanID, p.OperationID, time.Now().UTC())
	if err != nil {
		return nil, nodemgtErr(err)
	}
	nodemgtPushUser(nodemgtST(), p.UserID)
	return asg, nil
}

func nodemgtRenew(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		UserID      string `json:"user_id"`
		OperationID string `json:"operation_id"`
	}
	_ = req.BindParams(&p)
	asg, err := nodemgtOps().Renew(nodemgtActor(ctx), p.UserID, p.OperationID, time.Now().UTC())
	if err != nil {
		return nil, nodemgtErr(err)
	}
	nodemgtPushUser(nodemgtST(), p.UserID)
	return asg, nil
}

func nodemgtTopup(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		UserID      string `json:"user_id"`
		OperationID string `json:"operation_id"`
		ExtraBytes  int64  `json:"extra_bytes"`
	}
	_ = req.BindParams(&p)
	if err := nodemgtOps().Topup(nodemgtActor(ctx), p.UserID, p.OperationID, p.ExtraBytes); err != nil {
		return nil, nodemgtErr(err)
	}
	nodemgtPushUser(nodemgtST(), p.UserID)
	return map[string]any{"ok": true}, nil
}

func nodemgtModify(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		UserID      string `json:"user_id"`
		OperationID string `json:"operation_id"`
		QuotaBytes  *int64 `json:"quota_bytes"`
		RateLimit   *int64 `json:"rate_limit_bps"`
		Devices     *int   `json:"device_limit"`
	}
	_ = req.BindParams(&p)
	if err := nodemgtOps().Modify(nodemgtActor(ctx), p.UserID, p.OperationID, p.QuotaBytes, p.RateLimit, p.Devices, nil); err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{"ok": true}, nil
}

func nodemgtCertList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListCerts(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return rows, nil
}

func nodemgtRootCertList(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	rows, err := nodemgtST().ListRootCerts()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, rootCertView(row))
	}
	return out, nil
}

func nodemgtRootCertIssue(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
		TestCA bool   `json:"test_ca"`
		Sync   bool   `json:"sync"`
	}
	_ = req.BindParams(&p)
	domain := cert.RootDomain(p.Domain)
	if domain == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "domain required", nil)
	}
	st := nodemgtST()
	if !p.TestCA {
		token, _ := st.GetSetting("cf_api_token")
		email, _ := st.GetSetting("acme_email")
		if strings.TrimSpace(token) == "" {
			return nil, rpc.MakeError(rpc.InvalidParams, "cloudflare api token missing", nil)
		}
		if strings.TrimSpace(email) == "" {
			return nil, rpc.MakeError(rpc.InvalidParams, "acme email required", nil)
		}
	}
	row := models.RootCertificate{
		ID:     p.ID,
		Domain: domain,
		Status: models.CertPending,
	}
	if p.ID != "" {
		if existing, err := st.GetRootCert(p.ID); err == nil && existing != nil {
			row = *existing
			row.Domain = domain
			row.Status = models.CertPending
			row.LastError = ""
		}
	} else if existing, err := st.GetRootCertByDomain(domain); err == nil && existing != nil {
		row = *existing
		row.Status = models.CertPending
		row.LastError = ""
	}
	if err := st.UpsertRootCert(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.root_cert.issue", row.ID, domain)
	if p.Sync || p.TestCA {
		if err := control.IssueRootCert(ctx, st, &row, p.TestCA); err != nil {
			return rootCertView(row), nodemgtErr(err)
		}
		latest, err := st.GetRootCert(row.ID)
		if err != nil {
			return rootCertView(row), nil
		}
		return rootCertView(*latest), nil
	}
	go issueRootCertAsync(row.ID, p.TestCA)
	return rootCertView(row), nil
}

func issueRootCertAsync(id string, testCA bool) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Errorf("nodemgt", "root cert issue: %v", rec)
		}
	}()
	st := store.New(dbcore.GetDBInstance())
	row, err := st.GetRootCert(id)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := control.IssueRootCert(ctx, st, row, testCA); err != nil {
		logger.Warnf("nodemgt", "root cert issue %s: %v", id, err)
	}
}

func nodemgtRootCertDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	if strings.TrimSpace(p.ID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id required", nil)
	}
	st := nodemgtST()
	row, err := st.GetRootCert(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.DeleteRootCert(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.root_cert.delete", p.ID, row.Domain)
	return map[string]any{"ok": true}, nil
}

func rootCertView(row models.RootCertificate) map[string]any {
	return map[string]any{
		"id":          row.ID,
		"domain":      row.Domain,
		"fingerprint": row.Fingerprint,
		"issuer":      row.Issuer,
		"not_after":   row.NotAfter,
		"auto_renew":  row.AutoRenew,
		"status":      row.Status,
		"last_error":  row.LastError,
		"created_at":  row.CreatedAt,
		"updated_at":  row.UpdatedAt,
	}
}

func nodemgtRootCertSetAutoRenew(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID        string `json:"id"`
		AutoRenew bool   `json:"auto_renew"`
	}
	_ = req.BindParams(&p)
	if strings.TrimSpace(p.ID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id required", nil)
	}
	st := nodemgtST()
	row, err := st.GetRootCert(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	row.AutoRenew = p.AutoRenew
	if err := st.UpsertRootCert(row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.root_cert.set_auto_renew", row.ID, row.Domain)
	return rootCertView(*row), nil
}

func nodemgtCertSetAutoRenew(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID        string `json:"id"`
		AutoRenew bool   `json:"auto_renew"`
	}
	_ = req.BindParams(&p)
	if strings.TrimSpace(p.ID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id required", nil)
	}
	st := nodemgtST()
	row, err := st.GetCert(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	row.AutoRenew = p.AutoRenew
	if err := st.UpsertCert(row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.cert.set_auto_renew", row.ID, row.Domain)
	return row, nil
}

func nodemgtCertRequest(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID            string `json:"id"`
		NodeUUID      string `json:"node_uuid"`
		Domain        string `json:"domain"`
		RootCertID    string `json:"root_cert_id"`
		ShareDomain   string `json:"share_domain"`
		CoverWildcard *bool  `json:"cover_wildcard"`
		CSRPEM        string `json:"csr_pem"`
		TestCA        bool   `json:"test_ca"`
		Source        string `json:"source"`
		CertPath      string `json:"cert_path"`
		KeyPath       string `json:"key_path"`
	}
	_ = req.BindParams(&p)
	if strings.TrimSpace(p.NodeUUID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "domain and node required", nil)
	}
	st := nodemgtST()
	source := strings.ToLower(strings.TrimSpace(p.Source))
	if source == "" && strings.TrimSpace(p.RootCertID) != "" {
		source = models.CertSourceRoot
	}
	if source == "" && (strings.TrimSpace(p.CertPath) != "" || strings.TrimSpace(p.KeyPath) != "") {
		source = models.CertSourceFile
	}
	if source == models.CertSourceRoot {
		root, err := st.GetRootCert(p.RootCertID)
		if err != nil {
			return nil, nodemgtErr(err)
		}
		row := models.Certificate{ID: p.ID, NodeUUID: p.NodeUUID}
		if p.ID != "" {
			if existing, err := st.GetCert(p.ID); err == nil && existing != nil {
				row = *existing
				row.NodeUUID = p.NodeUUID
			}
		}
		if err := control.DeployRootToNode(st, root, &row, p.ShareDomain); err != nil {
			return nil, nodemgtErr(err)
		}
		_ = st.Audit(nodemgtActor(ctx), "nodemgt.cert.deploy_root", row.ID, row.ShareDomain)
		nodemgtPush(st, row.NodeUUID)
		return row, nil
	}
	if strings.TrimSpace(p.Domain) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "domain and node required", nil)
	}
	cover := cert.DefaultCoverWildcard(p.Domain)
	if p.CoverWildcard != nil {
		cover = *p.CoverWildcard
	}
	row := models.Certificate{
		ID:            p.ID,
		NodeUUID:      p.NodeUUID,
		Domain:        cert.NormalizeDomain(p.Domain),
		ShareDomain:   cert.NormalizeDomain(p.ShareDomain),
		CoverWildcard: cover && source != models.CertSourceFile,
		Status:        models.CertPending,
	}
	if p.ID != "" {
		if existing, err := st.GetCert(p.ID); err == nil && existing != nil {
			row = *existing
			row.Domain = cert.NormalizeDomain(p.Domain)
			row.NodeUUID = p.NodeUUID
			row.ShareDomain = cert.NormalizeDomain(p.ShareDomain)
			if source != models.CertSourceFile {
				row.CoverWildcard = cover
			}
			if row.Status != models.CertIssued {
				row.Status = models.CertPending
			}
			row.LastError = ""
		}
	}
	if source == models.CertSourceFile {
		row.CertPath = p.CertPath
		row.KeyPath = p.KeyPath
		if err := control.BindFileCert(st, &row); err != nil {
			return nil, nodemgtErr(err)
		}
		_ = st.Audit(nodemgtActor(ctx), "nodemgt.cert.bind_file", row.ID, p.Domain)
		return row, nil
	}
	row.Source = models.CertSourceACME
	row.CertPath = ""
	row.KeyPath = ""
	if strings.TrimSpace(p.CSRPEM) == "" {
		if err := control.RequestACME(st, &row, p.TestCA); err != nil {
			return nil, nodemgtErr(err)
		}
		return row, nil
	}
	if err := st.UpsertCert(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	var issued *cert.Result
	var err error
	if p.TestCA {
		issued, err = cert.IssueLocalTestCA(p.Domain, p.CSRPEM)
	} else {
		token, _ := st.GetSetting("cf_api_token")
		email, _ := st.GetSetting("acme_email")
		issued, err = cert.IssueACME(ctx, cert.Request{
			Domain:        row.Domain,
			Names:         cert.IssueNames(row.Domain, row.CoverWildcard),
			CoverWildcard: row.CoverWildcard,
			Email:         email,
			CSRPEM:        p.CSRPEM,
			CF:            cert.Cloudflare{APIToken: token},
		})
	}
	if err != nil {
		row.Status = models.CertFailed
		row.LastError = err.Error()
		_ = st.UpsertCert(&row)
		return nil, nodemgtErr(err)
	}
	if err := control.ApplyIssuedCert(st, &row, issued, p.Domain); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.cert.issue", row.ID, p.Domain)
	return row, nil
}

func nodemgtCertDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	if strings.TrimSpace(p.ID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "id required", nil)
	}
	st := nodemgtST()
	row, err := st.GetCert(p.ID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	if err := st.DeleteCert(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.cert.delete", p.ID, row.Domain)
	nodemgtPush(st, row.NodeUUID)
	return map[string]any{"ok": true}, nil
}

func nodemgtSubList(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	st := nodemgtST()
	users, err := st.ListUsers("")
	if err != nil {
		return nil, nodemgtErr(err)
	}
	byUser := map[string]models.NodeUser{}
	for _, user := range users {
		byUser[user.ID] = user
		if _, err := st.EnsureSubscription(user.ID); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	rows, err := st.ListSubscriptions()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	cfg, err := subhttp.LoadConfig(st)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id":          row.ID,
			"user_id":     row.UserID,
			"token":       row.Token,
			"format":      row.Format,
			"auto_detect": row.AutoDetect,
			"extra_urls":  row.ExtraURLs,
			"enabled":     row.Enabled,
			"created_at":  row.CreatedAt,
			"updated_at":  row.UpdatedAt,
			"path":        subhttp.NormalizePath(cfg.Path) + row.Token,
			"url":         subhttp.PublicURL(cfg, row.Token),
		}
		if user, ok := byUser[row.UserID]; ok {
			item["username"] = user.Username
		}
		out = append(out, item)
	}
	return out, nil
}

func nodemgtSubUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var row models.Subscription
	if err := req.BindParams(&row); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if strings.TrimSpace(row.UserID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "user required", nil)
	}
	st := nodemgtST()
	if row.ID == "" {
		if existing, err := st.GetSubscriptionByUser(row.UserID); err == nil && existing != nil {
			row.ID = existing.ID
			if row.Token == "" {
				row.Token = existing.Token
			}
		}
	}
	if _, err := subtpl.NormalizeClient(row.Format); row.Format != "" && err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if err := st.UpsertSubscription(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.subscription.upsert", row.ID, "")
	return row, nil
}

func nodemgtSubDelete(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	_ = req.BindParams(&p)
	if err := nodemgtST().DeleteSubscription(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{"ok": true}, nil
}

func nodemgtSubPreview(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID        string `json:"id"`
		Format    string `json:"format"`
		Target    string `json:"target"`
		UserAgent string `json:"user_agent"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	var row models.Subscription
	list, err := st.ListSubscriptions()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	for i := range list {
		if list[i].ID == p.ID {
			row = list[i]
			break
		}
	}
	if row.ID == "" {
		return nil, nodemgtErr(store.ErrNotFound)
	}
	doc, err := subhttp.Generate(st, row, subhttp.GenerateRequest{Target: p.Target, Format: p.Format, UserAgent: p.UserAgent})
	if err != nil {
		return nil, nodemgtErr(err)
	}
	cfg, err := subhttp.LoadConfig(st)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{
		"body":         doc.Body,
		"content_type": doc.ContentType,
		"client":       doc.Client,
		"template_id":  doc.TemplateID,
		"warnings":     doc.Warnings,
		"token":        row.Token,
		"path":         subhttp.NormalizePath(cfg.Path) + row.Token,
		"url":          subhttp.PublicURL(cfg, row.Token),
	}, nil
}

func nodemgtAuditList(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		Limit int `json:"limit"`
	}
	_ = req.BindParams(&p)
	rows, err := nodemgtST().ListAudit(p.Limit)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		target := strings.TrimSpace(row.Detail)
		if target == "" {
			target = row.Target
		}
		out = append(out, map[string]any{
			"id":         row.ID,
			"actor":      nodemgtActorName(row.Actor),
			"action":     row.Action,
			"target":     target,
			"created_at": row.CreatedAt,
		})
	}
	return out, nil
}

func nodemgtControlStatus(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	if strings.TrimSpace(p.NodeUUID) != "" {
		pending, err := st.PendingCommands(p.NodeUUID)
		if err != nil {
			return nil, nodemgtErr(err)
		}
		latest, err := st.LatestCommands()
		if err != nil {
			return nil, nodemgtErr(err)
		}
		for _, cmd := range latest {
			if cmd.NodeUUID == p.NodeUUID {
				return nodemgtCommandView(cmd), nil
			}
		}
		if len(pending) > 0 {
			return nodemgtCommandView(pending[len(pending)-1]), nil
		}
		return map[string]any{"node_uuid": p.NodeUUID, "status": "not_started"}, nil
	}
	rows, err := st.LatestCommands()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, nodemgtCommandView(row))
	}
	return out, nil
}

func nodemgtControlSync(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	if err := control.PushPending(nodemgtST(), p.NodeUUID); err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{"ok": true}, nil
}

func nodemgtDiagStatus(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID string `json:"node_uuid"`
	}
	_ = req.BindParams(&p)
	st := nodemgtST()
	pending, err := st.PendingCommands(p.NodeUUID)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	latest, err := st.LatestCommands()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	commands := make([]map[string]any, 0, len(latest))
	for _, cmd := range latest {
		if p.NodeUUID != "" && cmd.NodeUUID != p.NodeUUID {
			continue
		}
		commands = append(commands, nodemgtCommandView(cmd))
	}
	return map[string]any{
		"pending_commands": pending,
		"commands":         commands,
		"cores":            []string{models.CoreXray, models.CoreSingBox},
		"xray_version":     "v26.6.27",
		"singbox_version":  "v1.14.3",
	}, nil
}

func nodemgtSettingsGet(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	st := nodemgtST()
	token, _ := st.GetSetting("cf_api_token")
	email, _ := st.GetSetting("acme_email")
	cfg, err := subhttp.LoadConfig(st)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	httpsCert, httpsKey, httpsDomains := subhttp.PanelCertificate()
	publishName, publishUserinfo := subhttp.MetadataPublishFlags(st)
	return map[string]any{
		"cf_api_token_set":       strings.TrimSpace(token) != "",
		"acme_email":             email,
		"sub_listen_port":        cfg.ListenPort,
		"sub_public_port":        cfg.PublicPort,
		"sub_path":               cfg.Path,
		"sub_public_host":        cfg.PublicHost,
		"sub_domain":             cfg.Domain,
		"sub_reuse_https":        cfg.ReuseHTTPS,
		"sub_publish_name":       publishName,
		"sub_publish_userinfo":   publishUserinfo,
		"https_certificate_path": httpsCert,
		"https_private_key_path": httpsKey,
		"https_domains":          httpsDomains,
	}, nil
}

func nodemgtSettingsSet(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		CFAPIToken         string  `json:"cf_api_token"`
		ClearIssuer        *bool   `json:"clear_issuer"`
		ACMEEmail          *string `json:"acme_email"`
		SubListenPort      *int    `json:"sub_listen_port"`
		SubPublicPort      *int    `json:"sub_public_port"`
		SubPath            *string `json:"sub_path"`
		SubPublicHost      *string `json:"sub_public_host"`
		SubReuseHTTPS      *bool   `json:"sub_reuse_https"`
		SubPublishName     *bool   `json:"sub_publish_name"`
		SubPublishUserinfo *bool   `json:"sub_publish_userinfo"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	st := nodemgtST()
	if p.ClearIssuer != nil && *p.ClearIssuer {
		if err := st.DeleteSetting("cf_api_token"); err != nil {
			return nil, nodemgtErr(err)
		}
		if err := st.DeleteSetting("acme_email"); err != nil {
			return nil, nodemgtErr(err)
		}
	} else {
		if token := strings.TrimSpace(p.CFAPIToken); token != "" {
			if err := st.SetSetting("cf_api_token", token); err != nil {
				return nil, nodemgtErr(err)
			}
		}
		if p.ACMEEmail != nil {
			email := strings.TrimSpace(*p.ACMEEmail)
			if email == "" {
				return nil, rpc.MakeError(rpc.InvalidParams, "acme email required", nil)
			}
			storedToken, _ := st.GetSetting("cf_api_token")
			if strings.TrimSpace(storedToken) == "" {
				return nil, rpc.MakeError(rpc.InvalidParams, "cloudflare api token required", nil)
			}
			if err := st.SetSetting("acme_email", email); err != nil {
				return nil, nodemgtErr(err)
			}
		}
	}
	restartSub := p.SubListenPort != nil || p.SubPath != nil || p.SubReuseHTTPS != nil
	if p.SubListenPort != nil {
		port := *p.SubListenPort
		if port < 0 || port > 65535 {
			return nil, rpc.MakeError(rpc.InvalidParams, "invalid subscription port", nil)
		}
		if err := st.SetSetting("sub_listen_port", strconv.Itoa(port)); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubPublicPort != nil {
		port := *p.SubPublicPort
		if port < 0 || port > 65535 {
			return nil, rpc.MakeError(rpc.InvalidParams, "invalid reverse proxy port", nil)
		}
		if err := st.SetSetting("sub_public_port", strconv.Itoa(port)); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubPath != nil {
		path := subhttp.NormalizePath(*p.SubPath)
		if path == "/" {
			return nil, rpc.MakeError(rpc.InvalidParams, "subscription path required", nil)
		}
		if err := st.SetSetting("sub_path", path); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubPublicHost != nil {
		if err := st.SetSetting("sub_public_host", strings.TrimSpace(*p.SubPublicHost)); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubReuseHTTPS != nil {
		if err := st.SetSetting("sub_reuse_https", strconv.FormatBool(*p.SubReuseHTTPS)); err != nil {
			return nil, nodemgtErr(err)
		}
		for _, key := range []string{"sub_cert_path", "sub_key_path", "sub_domain"} {
			if err := st.SetSetting(key, ""); err != nil {
				return nil, nodemgtErr(err)
			}
		}
	}
	if p.SubPublishName != nil {
		if err := st.SetSetting(subhttp.SettingPublishName, strconv.FormatBool(*p.SubPublishName)); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubPublishUserinfo != nil {
		if err := st.SetSetting(subhttp.SettingPublishUserinfo, strconv.FormatBool(*p.SubPublishUserinfo)); err != nil {
			return nil, nodemgtErr(err)
		}
	}
	if p.SubPublicHost != nil || p.SubReuseHTTPS != nil || restartSub {
		cfg, err := subhttp.LoadConfig(st)
		if err != nil {
			return nil, nodemgtErr(err)
		}
		if err := cfg.ValidateTLS(); err != nil {
			return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
		}
		if restartSub {
			if err := subhttp.Apply(cfg); err != nil {
				return nil, nodemgtErr(err)
			}
		}
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.settings.set", "nodemgt", "")
	return nodemgtSettingsGet(ctx, req)
}

func nodemgtNodeList(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	rows, err := nodemgtST().ListNodeProfiles()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return rows, nil
}

func nodemgtNodeUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		NodeUUID  string `json:"node_uuid"`
		DialStack string `json:"dial_stack"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if strings.TrimSpace(p.NodeUUID) == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "node_uuid required", nil)
	}
	if _, err := clients.GetClientByUUID(p.NodeUUID); err != nil {
		return nil, nodemgtErr(err)
	}
	st := nodemgtST()
	row, err := st.UpsertNodeProfile(p.NodeUUID, p.DialStack)
	if err != nil {
		return nil, nodemgtErr(err)
	}
	_ = st.Audit(nodemgtActor(ctx), "nodemgt.node.upsert", p.NodeUUID, row.DialStack)
	nodemgtPush(st, p.NodeUUID)
	return row, nil
}
