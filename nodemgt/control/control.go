package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/cert"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/nodemgt/store"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
)

func EnqueueApplyConfig(st *store.Store, nodeUUID string) error {
	if strings.TrimSpace(nodeUUID) == "" {
		return nil
	}
	snap, err := st.NodeSnapshot(nodeUUID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return st.EnqueueCommand(&models.ControlCommand{
		NodeUUID:    nodeUUID,
		Kind:        "applyConfig",
		PayloadJSON: string(payload),
		Status:      models.CmdPending,
	})
}

func PushPending(st *store.Store, nodeUUID string) error {
	cmds, err := st.DueCommands(nodeUUID, 2*time.Minute)
	if err != nil {
		return err
	}
	for _, cmd := range cmds {
		PushCommand(st, cmd)
	}
	return nil
}

func commandPayloadJSON(cmd models.ControlCommand) string {
	if cmd.PayloadJSON == "" {
		return ""
	}
	plain, err := secretcrypt.Open(cmd.PayloadJSON)
	if err != nil {
		return cmd.PayloadJSON
	}
	return plain
}

func PushCommand(st *store.Store, cmd models.ControlCommand) {
	var payload any
	if raw := commandPayloadJSON(cmd); raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	queued := agent_runtime.DispatchV2Event(cmd.NodeUUID, v2.MethodNodemgtControl, map[string]any{
		"operation_id": cmd.OperationID,
		"kind":         cmd.Kind,
		"payload":      payload,
	})
	if st != nil && queued && agent_runtime.IsAgentOnline(cmd.NodeUUID) {
		_ = st.MarkCommandSent(cmd.OperationID)
	}
}

func Ack(st *store.Store, operationID, status, lastErr string) error {
	return st.AckCommand(operationID, status, lastErr)
}

type Result struct {
	NodeUUID    string
	OperationID string
	Status      string
	Error       string
	CSRPEM      string
	CertID      string
	Domain      string
	Fingerprint string
	Issuer      string
	NotAfter    *time.Time
}

func HandleResult(st *store.Store, r Result) error {
	if strings.TrimSpace(r.CSRPEM) == "" && strings.TrimSpace(r.CertID) != "" {
		if err := applyFileCertStatus(st, r); err != nil {
			return err
		}
	}
	if strings.TrimSpace(r.OperationID) == "" {
		if strings.TrimSpace(r.CertID) == "" {
			return fmt.Errorf("%w: operation_id", store.ErrInvalid)
		}
		return nil
	}
	cmd, err := st.GetCommand(r.OperationID)
	if err != nil {
		return err
	}
	if r.NodeUUID != "" && cmd.NodeUUID != r.NodeUUID {
		return store.ErrForbidden
	}
	if strings.TrimSpace(r.CSRPEM) != "" {
		if cmd.Kind != "needCSR" {
			return fmt.Errorf("%w: csr not allowed for %s", store.ErrInvalid, cmd.Kind)
		}
		if strings.EqualFold(r.Status, "failed") {
			return st.AckCommand(r.OperationID, r.Status, r.Error)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := completeCertFromCSR(ctx, st, *cmd, r.CSRPEM); err != nil {
			_ = st.AckCommand(r.OperationID, models.CmdFailed, err.Error())
			return err
		}
	}
	return st.AckCommand(r.OperationID, r.Status, r.Error)
}

func BindFileCert(st *store.Store, row *models.Certificate) error {
	if strings.TrimSpace(row.Domain) == "" || strings.TrimSpace(row.NodeUUID) == "" {
		return fmt.Errorf("%w: domain and node required", store.ErrInvalid)
	}
	if err := validAgentPath(row.CertPath); err != nil {
		return err
	}
	if err := validAgentPath(row.KeyPath); err != nil {
		return err
	}
	row.Source = models.CertSourceFile
	row.CertPath = strings.TrimSpace(row.CertPath)
	row.KeyPath = strings.TrimSpace(row.KeyPath)
	row.ChainPEM = ""
	row.Issuer = ""
	row.Fingerprint = ""
	row.NotAfter = nil
	row.Status = models.CertPending
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	if err := EnqueueApplyConfig(st, row.NodeUUID); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func validAgentPath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("%w: cert and key paths required", store.ErrInvalid)
	}
	if strings.ContainsRune(p, 0) || len(p) > 512 {
		return fmt.Errorf("%w: path", store.ErrInvalid)
	}
	return nil
}

func applyFileCertStatus(st *store.Store, r Result) error {
	row, err := st.GetCert(r.CertID)
	if err != nil {
		return err
	}
	if r.NodeUUID != "" && row.NodeUUID != r.NodeUUID {
		return store.ErrForbidden
	}
	if row.Source != models.CertSourceFile {
		return nil
	}
	if strings.EqualFold(r.Status, "failed") {
		row.Status = models.CertFailed
		row.LastError = r.Error
		return st.UpsertCert(row)
	}
	if r.Fingerprint != "" {
		row.Fingerprint = r.Fingerprint
	}
	if issuer := clipIssuer(r.Issuer); issuer != "" {
		row.Issuer = issuer
	}
	if r.NotAfter != nil {
		row.NotAfter = r.NotAfter
	}
	if r.Fingerprint != "" || r.NotAfter != nil {
		row.Status = models.CertIssued
		row.LastError = ""
	}
	return st.UpsertCert(row)
}

func clipIssuer(s string) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) > 64 {
		return string(runes[:64])
	}
	return s
}

func completeCertFromCSR(ctx context.Context, st *store.Store, cmd models.ControlCommand, csrPEM string) error {
	var payload struct {
		CertID        string   `json:"cert_id"`
		Domain        string   `json:"domain"`
		TestCA        bool     `json:"test_ca"`
		CoverWildcard bool     `json:"cover_wildcard"`
		DNSNames      []string `json:"dns_names"`
	}
	_ = json.Unmarshal([]byte(commandPayloadJSON(cmd)), &payload)
	certID, domain, testCA := payload.CertID, payload.Domain, payload.TestCA
	names := payload.DNSNames
	if len(names) == 0 {
		names = cert.IssueNames(domain, payload.CoverWildcard)
	}
	if err := csrMatchesTask(csrPEM, names); err != nil {
		return err
	}
	if certID == "" {
		return nil
	}
	row, err := st.GetCert(certID)
	if err != nil {
		return err
	}
	if cmd.NodeUUID != "" && row.NodeUUID != cmd.NodeUUID {
		return store.ErrForbidden
	}
	if domain == "" {
		domain = row.Domain
	}
	var issued *cert.Result
	if testCA {
		issued, err = cert.IssueLocalTestCA(domain, csrPEM)
	} else {
		token, _ := st.GetSetting("cf_api_token")
		email, _ := st.GetSetting("acme_email")
		issued, err = cert.IssueACME(ctx, cert.Request{
			Domain:        domain,
			Names:         names,
			CoverWildcard: payload.CoverWildcard,
			Email:         email,
			CSRPEM:        csrPEM,
			CF:            cert.Cloudflare{APIToken: token},
		})
	}
	if err != nil {
		row.Status = models.CertFailed
		row.LastError = err.Error()
		return st.UpsertCert(row)
	}
	return ApplyIssuedCert(st, row, issued, domain)
}

func RequestACME(st *store.Store, row *models.Certificate, testCA bool) error {
	if strings.TrimSpace(row.Domain) == "" || strings.TrimSpace(row.NodeUUID) == "" {
		return fmt.Errorf("%w: domain and node required", store.ErrInvalid)
	}
	if row.Source == models.CertSourceFile || row.Source == models.CertSourceRoot {
		return fmt.Errorf("%w: source", store.ErrInvalid)
	}
	row.Source = models.CertSourceACME
	row.CertPath = ""
	row.KeyPath = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	names := cert.IssueNames(row.Domain, row.CoverWildcard)
	payload, err := json.Marshal(map[string]any{
		"domain":         row.Domain,
		"cert_id":        row.ID,
		"test_ca":        testCA,
		"cover_wildcard": row.CoverWildcard,
		"dns_names":      names,
	})
	if err != nil {
		return err
	}
	if err := st.EnqueueCommand(&models.ControlCommand{
		NodeUUID:    row.NodeUUID,
		Kind:        "needCSR",
		PayloadJSON: string(payload),
	}); err != nil {
		return err
	}
	row.Status = models.CertPending
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func ApplyIssuedCert(st *store.Store, row *models.Certificate, issued *cert.Result, domain string) error {
	if domain == "" {
		domain = row.Domain
	}
	row.Status = models.CertIssued
	row.Source = models.CertSourceACME
	row.CertPath = ""
	row.KeyPath = ""
	row.ChainPEM = issued.ChainPEM
	row.Fingerprint = issued.Fingerprint
	row.Issuer = issued.Issuer
	row.NotAfter = &issued.NotAfter
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":    domain,
		"cert_id":   row.ID,
		"chain_pem": issued.ChainPEM,
	})
	if err != nil {
		return err
	}
	apply := &models.ControlCommand{
		NodeUUID:    row.NodeUUID,
		Kind:        "applyCert",
		PayloadJSON: string(payload),
	}
	if err := st.EnqueueCommand(apply); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func IssueRootCert(ctx context.Context, st *store.Store, row *models.RootCertificate, testCA bool) error {
	domain := cert.RootDomain(row.Domain)
	if domain == "" {
		return fmt.Errorf("%w: domain", store.ErrInvalid)
	}
	row.Domain = domain
	row.Status = models.CertPending
	row.LastError = ""
	if err := st.UpsertRootCert(row); err != nil {
		return err
	}
	token, _ := st.GetSetting("cf_api_token")
	email, _ := st.GetSetting("acme_email")
	keyPEM, issued, err := cert.IssueRoot(ctx, cert.RootIssue{
		Domain: domain,
		Email:  email,
		CF:     cert.Cloudflare{APIToken: token},
		TestCA: testCA,
	})
	if err != nil {
		row.Status = models.CertFailed
		row.LastError = err.Error()
		_ = st.UpsertRootCert(row)
		return err
	}
	sealed, err := secretcrypt.Seal(keyPEM)
	if err != nil {
		row.Status = models.CertFailed
		row.LastError = err.Error()
		_ = st.UpsertRootCert(row)
		return err
	}
	row.Status = models.CertIssued
	row.KeyPEM = sealed
	row.ChainPEM = issued.ChainPEM
	row.Fingerprint = issued.Fingerprint
	row.Issuer = issued.Issuer
	row.NotAfter = &issued.NotAfter
	row.LastError = ""
	if err := st.UpsertRootCert(row); err != nil {
		return err
	}
	children, err := st.ListCertsByRoot(row.ID)
	if err != nil {
		return err
	}
	for i := range children {
		if err := PushRootToNode(st, row, &children[i]); err != nil {
			return err
		}
	}
	return nil
}

func DeployRootToNode(st *store.Store, root *models.RootCertificate, row *models.Certificate, shareDomain string) error {
	if root == nil || strings.TrimSpace(root.ID) == "" {
		return fmt.Errorf("%w: root certificate required", store.ErrInvalid)
	}
	if !strings.EqualFold(root.Status, models.CertIssued) {
		return fmt.Errorf("%w: root certificate is not issued", store.ErrInvalid)
	}
	shareDomain = cert.NormalizeDomain(shareDomain)
	if shareDomain == "" {
		return fmt.Errorf("%w: subdomain required", store.ErrInvalid)
	}
	if !cert.HostCovered(root.Domain, shareDomain) {
		return fmt.Errorf("%w: subdomain must be %s or a name under it", store.ErrInvalid, root.Domain)
	}
	if strings.TrimSpace(row.NodeUUID) == "" {
		return fmt.Errorf("%w: node required", store.ErrInvalid)
	}
	row.RootCertID = root.ID
	row.Domain = root.Domain
	row.ShareDomain = shareDomain
	row.CoverWildcard = true
	row.Source = models.CertSourceRoot
	row.CertPath = ""
	row.KeyPath = ""
	row.ChainPEM = ""
	row.Fingerprint = root.Fingerprint
	row.Issuer = root.Issuer
	row.NotAfter = root.NotAfter
	row.Status = models.CertIssued
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	return PushRootToNode(st, root, row)
}

func PushRootToNode(st *store.Store, root *models.RootCertificate, row *models.Certificate) error {
	keyPEM, err := secretcrypt.Open(root.KeyPEM)
	if err != nil {
		return err
	}
	if strings.TrimSpace(keyPEM) == "" || strings.TrimSpace(root.ChainPEM) == "" {
		return fmt.Errorf("%w: root certificate material missing", store.ErrInvalid)
	}
	payload, err := json.Marshal(map[string]any{
		"domain":    cert.FileKey(root.Domain),
		"cert_id":   row.ID,
		"chain_pem": root.ChainPEM,
		"key_pem":   keyPEM,
	})
	if err != nil {
		return err
	}
	if err := st.EnqueueCommand(&models.ControlCommand{
		NodeUUID:    row.NodeUUID,
		Kind:        "applyCert",
		PayloadJSON: string(payload),
	}); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func csrMatchesTask(csrPEM string, names []string) error {
	if len(uniqueDNS(names)) == 0 {
		return fmt.Errorf("%w: domain", store.ErrInvalid)
	}
	if err := cert.CSRNamesMatch(csrPEM, names); err != nil {
		return fmt.Errorf("%w: %s", store.ErrForbidden, err.Error())
	}
	return nil
}

func uniqueDNS(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = cert.NormalizeDomain(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
