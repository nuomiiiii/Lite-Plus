package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/utils/instancekey"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	cleanup := instancekey.SetupTempFileForTest()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{NowFunc: func() time.Time { return time.Now().UTC() }})
	require.NoError(t, err)
	st := store.New(db)
	require.NoError(t, st.Migrate())
	return st
}

func testCSR(t *testing.T, domain string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
	}, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestHandleResultCompletesCSR(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "nodemgt.test", Status: models.CertPending}
	require.NoError(t, st.UpsertCert(row))
	cmd := &models.ControlCommand{
		OperationID: "op-csr",
		NodeUUID:    "n1",
		Kind:        "needCSR",
		PayloadJSON: `{"domain":"nodemgt.test","cert_id":"` + row.ID + `","test_ca":true}`,
	}
	require.NoError(t, st.EnqueueCommand(cmd))
	err := HandleResult(st, Result{
		OperationID: "op-csr",
		Status:      "applied",
		CSRPEM:      testCSR(t, "nodemgt.test"),
		CertID:      row.ID,
		Domain:      "nodemgt.test",
	})
	require.NoError(t, err)
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.NotEmpty(t, got.ChainPEM)
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	require.Equal(t, "applyCert", pending[0].Kind)
}

func TestHandleResultCompletesWildcardCSR(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "abc.com", CoverWildcard: true, ShareDomain: "hk.abc.com", Status: models.CertPending}
	require.NoError(t, st.UpsertCert(row))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "abc.com"}, DNSNames: []string{"abc.com", "*.abc.com"},
	}, key)
	require.NoError(t, err)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	cmd := &models.ControlCommand{
		OperationID: "op-wild",
		NodeUUID:    "n1",
		Kind:        "needCSR",
		PayloadJSON: `{"domain":"abc.com","cert_id":"` + row.ID + `","test_ca":true,"cover_wildcard":true,"dns_names":["abc.com","*.abc.com"]}`,
	}
	require.NoError(t, st.EnqueueCommand(cmd))
	require.NoError(t, HandleResult(st, Result{
		OperationID: "op-wild",
		Status:      "applied",
		CSRPEM:      csrPEM,
		CertID:      row.ID,
		Domain:      "abc.com",
	}))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.Equal(t, "hk.abc.com", got.ShareDomain)
	require.True(t, got.CoverWildcard)
}

func TestIssueRootAndDeployToNode(t *testing.T) {
	st := testStore(t)
	root := &models.RootCertificate{Domain: "abc.com"}
	require.NoError(t, IssueRootCert(context.Background(), st, root, true))
	got, err := st.GetRootCert(root.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.NotEmpty(t, got.KeyPEM)
	require.NotEmpty(t, got.ChainPEM)
	row := &models.Certificate{NodeUUID: "n1"}
	require.NoError(t, DeployRootToNode(st, got, row, "hk.abc.com"))
	saved, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertSourceRoot, saved.Source)
	require.Equal(t, "hk.abc.com", saved.ShareDomain)
	require.Equal(t, got.ID, saved.RootCertID)
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	require.Equal(t, "applyCert", pending[0].Kind)
	require.True(t, strings.HasPrefix(pending[0].PayloadJSON, "enc:v1:"))
}

func TestEnqueueApplyConfig(t *testing.T) {
	st := testStore(t)
	require.NoError(t, EnqueueApplyConfig(st, "n1"))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "applyConfig", pending[0].Kind)
	require.NoError(t, EnqueueApplyConfig(st, ""))
	pending, err = st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
}

func TestEnqueueApplyConfigSealsSecrets(t *testing.T) {
	st := testStore(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	_, plain, err := st.IssueCredential(user.ID, "trojan", "audit-protocol-secret", nil)
	require.NoError(t, err)
	require.NoError(t, EnqueueApplyConfig(st, "n1"))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, strings.HasPrefix(pending[0].PayloadJSON, "enc:v1:"))
	require.False(t, strings.Contains(pending[0].PayloadJSON, plain))
	opened, err := commandPayloadJSON(pending[0])
	require.NoError(t, err)
	require.Contains(t, opened, plain)
}

func TestHandleResultRejectsOtherNode(t *testing.T) {
	st := testStore(t)
	cmd := &models.ControlCommand{OperationID: "op-a", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(cmd))
	err := HandleResult(st, Result{NodeUUID: "n2", OperationID: "op-a", Status: "applied"})
	require.ErrorIs(t, err, store.ErrForbidden)
	got, err := st.GetCommand("op-a")
	require.NoError(t, err)
	require.Equal(t, models.CmdPending, got.Status)
}

func TestHandleResultWithoutCSROnlyAcks(t *testing.T) {
	st := testStore(t)
	cmd := &models.ControlCommand{OperationID: "op-ok", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(cmd))
	require.NoError(t, HandleResult(st, Result{OperationID: "op-ok", Status: "applied"}))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 0)
}

func TestBindFileCertEnqueuesApplyConfig(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "panel.example",
		CertPath: "/opt/1panel/ssl/fullchain.pem",
		KeyPath:  "/opt/1panel/ssl/privkey.pem",
	}
	require.NoError(t, BindFileCert(st, row))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertSourceFile, got.Source)
	require.Equal(t, models.CertPending, got.Status)
	require.Empty(t, got.Issuer)
	require.Empty(t, got.ChainPEM)
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "applyConfig", pending[0].Kind)
	opened, err := commandPayloadJSON(pending[0])
	require.NoError(t, err)
	require.Contains(t, opened, "/opt/1panel/ssl/fullchain.pem")
	require.Contains(t, opened, "/opt/1panel/ssl/privkey.pem")
	require.Contains(t, opened, `"source":"file"`)
}

func TestBindFileCertRejectsEmptyPath(t *testing.T) {
	st := testStore(t)
	err := BindFileCert(st, &models.Certificate{NodeUUID: "n1", Domain: "panel.example", CertPath: "/c.pem"})
	require.ErrorIs(t, err, store.ErrInvalid)
}

func TestHandleResultUpdatesFileCert(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "panel.example",
		Source:   models.CertSourceFile,
		CertPath: "/c.pem",
		KeyPath:  "/k.pem",
	}
	require.NoError(t, st.UpsertCert(row))
	notAfter := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, HandleResult(st, Result{
		NodeUUID:    "n1",
		CertID:      row.ID,
		Status:      "applied",
		Fingerprint: "abc123",
		Issuer:      "Let's Encrypt",
		NotAfter:    &notAfter,
	}))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.Equal(t, "abc123", got.Fingerprint)
	require.Equal(t, "Let's Encrypt", got.Issuer)
	require.NotNil(t, got.NotAfter)
	require.True(t, got.NotAfter.Equal(notAfter))
}

func TestHandleResultFileCertRejectsOtherNode(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "panel.example", Source: models.CertSourceFile, CertPath: "/c.pem", KeyPath: "/k.pem"}
	require.NoError(t, st.UpsertCert(row))
	err := HandleResult(st, Result{NodeUUID: "n2", CertID: row.ID, Status: "applied", Fingerprint: "abc"})
	require.ErrorIs(t, err, store.ErrForbidden)
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertPending, got.Status)
}

func TestHandleResultIgnoresFileStatusForACMECert(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "acme.example", Status: models.CertPending}
	require.NoError(t, st.UpsertCert(row))
	require.NoError(t, HandleResult(st, Result{NodeUUID: "n1", CertID: row.ID, Status: "applied", Fingerprint: "abc"}))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertPending, got.Status)
	require.Empty(t, got.Fingerprint)
}

func TestRenewDueEnqueuesACMEAndSkipsDisabled(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	soon := now.Add(24 * time.Hour)
	due := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "due.example",
		Source:   models.CertSourceACME,
		Status:   models.CertIssued,
		NotAfter: &soon,
	}
	require.NoError(t, st.UpsertCert(due))
	off := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "off.example",
		Source:   models.CertSourceACME,
		Status:   models.CertIssued,
		NotAfter: &soon,
	}
	require.NoError(t, st.UpsertCert(off))
	off.AutoRenew = false
	require.NoError(t, st.UpsertCert(off))
	file := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "file.example",
		Source:   models.CertSourceFile,
		CertPath: "/c.pem",
		KeyPath:  "/k.pem",
		Status:   models.CertIssued,
		NotAfter: &soon,
	}
	require.NoError(t, st.UpsertCert(file))
	require.NoError(t, RenewDue(context.Background(), st, now, true))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	var need int
	for _, cmd := range pending {
		if cmd.Kind == "needCSR" {
			need++
		}
	}
	require.Equal(t, 1, need)
	got, err := st.GetCert(due.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertPending, got.Status)
	require.True(t, got.AutoRenew)
	skipped, err := st.GetCert(off.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, skipped.Status)
	require.False(t, skipped.AutoRenew)
}

func TestRenewDueReissuesRootAndLeavesChildrenToPush(t *testing.T) {
	st := testStore(t)
	root := &models.RootCertificate{Domain: "abc.com"}
	require.NoError(t, IssueRootCert(context.Background(), st, root, true))
	got, err := st.GetRootCert(root.ID)
	require.NoError(t, err)
	require.True(t, got.AutoRenew)
	other := &models.RootCertificate{Domain: "xyz.com"}
	require.NoError(t, IssueRootCert(context.Background(), st, other, true))
	listed, err := st.ListRootCerts()
	require.NoError(t, err)
	require.Len(t, listed, 2)
	soon := time.Now().UTC().Add(time.Hour)
	got.NotAfter = &soon
	require.NoError(t, st.UpsertRootCert(got))
	row := &models.Certificate{NodeUUID: "n1"}
	require.NoError(t, DeployRootToNode(st, got, row, "hk.abc.com"))
	require.NoError(t, RenewDue(context.Background(), st, time.Now().UTC(), true))
	renewed, err := st.GetRootCert(root.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, renewed.Status)
	require.NotNil(t, renewed.NotAfter)
	require.True(t, renewed.NotAfter.After(soon.Add(24*time.Hour)))
	fresh, err := st.GetRootCert(other.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, fresh.Status)
	require.NotNil(t, fresh.NotAfter)
	require.True(t, fresh.NotAfter.After(time.Now().UTC().Add(60*24*time.Hour)))
}

func TestPushCommandRejectsUndecryptablePayload(t *testing.T) {
	st := testStore(t)
	badCmd := models.ControlCommand{
		OperationID: "op-corrupt",
		NodeUUID:    "n1",
		Kind:        "applyConfig",
		PayloadJSON: "enc:v1:not-valid-ciphertext",
		Status:      models.CmdPending,
	}
	err := PushCommand(st, badCmd)
	require.Error(t, err)
}
