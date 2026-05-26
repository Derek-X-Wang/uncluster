package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/ca"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"golang.org/x/crypto/ssh"
)

// failingAuditStore wraps a real store but injects an error on WriteCertEvent.
// All other Store methods delegate via embedding. The injection toggles via
// the FailWrites field so the same wrapper can be flipped mid-test.
type failingAuditStore struct {
	store.Store
	FailWrites bool
}

func (f *failingAuditStore) WriteCertEvent(ctx context.Context, e store.CertEvent) error {
	if f.FailWrites {
		return errors.New("simulated cert_issuance_events write failure")
	}
	return f.Store.WriteCertEvent(ctx, e)
}

// TestCertIssue_AuditWriteFailure_SuccessPathStrict proves the success-path
// policy chosen for #44: when WriteCertEvent fails on a path that would
// otherwise return a signed cert, the handler returns 500 and does NOT
// return the cert. Otherwise `uncluster audit certs` would silently miss
// the issuance and operators would get a false-negative answer.
//
// Pre-fix the handler did `_ = WriteCertEvent(...)` and returned the cert
// regardless; an audit-write hiccup silently dropped the row.
func TestCertIssue_AuditWriteFailure_SuccessPathStrict(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auditfail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Generate a real CA so the cert-sign path runs.
	caPriv, caPub, err := ca.Generate()
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caPubBytes, _ := ca.MarshalPublic(caPub)

	wrapped := &failingAuditStore{Store: st}
	srv := server.New(server.Config{
		Store:    wrapped,
		CAPubkey: string(caPubBytes),
		CASigner: caSigner,
	})
	ts := httpTestServer(t, srv.Handler())

	// Seed caller token and register an agent.
	cliTok, cliTokID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "audit-agent")

	// Create the ACL row so the cert request is authorized.
	if _, err := st.CreateACL(context.Background(), store.CreateACLParams{
		CallerTokenID: cliTokID, AgentID: agentID, Username: "derek",
	}); err != nil {
		t.Fatal(err)
	}

	// Build a user keypair to request a cert for.
	userPubBytes := genTestUserKey(t)

	certBody, _ := json.Marshal(api.CertRequest{
		Agent: agentID, Username: "derek", Pubkey: userPubBytes,
	})

	// Sanity: with audit writes working, the cert request should succeed.
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs",
		bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+cliTok)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, err := http.DefaultClient.Do(certReq)
	if err != nil {
		t.Fatal(err)
	}
	if certResp.StatusCode != http.StatusOK {
		t.Fatalf("baseline cert: status=%d", certResp.StatusCode)
	}
	certResp.Body.Close()

	// Flip the wrapper to fail audit writes. Now the same cert request must
	// 500 (audit-write-failed) and must not return a cert.
	wrapped.FailWrites = true

	certReq2, _ := http.NewRequest("POST", ts.URL+"/v1/certs",
		bytes.NewReader(certBody))
	certReq2.Header.Set("Authorization", "Bearer "+cliTok)
	certReq2.Header.Set("Content-Type", "application/json")
	certResp2, err := http.DefaultClient.Do(certReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer certResp2.Body.Close()

	if certResp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit-failure cert: status=%d, want 500", certResp2.StatusCode)
	}
	// Decode body to confirm no certificate slipped through.
	var resp api.CertResponse
	_ = json.NewDecoder(certResp2.Body).Decode(&resp)
	if resp.Certificate != "" {
		t.Errorf("got certificate %q in 500 response; strict policy violated", resp.Certificate)
	}
}

// TestCertIssue_AuditWriteFailure_DeniedPathLenient verifies the denial-path
// policy: a 4xx denial is still returned even if the audit write fails. The
// audit failure is logged but does not turn the Caller's 403 into a 500.
//
// Specifically: ACL miss returns 403 + (best-effort) denied audit event. With
// audit writes failing, the Caller still sees 403.
func TestCertIssue_AuditWriteFailure_DeniedPathLenient(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auditdeny.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	caPriv, caPub, _ := ca.Generate()
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caPubBytes, _ := ca.MarshalPublic(caPub)

	wrapped := &failingAuditStore{Store: st, FailWrites: true}
	srv := server.New(server.Config{
		Store:    wrapped,
		CAPubkey: string(caPubBytes),
		CASigner: caSigner,
	})
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "deny-agent")
	// Intentionally no ACL row → cert request hits acl_miss.

	userPubBytes := genTestUserKey(t)
	certBody, _ := json.Marshal(api.CertRequest{
		Agent: agentID, Username: "nobody", Pubkey: userPubBytes,
	})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs",
		bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+cliTok)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, err := http.DefaultClient.Do(certReq)
	if err != nil {
		t.Fatal(err)
	}
	defer certResp.Body.Close()
	if certResp.StatusCode != http.StatusForbidden {
		t.Errorf("denied path with audit failure: status=%d, want 403 (lenient policy: audit-write failure must not promote 403 → 500)",
			certResp.StatusCode)
	}
}
