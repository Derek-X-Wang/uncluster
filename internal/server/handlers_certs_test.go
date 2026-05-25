package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/ca"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// genTestCA generates an ephemeral ed25519 CA keypair for testing.
func genTestCA(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// genTestUserKey generates an ephemeral user keypair and returns the
// authorized_keys-format public key string.
func genTestUserKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// genTestCertKey signs a user key and returns the cert in authorized_keys
// format — used to test rejection of cert-as-input.
func genTestCertKey(t *testing.T, caSigner ssh.Signer) string {
	t.Helper()
	userPubkey := genTestUserKey(t)
	now := time.Now()
	certBytes, err := ca.Sign(caSigner, ca.SignCertParams{
		UserPublicKey: []byte(userPubkey),
		Principals:    []string{"tester"},
		KeyID:         "test:key",
		ValidAfter:    now.Add(-30 * time.Second),
		ValidBefore:   now.Add(5 * time.Minute),
		Serial:        999,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(certBytes)
}

// newTestServerWithCA creates a test server with an ephemeral CA.
func newTestServerWithCA(t *testing.T) (*server.Server, store.Store, ssh.Signer) {
	t.Helper()
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	t.Cleanup(func() { _ = st.Close() })
	caSigner := genTestCA(t)
	pubBytes := ssh.MarshalAuthorizedKey(caSigner.PublicKey())
	srv := server.New(server.Config{
		Store:    st,
		CASigner: caSigner,
		CAPubkey: string(pubBytes),
	})
	return srv, st, caSigner
}

// TestIssueCert_Success verifies end-to-end cert issuance.
func TestIssueCert_Success(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "cert-agent")

	// Grant ACL.
	grantBody, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "derek"})
	grantReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+cliTok)
	grantReq.Header.Set("Content-Type", "application/json")
	grantResp, _ := http.DefaultClient.Do(grantReq)
	grantResp.Body.Close()
	if grantResp.StatusCode != http.StatusCreated {
		t.Fatalf("grant ACL: status=%d", grantResp.StatusCode)
	}

	// Issue cert.
	certBody, _ := json.Marshal(api.CertRequest{
		Agent:    agentID,
		Username: "derek",
		Pubkey:   genTestUserKey(t),
	})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, _ := http.DefaultClient.Do(certReq)
	if certResp.StatusCode != http.StatusOK {
		buf := make([]byte, 512)
		n, _ := certResp.Body.Read(buf)
		t.Fatalf("issue cert: status=%d body=%s", certResp.StatusCode, buf[:n])
	}
	var cr api.CertResponse
	json.NewDecoder(certResp.Body).Decode(&cr)
	certResp.Body.Close()

	if cr.Certificate == "" {
		t.Error("certificate should not be empty")
	}
	if cr.Principal != callerID {
		t.Errorf("principal = %q, want callerID=%q", cr.Principal, callerID)
	}
	if cr.Serial == 0 {
		t.Error("serial should be non-zero")
	}
	if cr.ValidBefore <= cr.ValidAfter {
		t.Errorf("valid_before (%d) must be > valid_after (%d)", cr.ValidBefore, cr.ValidAfter)
	}

	// Verify the cert is parseable.
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cr.Certificate))
	if err != nil {
		t.Errorf("issued cert not parseable: %v", err)
	}
}

// TestIssueCert_ACLMiss verifies 403 when no ACL row exists.
func TestIssueCert_ACLMiss(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	callerPlaintext, _ := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "cert-miss")

	certBody, _ := json.Marshal(api.CertRequest{
		Agent:    agentID,
		Username: "alice",
		Pubkey:   genTestUserKey(t),
	})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, _ := http.DefaultClient.Do(certReq)
	certResp.Body.Close()

	if certResp.StatusCode != http.StatusForbidden {
		t.Errorf("acl miss: status=%d, want 403", certResp.StatusCode)
	}
}

// TestIssueCert_RejectsCertAsPubkey verifies 400 when a cert is used as the pubkey input.
func TestIssueCert_RejectsCertAsPubkey(t *testing.T) {
	srv, st, caSigner := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "cert-certpub")

	// Grant ACL.
	gb, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "x"})
	gr, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(gb))
	gr.Header.Set("Authorization", "Bearer "+cliTok)
	gr.Header.Set("Content-Type", "application/json")
	r, _ := http.DefaultClient.Do(gr)
	r.Body.Close()

	certPubkey := genTestCertKey(t, caSigner)
	certBody, _ := json.Marshal(api.CertRequest{
		Agent:    agentID,
		Username: "x",
		Pubkey:   certPubkey,
	})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, _ := http.DefaultClient.Do(certReq)
	certResp.Body.Close()

	if certResp.StatusCode != http.StatusBadRequest {
		t.Errorf("cert-as-pubkey: status=%d, want 400", certResp.StatusCode)
	}
}

// TestIssueCert_TTLTooLong verifies 400 for TTL > 900s.
func TestIssueCert_TTLTooLong(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "cert-ttl")

	gb, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "u"})
	gr, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(gb))
	gr.Header.Set("Authorization", "Bearer "+cliTok)
	gr.Header.Set("Content-Type", "application/json")
	gr2, _ := http.DefaultClient.Do(gr)
	gr2.Body.Close()

	certBody, _ := json.Marshal(api.CertRequest{
		Agent:      agentID,
		Username:   "u",
		Pubkey:     genTestUserKey(t),
		TTLSeconds: 901,
	})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, _ := http.DefaultClient.Do(certReq)
	certResp.Body.Close()

	if certResp.StatusCode != http.StatusBadRequest {
		t.Errorf("ttl too long: status=%d, want 400", certResp.StatusCode)
	}
}

// TestIssueCert_NoCASigner verifies 503 when no CA is configured.
func TestIssueCert_NoCASigner(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "noca.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st}) // no CASigner
	ts := httpTestServer(t, srv.Handler())

	callerPlaintext, _ := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "noca-agent")

	certBody, _ := json.Marshal(api.CertRequest{Agent: agentID, Username: "u", Pubkey: genTestUserKey(t)})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, _ := http.DefaultClient.Do(certReq)
	certResp.Body.Close()

	if certResp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no CA: status=%d, want 503", certResp.StatusCode)
	}
}

// TestGetAgent_ByIDAndName verifies GET /v1/agents/{id} resolves both id and name.
func TestGetAgent_ByIDAndName(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "ag.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "my-box")

	doGet := func(path string) api.AgentDetail {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+cliTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status=%d", path, resp.StatusCode)
		}
		var d api.AgentDetail
		json.NewDecoder(resp.Body).Decode(&d)
		return d
	}

	byID := doGet("/v1/agents/" + agentID)
	if byID.ID != agentID {
		t.Errorf("by id: got %q want %q", byID.ID, agentID)
	}
	if byID.Name != "my-box" {
		t.Errorf("name = %q, want my-box", byID.Name)
	}

	byName := doGet("/v1/agents/my-box")
	if byName.ID != agentID {
		t.Errorf("by name: got %q want %q", byName.ID, agentID)
	}
}
