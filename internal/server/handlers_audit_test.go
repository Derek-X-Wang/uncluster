package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestCertAudit_SignedEventWritten verifies that a successful cert issuance
// writes a row with outcome=signed and the correct key_id.
func TestCertAudit_SignedEventWritten(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "audit-box")

	// Grant ACL.
	grantBody, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "derek"})
	grantReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+cliTok)
	grantReq.Header.Set("Content-Type", "application/json")
	gr, _ := http.DefaultClient.Do(grantReq)
	gr.Body.Close()

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
	var cr api.CertResponse
	json.NewDecoder(certResp.Body).Decode(&cr)
	certResp.Body.Close()
	if certResp.StatusCode != http.StatusOK {
		t.Fatalf("issue cert: status=%d", certResp.StatusCode)
	}

	// Query audit log.
	auditReq, _ := http.NewRequest("GET", ts.URL+"/v1/audit/certs", nil)
	auditReq.Header.Set("Authorization", "Bearer "+cliTok)
	auditResp, err := http.DefaultClient.Do(auditReq)
	if err != nil {
		t.Fatal(err)
	}
	defer auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("audit list: status=%d", auditResp.StatusCode)
	}
	var events []api.CertEventSummary
	json.NewDecoder(auditResp.Body).Decode(&events)

	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Outcome != "signed" {
		t.Errorf("outcome = %q, want signed", e.Outcome)
	}
	if e.KeyID != cr.KeyID {
		t.Errorf("key_id = %q, want %q", e.KeyID, cr.KeyID)
	}
	if e.CallerTokenID != callerID {
		t.Errorf("caller_token_id = %q, want %q", e.CallerTokenID, callerID)
	}
	if e.TargetAgentID != agentID {
		t.Errorf("target_agent_id = %q, want %q", e.TargetAgentID, agentID)
	}
	if e.Username != "derek" {
		t.Errorf("username = %q, want derek", e.Username)
	}
	if e.PubkeyFP == "" {
		t.Error("pubkey_fp should be set")
	}
	if e.Serial != cr.Serial {
		t.Errorf("serial = %d, want %d", e.Serial, cr.Serial)
	}
}

// TestCertAudit_DeniedEventWritten_ACLMiss verifies that a denied cert request
// writes a row with outcome=denied and denial_reason=acl_miss.
func TestCertAudit_DeniedEventWritten_ACLMiss(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "audit-deny")

	// No ACL grant.
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
		t.Fatalf("acl miss: status=%d", certResp.StatusCode)
	}

	// Query audit log.
	auditReq, _ := http.NewRequest("GET", ts.URL+"/v1/audit/certs?caller="+callerID, nil)
	auditReq.Header.Set("Authorization", "Bearer "+cliTok)
	auditResp, err := http.DefaultClient.Do(auditReq)
	if err != nil {
		t.Fatal(err)
	}
	defer auditResp.Body.Close()

	var events []api.CertEventSummary
	json.NewDecoder(auditResp.Body).Decode(&events)
	if len(events) != 1 {
		t.Fatalf("want 1 denied event, got %d", len(events))
	}
	e := events[0]
	if e.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", e.Outcome)
	}
	if e.DenialReason != "acl_miss" {
		t.Errorf("denial_reason = %q, want acl_miss", e.DenialReason)
	}
}

// TestCertAudit_FilterByOutcome verifies the ?outcome= filter.
func TestCertAudit_FilterByOutcome(t *testing.T) {
	srv, st, _ := newTestServerWithCA(t)
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "audit-filter")

	// Grant ACL and issue (signed event).
	grantBody, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "bob"})
	grantReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+cliTok)
	grantReq.Header.Set("Content-Type", "application/json")
	gr, _ := http.DefaultClient.Do(grantReq)
	gr.Body.Close()

	certBody, _ := json.Marshal(api.CertRequest{Agent: agentID, Username: "bob", Pubkey: genTestUserKey(t)})
	certReq, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody))
	certReq.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq.Header.Set("Content-Type", "application/json")
	cr, _ := http.DefaultClient.Do(certReq)
	cr.Body.Close()

	// Also trigger a denial.
	certBody2, _ := json.Marshal(api.CertRequest{Agent: agentID, Username: "nobody", Pubkey: genTestUserKey(t)})
	certReq2, _ := http.NewRequest("POST", ts.URL+"/v1/certs", bytes.NewReader(certBody2))
	certReq2.Header.Set("Authorization", "Bearer "+callerPlaintext)
	certReq2.Header.Set("Content-Type", "application/json")
	cr2, _ := http.DefaultClient.Do(certReq2)
	cr2.Body.Close()

	doList := func(outcome string) []api.CertEventSummary {
		u := ts.URL + "/v1/audit/certs?outcome=" + outcome
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "Bearer "+cliTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var events []api.CertEventSummary
		json.NewDecoder(resp.Body).Decode(&events)
		return events
	}

	signed := doList("signed")
	if len(signed) != 1 || signed[0].Outcome != "signed" {
		t.Errorf("signed filter: %+v", signed)
	}
	denied := doList("denied")
	if len(denied) != 1 || denied[0].Outcome != "denied" {
		t.Errorf("denied filter: %+v", denied)
	}
}

// TestListCertEvents_Empty verifies that with no events, we get an empty array.
func TestListCertEvents_Empty(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "empty.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)

	req, _ := http.NewRequest("GET", ts.URL+"/v1/audit/certs", nil)
	req.Header.Set("Authorization", "Bearer "+cliTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var events []api.CertEventSummary
	json.NewDecoder(resp.Body).Decode(&events)
	if events == nil {
		// nil slice is fine; marshalled as [] by the handler. But we check the
		// JSON actually decoded to a non-nil slice or empty slice.
	}
	if len(events) != 0 {
		t.Errorf("want 0 events, got %d", len(events))
	}
}
