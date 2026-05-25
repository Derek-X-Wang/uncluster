package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/ca"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

const (
	certTTLDefault = 300 // seconds
	certTTLMax     = 900 // seconds
)

// handleIssueCert handles POST /v1/certs.
//
// Auth: caller token required.
// Body: CertRequest { agent, username, pubkey, ttl_seconds }.
// Response: CertResponse with the signed cert.
func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.cfg.CASigner == nil {
		writeError(w, http.StatusServiceUnavailable, "CA not configured; run `uncluster server bootstrap`")
		return
	}

	callerTok := ctx.Value(ctxAuthedToken).(store.Token)

	var req api.CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Agent == "" || req.Username == "" || req.Pubkey == "" {
		writeError(w, http.StatusBadRequest, "agent, username, and pubkey are required")
		return
	}

	// Validate TTL.
	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = certTTLDefault
	}
	if ttl > certTTLMax {
		writeError(w, http.StatusBadRequest, "ttl_seconds exceeds maximum (900)")
		return
	}

	// Resolve agent.
	agent, err := resolveAgent(ctx, s.cfg.Store, req.Agent)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Check ACL: must have a row (caller_token_id, agent_id, username).
	entries, err := s.cfg.Store.ListACL(ctx, store.ListACLFilter{
		CallerTokenID: callerTok.ID,
		AgentID:       agent.ID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	aclOK := false
	for _, e := range entries {
		if e.Username == req.Username {
			aclOK = true
			break
		}
	}
	if !aclOK {
		writeError(w, http.StatusForbidden, "acl_miss: no grant for (caller, agent, username)")
		return
	}

	// Build cert params.
	requestID := token.NewRequestID()
	now := time.Now()
	validAfter := now.Add(-30 * time.Second) // clock skew defense
	validBefore := now.Add(time.Duration(ttl) * time.Second)
	serial := s.serial.Add(1)
	keyID := ca.FormatKeyID(requestID, callerTok.ID, agent.ID, req.Username)

	certBytes, err := ca.Sign(s.cfg.CASigner, ca.SignCertParams{
		UserPublicKey: []byte(req.Pubkey),
		Principals:    []string{callerTok.ID},
		KeyID:         keyID,
		ValidAfter:    validAfter,
		ValidBefore:   validBefore,
		Serial:        serial,
	})
	if err != nil {
		// Distinguish user errors from server errors.
		if isCertInputError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, api.CertResponse{
		Certificate: string(certBytes),
		KeyID:       keyID,
		Principal:   callerTok.ID,
		Serial:      serial,
		ValidAfter:  validAfter.Unix(),
		ValidBefore: validBefore.Unix(),
	})
}

// isCertInputError returns true for errors produced by bad caller input
// (malformed pubkey, cert-as-pubkey, timing issues) so we can 400 them.
func isCertInputError(err error) bool {
	msg := err.Error()
	for _, sub := range []string{
		"parse user pubkey",
		"is itself a certificate",
		"ValidBefore must be strictly after",
		"at least one principal",
		"KeyID required",
	} {
		if containsSubstr(msg, sub) {
			return true
		}
	}
	return false
}

func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
