package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

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
//
// Every request (success or denial) writes a row to cert_issuance_events.
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
		// writeDeniedEvent with empty agent since we don't have it yet.
		s.writeDeniedEvent(ctx, callerTok.ID, "", req.Username, "", "bad_input")
		writeError(w, http.StatusBadRequest, "agent, username, and pubkey are required")
		return
	}

	// Validate TTL.
	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = certTTLDefault
	}
	if ttl > certTTLMax {
		s.writeDeniedEvent(ctx, callerTok.ID, "", req.Username, req.Pubkey, "bad_input")
		writeError(w, http.StatusBadRequest, "ttl_seconds exceeds maximum (900)")
		return
	}

	// Resolve agent.
	agent, err := resolveAgent(ctx, s.cfg.Store, req.Agent)
	if err != nil {
		s.writeDeniedEvent(ctx, callerTok.ID, "", req.Username, req.Pubkey, "agent_not_found")
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
		s.writeDeniedEvent(ctx, callerTok.ID, agent.ID, req.Username, req.Pubkey, "acl_miss")
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
			s.writeDeniedEvent(ctx, callerTok.ID, agent.ID, req.Username, req.Pubkey, "bad_input")
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Write success event.
	fp := pubkeyFingerprint(req.Pubkey)
	_ = s.cfg.Store.WriteCertEvent(ctx, store.CertEvent{
		RequestID:     requestID,
		TS:            now,
		CallerTokenID: callerTok.ID,
		TargetAgentID: agent.ID,
		Username:      req.Username,
		CertPrincipal: callerTok.ID,
		PubkeyFP:      fp,
		TTLSeconds:    ttl,
		Serial:        serial,
		KeyID:         keyID,
		Outcome:       "signed",
	})

	writeJSON(w, http.StatusOK, api.CertResponse{
		Certificate: string(certBytes),
		KeyID:       keyID,
		Principal:   callerTok.ID,
		Serial:      serial,
		ValidAfter:  validAfter.Unix(),
		ValidBefore: validBefore.Unix(),
	})
}

// writeDeniedEvent writes a denial row to cert_issuance_events. Best-effort;
// errors are silently dropped since the primary response is already decided.
func (s *Server) writeDeniedEvent(ctx context.Context, callerID, agentID, username, rawPubkey, reason string) {
	fp := pubkeyFingerprint(rawPubkey)
	_ = s.cfg.Store.WriteCertEvent(ctx, store.CertEvent{
		RequestID:     token.NewRequestID(),
		TS:            time.Now(),
		CallerTokenID: callerID,
		TargetAgentID: agentID,
		Username:      username,
		PubkeyFP:      fp,
		Outcome:       "denied",
		DenialReason:  reason,
	})
}

// pubkeyFingerprint returns the SHA-256 fingerprint of an authorized_keys-format
// public key string in the format "SHA256:<base64>". Returns "" on parse error.
func pubkeyFingerprint(rawPubkey string) string {
	if rawPubkey == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawPubkey))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
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
