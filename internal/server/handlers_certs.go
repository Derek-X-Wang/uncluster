package server

import (
	"context"
	"encoding/json"
	"log/slog"
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

	// Defensive comma-ok (#49): today's router always mounts /v1/certs under
	// requireAuth(TokenCaller), but a future refactor that exposes the route
	// without the middleware would panic here and chi recovery would obscure
	// it as a 500 with no useful message. Match the heartbeat handler's
	// pattern (handlers_agent.go) and return a clean error instead.
	callerTok, ok := ctx.Value(ctxAuthedToken).(store.Token)
	if !ok {
		writeError(w, http.StatusInternalServerError, "auth context missing")
		return
	}

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

	// Write success event. Strict policy (#44 / ACCEPTANCE.md "Audit"): every
	// cert issuance writes a row to cert_issuance_events. If the audit write
	// fails we refuse to return the cert — otherwise "uncluster audit certs"
	// would silently miss a signed-cert event and operators investigating an
	// incident would get a false-negative answer. The Caller's retry path is
	// fine here; cert minting is idempotent at the caller's pubkey level.
	fp := pubkeyFingerprint(req.Pubkey)
	if err := s.cfg.Store.WriteCertEvent(ctx, store.CertEvent{
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
	}); err != nil {
		slog.Error("audit-event-write-failed",
			"path", "POST /v1/certs (success)",
			"request_id", requestID,
			"caller_token_id", callerTok.ID,
			"target_agent_id", agent.ID,
			"err", err)
		writeError(w, http.StatusInternalServerError,
			"audit write failed; cert not issued (request_id="+requestID+")")
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

// writeDeniedEvent writes a denial row to cert_issuance_events. Lenient
// policy (#44): the Caller's denial response is already decided; if the audit
// write fails we log at ERROR (so operators can detect audit-infrastructure
// breakage) but still return the planned 4xx. Promoting an audit-write
// failure to a 500 would mask the underlying denial reason and make the
// Caller's experience worse during incidents.
func (s *Server) writeDeniedEvent(ctx context.Context, callerID, agentID, username, rawPubkey, reason string) {
	fp := pubkeyFingerprint(rawPubkey)
	requestID := token.NewRequestID()
	if err := s.cfg.Store.WriteCertEvent(ctx, store.CertEvent{
		RequestID:     requestID,
		TS:            time.Now(),
		CallerTokenID: callerID,
		TargetAgentID: agentID,
		Username:      username,
		PubkeyFP:      fp,
		Outcome:       "denied",
		DenialReason:  reason,
	}); err != nil {
		slog.Error("audit-event-write-failed",
			"path", "POST /v1/certs (denied)",
			"request_id", requestID,
			"caller_token_id", callerID,
			"target_agent_id", agentID,
			"denial_reason", reason,
			"err", err)
	}
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
