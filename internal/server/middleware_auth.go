package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

type ctxKey string

const (
	ctxAuthedToken ctxKey = "authed_token"
	ctxAuthedAgent ctxKey = "authed_agent" // store.Agent — V2 agent tokens
)

func (s *Server) requireAuth(requiredKind store.TokenKind) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerFrom(r.Header.Get("Authorization"))
			if raw == "" {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			parsed, err := token.Parse(raw)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "malformed token")
				return
			}
			row, err := s.cfg.Store.GetTokenByID(r.Context(), parsed.ID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unknown token")
				return
			}
			// Kind from DB is authoritative; also check it matches the parsed string.
			if store.TokenKind(parsed.Kind) != row.Kind {
				writeError(w, http.StatusUnauthorized, "kind mismatch")
				return
			}
			if row.Kind != requiredKind {
				writeError(w, http.StatusUnauthorized, "wrong token kind for this route")
				return
			}
			// For agent tokens, check agent-record status first: a deprovisioned agent
			// (AgentRevoked) returns 410 Gone so the Agent knows to wipe its principals.
			// This is distinct from token revocation (401). After the agent-record check,
			// all token kinds — including agent tokens — go through the shared
			// revocation/expiry checks. Skipping that shared check for agent tokens was
			// the bug: DELETE /v1/tokens/{id} sets tokens.revoked_at but never touches
			// agents.status, so a revoked Caller token for an agent would authenticate
			// indefinitely. Fix: apply revoked_at/expires_at to all kinds.
			ctx := context.WithValue(r.Context(), ctxAuthedToken, row)
			if row.Kind == store.TokenAgent {
				if row.AgentID == nil {
					writeError(w, http.StatusUnauthorized, "agent token has no linked record")
					return
				}
				ag, err := s.cfg.Store.GetAgent(r.Context(), *row.AgentID)
				if err != nil {
					writeError(w, http.StatusUnauthorized, "agent not found")
					return
				}
				if ag.Status == store.AgentRevoked {
					// 410 Gone signals explicit deprovision; Agent must wipe principals.
					writeJSON(w, http.StatusGone, api.RevokedResponse{Reason: "node_revoked"})
					return
				}
				ctx = context.WithValue(ctx, ctxAuthedAgent, ag)
			}
			// Apply revocation and expiry checks for all token kinds, including agent
			// tokens. A token revoked via DELETE /v1/tokens/{id} must return 401 on the
			// next heartbeat regardless of agent-record status (ACCEPTANCE.md §44).
			if row.RevokedAt != nil {
				writeError(w, http.StatusUnauthorized, "token revoked")
				return
			}
			if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
				writeError(w, http.StatusUnauthorized, "token expired")
				return
			}
			if row.Kind == store.TokenJoin && row.UsedAt != nil {
				writeError(w, http.StatusUnauthorized, "join token already used")
				return
			}
			// VerifySecret last: argon2 is expensive; only run after all cheap checks pass.
			ok, err := token.VerifySecret(parsed.Secret, row.SecretHash)
			if err != nil || !ok {
				writeError(w, http.StatusUnauthorized, "secret mismatch")
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerFrom(h string) string {
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[len("Bearer "):])
}

// ErrAuthFailed is exported for tests / handlers that want to detect auth
// problems distinctly from store/not-found.
var ErrAuthFailed = errors.New("auth: failed")
