package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

type ctxKey string

const (
	ctxAuthedToken ctxKey = "authed_token"
	ctxAuthedNode  ctxKey = "authed_node"  // store.Node — V1 agent tokens (node_id set)
	ctxAuthedAgent ctxKey = "authed_agent" // store.Agent — V2 agent tokens (agent_id set)
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
			ctx := context.WithValue(r.Context(), ctxAuthedToken, row)
			// For agent tokens, carry the node (V1) or agent (V2) and reject revoked ones.
			if row.Kind == store.TokenAgent {
				switch {
				case row.AgentID != nil:
					// V2: token linked to agents table.
					ag, err := s.cfg.Store.GetAgent(r.Context(), *row.AgentID)
					if err != nil || ag.Status == store.AgentRevoked {
						writeError(w, http.StatusUnauthorized, "agent revoked")
						return
					}
					ctx = context.WithValue(ctx, ctxAuthedAgent, ag)
				case row.NodeID != nil:
					// V1: token linked to nodes table.
					node, err := s.cfg.Store.GetNode(r.Context(), *row.NodeID)
					if err != nil || node.Status == store.NodeRevoked {
						writeError(w, http.StatusUnauthorized, "node revoked")
						return
					}
					ctx = context.WithValue(ctx, ctxAuthedNode, node)
				default:
					writeError(w, http.StatusUnauthorized, "agent token has no linked record")
					return
				}
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
