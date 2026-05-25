package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req api.CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	var kind store.TokenKind
	switch req.Kind {
	case "join":
		kind = store.TokenJoin
	case "caller":
		kind = store.TokenCaller
	default:
		writeError(w, http.StatusBadRequest, "kind must be join or caller")
		return
	}

	tok, err := token.Generate(token.Kind(kind))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate: "+err.Error())
		return
	}
	hash, err := token.HashSecret(tok.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash: "+err.Error())
		return
	}
	var expiresAt *time.Time
	switch {
	case req.ExpiresAt != nil:
		v := time.Unix(*req.ExpiresAt, 0)
		expiresAt = &v
	case kind == store.TokenJoin:
		v := time.Now().Add(15 * time.Minute)
		expiresAt = &v
	}
	row, err := s.cfg.Store.CreateToken(r.Context(), store.NewTokenParams{
		ID:         tok.ID,
		Kind:       kind,
		SecretHash: hash,
		Label:      req.Label,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	// Defensive: update tok.ID in case store reassigned.
	tok.ID = row.ID
	writeJSON(w, http.StatusOK, api.CreateTokenResponse{ID: row.ID, Token: tok.String()})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := s.cfg.Store.ListTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.TokenSummary, 0, len(rows))
	for _, t := range rows {
		out = append(out, api.TokenSummary{
			ID:        t.ID,
			Kind:      string(t.Kind),
			Label:     t.Label,
			CreatedAt: t.CreatedAt.Unix(),
			ExpiresAt: api.TimePtr(t.ExpiresAt),
			UsedAt:    api.TimePtr(t.UsedAt),
			RevokedAt: api.TimePtr(t.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.cfg.Store.RevokeToken(r.Context(), id, time.Now()); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
