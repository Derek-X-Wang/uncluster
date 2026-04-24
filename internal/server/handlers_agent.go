package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req api.AgentRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.JoinToken == "" {
		writeError(w, http.StatusBadRequest, "name and join_token required")
		return
	}

	parsed, err := token.Parse(req.JoinToken)
	if err != nil || parsed.Kind != token.Kind(store.TokenJoin) {
		writeError(w, http.StatusUnauthorized, "invalid join token")
		return
	}
	row, err := s.cfg.Store.GetTokenByID(r.Context(), parsed.ID)
	if err != nil || row.Kind != store.TokenJoin {
		writeError(w, http.StatusUnauthorized, "unknown join token")
		return
	}
	if row.UsedAt != nil {
		writeError(w, http.StatusUnauthorized, "join token already used")
		return
	}
	if row.RevokedAt != nil {
		writeError(w, http.StatusUnauthorized, "join token revoked")
		return
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusUnauthorized, "join token expired")
		return
	}
	ok, err := token.VerifySecret(parsed.Secret, row.SecretHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "secret mismatch")
		return
	}

	metaJSON, _ := json.Marshal(req.Metadata)
	node, err := s.cfg.Store.CreateNode(r.Context(), store.NewNodeParams{
		Name: req.Name, Metadata: string(metaJSON),
	})
	if err != nil {
		if err == store.ErrNameTaken {
			writeError(w, http.StatusConflict, "name already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	agentTok, err := token.Generate(token.KindAgent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash, _ := token.HashSecret(agentTok.Secret)
	nid := node.ID
	if _, err := s.cfg.Store.CreateToken(r.Context(), store.NewTokenParams{
		ID: agentTok.ID, Kind: store.TokenAgent, NodeID: &nid, SecretHash: hash, Label: "agent:" + node.Name,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.cfg.Store.MarkJoinTokenUsed(r.Context(), row.ID, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, api.AgentRegisterResponse{
		NodeID: node.ID, AgentToken: agentTok.String(),
	})
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	var req api.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	metaJSON, _ := json.Marshal(req.Metadata)
	if err := s.cfg.Store.UpdateNodeHeartbeat(r.Context(), node.ID, string(metaJSON), time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cancels, _ := s.cfg.Store.PendingCancelsForNode(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{CancelTaskIDs: cancels})
}
