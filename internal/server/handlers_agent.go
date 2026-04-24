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

func (s *Server) handleAgentChunks(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	taskID := chi.URLParam(r, "id")

	// Ownership check: task must belong to this node.
	task, err := s.cfg.Store.GetTask(r.Context(), taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if task.NodeID != node.ID {
		writeError(w, http.StatusForbidden, "task not assigned to this node")
		return
	}

	var req api.ChunkUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	now := time.Now()
	result, err := s.cfg.Store.AppendChunk(r.Context(), taskID, req.Stream, req.Data, now, s.cfg.OutputCapBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.dispatcher.PublishChunk(taskID, DispatcherEvent{
		Kind: "chunk",
		Payload: api.ChunkOut{
			Stream:    req.Stream,
			Data:      req.Data,
			CreatedAt: now.Unix(),
		},
	})

	cancels, _ := s.cfg.Store.PendingCancelsForNode(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, api.ChunkUploadResponse{
		Truncated:     result.Truncated,
		CancelTaskIDs: cancels,
	})
}

func (s *Server) handleAgentComplete(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	taskID := chi.URLParam(r, "id")

	// Ownership check: task must belong to this node.
	task, err := s.cfg.Store.GetTask(r.Context(), taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if task.NodeID != node.ID {
		writeError(w, http.StatusForbidden, "task not assigned to this node")
		return
	}

	var req api.CompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	now := time.Now()
	if err := s.cfg.Store.CompleteTask(r.Context(), taskID, req.ExitCode, now); err != nil {
		switch err {
		case store.ErrTaskCompleted:
			writeError(w, http.StatusConflict, "task already completed")
		case store.ErrNotFound:
			writeError(w, http.StatusNotFound, "task not found")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Fetch final task state to include in the done event.
	finalTask, err := s.cfg.Store.GetTask(r.Context(), taskID)
	if err != nil {
		// Non-fatal: publish best-effort done event with what we have.
		finalTask = store.Task{ID: taskID, ExitCode: &req.ExitCode, Status: store.TaskSucceeded}
	}

	s.dispatcher.PublishChunk(taskID, DispatcherEvent{
		Kind: "done",
		Payload: map[string]any{
			"exit_code": req.ExitCode,
			"status":    string(finalTask.Status),
		},
	})

	w.WriteHeader(http.StatusNoContent)
}
