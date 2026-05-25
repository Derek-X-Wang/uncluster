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

// expectedPaths returns the canonical SSH-related paths for the given GOOS
// platform string (as reported in metadata["os"] by the Agent). Defaults to
// POSIX paths for unknown platforms.
func expectedPaths(goos string) api.ExpectedPaths {
	switch goos {
	case "windows":
		return api.ExpectedPaths{
			CAPubkey:      `C:\ProgramData\ssh\uncluster_ca.pub`,
			SSHDropIn:     `C:\ProgramData\ssh\sshd_config.d\uncluster.conf`,
			PrincipalsDir: `C:\ProgramData\ssh\auth_principals`,
		}
	default: // linux, darwin, and anything else
		return api.ExpectedPaths{
			CAPubkey:      "/etc/ssh/uncluster_ca.pub",
			SSHDropIn:     "/etc/ssh/sshd_config.d/uncluster.conf",
			PrincipalsDir: "/etc/ssh/auth_principals",
		}
	}
}

// osFromMetadata extracts the "os" string from request metadata. Returns an
// empty string when absent.
func osFromMetadata(m map[string]any) string {
	if m == nil {
		return ""
	}
	if v, ok := m["os"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

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

	// Check for existing enrollment: idempotency-by-rejection for this slice.
	// S2b's `agent install` adds self-healing; `agent join` errors if already enrolled.
	if _, err := s.cfg.Store.GetAgentByName(r.Context(), req.Name); err == nil {
		writeError(w, http.StatusConflict, "already enrolled")
		return
	}

	// Create V2 Agent record.
	ag, err := s.cfg.Store.CreateAgent(r.Context(), store.NewAgentParams{
		Name: req.Name,
	})
	if err != nil {
		if err == store.ErrAgentNameTaken {
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
	aid := ag.ID
	if _, err := s.cfg.Store.CreateToken(r.Context(), store.NewTokenParams{
		ID: agentTok.ID, Kind: store.TokenAgent, AgentID: &aid, SecretHash: hash, Label: "agent:" + ag.Name,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.cfg.Store.MarkJoinTokenUsed(r.Context(), row.ID, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	goos := osFromMetadata(req.Metadata)
	writeJSON(w, http.StatusOK, api.AgentRegisterResponse{
		AgentID:       ag.ID,
		AgentToken:    agentTok.String(),
		CAPubkey:      s.cfg.CAPubkey,
		ExpectedPaths: expectedPaths(goos),
	})
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Dispatch: V2 agent token → new heartbeat path; V1 node token → legacy path.
	if ag, ok := ctx.Value(ctxAuthedAgent).(store.Agent); ok {
		s.handleV2Heartbeat(w, r, ag)
		return
	}

	// V1 legacy path.
	node := ctx.Value(ctxAuthedNode).(store.Node)
	var req api.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	metaJSON, _ := json.Marshal(req.Metadata)
	if err := s.cfg.Store.UpdateNodeHeartbeat(ctx, node.ID, string(metaJSON), time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cancels, _ := s.cfg.Store.PendingCancelsForNode(ctx, node.ID)
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{CancelTaskIDs: cancels})
}

func (s *Server) handleV2Heartbeat(w http.ResponseWriter, r *http.Request, ag store.Agent) {
	ctx := r.Context()
	var req api.V2HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	now := time.Now()

	// Update agents.last_seen_at + agent_version.
	if err := s.cfg.Store.UpdateAgentHeartbeat(ctx, ag.ID, req.AgentVersion, now); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Persist policy state (best-effort).
	_ = s.cfg.Store.UpsertAgentPolicyState(ctx, store.UpsertAgentPolicyStateParams{
		AgentID:         ag.ID,
		DesiredVersion:  req.PolicyState.DesiredVersion,
		AppliedVersion:  req.PolicyState.AppliedVersion,
		AppliedHash:     req.PolicyState.AppliedHash,
		LastApplyStatus: req.PolicyState.LastApplyStatus,
		LastApplyError:  req.PolicyState.LastApplyError,
		LastApplyAt:     time.Unix(req.PolicyState.LastApplyAt, 0),
	})

	// Compute current policy snapshot; send it if the agent's applied_hash differs.
	var policy *api.PolicyPayload
	snap, err := s.cfg.Store.GetPolicySnapshot(ctx, ag.ID)
	if err == nil && snap.Hash != req.PolicyState.AppliedHash {
		principals := make([]api.PolicyPrincipal, 0, len(snap.Principals))
		for _, p := range snap.Principals {
			principals = append(principals, api.PolicyPrincipal{
				Username:       p.Username,
				CallerTokenIDs: p.CallerTokenIDs,
			})
		}
		policy = &api.PolicyPayload{
			Version:    snap.Version,
			Hash:       snap.Hash,
			Principals: principals,
		}
	}

	writeJSON(w, http.StatusOK, api.V2HeartbeatResponse{
		AckTS:      req.ObservedAt,
		ServerTime: now.Unix(),
		Policy:     policy,
		Commands:   []any{},
	})
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
