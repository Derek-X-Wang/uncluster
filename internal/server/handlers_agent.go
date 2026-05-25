package server

import (
	"encoding/json"
	"net/http"
	"time"

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
	ag, ok := r.Context().Value(ctxAuthedAgent).(store.Agent)
	if !ok {
		writeError(w, http.StatusUnauthorized, "agent context missing")
		return
	}
	s.handleV2Heartbeat(w, r, ag)
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

	// Persist endpoints (best-effort).
	if len(req.Endpoints) > 0 {
		eps := make([]store.AgentEndpoint, 0, len(req.Endpoints))
		for _, e := range req.Endpoints {
			eps = append(eps, store.AgentEndpoint{Subnet: e.Subnet, Address: e.Address})
		}
		_ = s.cfg.Store.UpsertAgentEndpoints(ctx, ag.ID, eps)
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

	// Re-read agent to get latest fail_closed_after setting.
	latestAg, _ := s.cfg.Store.GetAgent(ctx, ag.ID)

	// Build commands. Inject check_update if agent_version ≠ expected_version.
	commands := buildUpdateCommands(ctx, s, req.AgentVersion)

	writeJSON(w, http.StatusOK, api.V2HeartbeatResponse{
		AckTS:           req.ObservedAt,
		ServerTime:      now.Unix(),
		Policy:          policy,
		Commands:        commands,
		FailClosedAfter: latestAg.FailClosedAfter,
	})
}
