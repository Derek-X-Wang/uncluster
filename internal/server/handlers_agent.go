package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

// hashSecret is a package-level indirection over token.HashSecret so tests can
// inject a deterministic failure to verify the register handler's error path
// (see TestAgentRegister_HashSecretFailure). Production code uses the real
// argon2id implementation.
var hashSecret = token.HashSecret

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
	hash, err := hashSecret(agentTok.Secret)
	if err != nil {
		// argon2id can fail under memory pressure or if rand.Read fails. The
		// pre-fix code swallowed this and stored an empty hash, which made
		// every future heartbeat 401 forever (#42). Returning 500 lets the
		// Agent's register retry pick a new join token; nothing has been
		// persisted into tokens yet because CreateToken is below.
		slog.Error("register: hash agent token secret", "err", err)
		writeError(w, http.StatusInternalServerError, "hash secret: "+err.Error())
		return
	}
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

	// Compute current policy snapshot before persisting state — the server is
	// authoritative for desired_version (CONTEXT.md Policy term, bidirectional
	// handshake). Pre-fix this handler stored req.PolicyState.DesiredVersion,
	// which is always nil since Agents do not track or send desired_version.
	// The result was that desired_version stayed at 0 forever and the
	// "desired vs applied" gap invariant — the entire point of the version
	// pair — could never fire. See #43.
	snap, snapErr := s.cfg.Store.GetPolicySnapshot(ctx, ag.ID)
	var policy *api.PolicyPayload
	if snapErr == nil && snap.Hash != req.PolicyState.AppliedHash {
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

	// Persist policy state (best-effort). desired_version comes from the
	// snapshot the server just computed — never from the Agent's report.
	// Agent-reported desired_version is intentionally discarded.
	var desiredVersion *int64
	if snapErr == nil {
		v := snap.Version
		desiredVersion = &v
	}
	_ = s.cfg.Store.UpsertAgentPolicyState(ctx, store.UpsertAgentPolicyStateParams{
		AgentID:         ag.ID,
		DesiredVersion:  desiredVersion,
		AppliedVersion:  req.PolicyState.AppliedVersion,
		AppliedHash:     req.PolicyState.AppliedHash,
		LastApplyStatus: req.PolicyState.LastApplyStatus,
		LastApplyError:  req.PolicyState.LastApplyError,
		LastApplyAt:     time.Unix(req.PolicyState.LastApplyAt, 0),
	})

	// Re-read agent to get the freshest fail_closed_after (operator may have
	// just changed it via `uncluster agents set <name> --fail-closed-after`).
	// Pre-fix this swallowed the error and fell back to a zero-value Agent,
	// which made FailClosedAfter nil — the agent then briefly switched to
	// lenient mode until the next heartbeat (#47). Fix: fall back to the
	// auth-time `ag` (already authoritative for this request) and log the
	// re-read failure so the underlying lock/IO issue is observable.
	failClosedAfter := ag.FailClosedAfter
	if latestAg, err := s.cfg.Store.GetAgent(ctx, ag.ID); err == nil {
		failClosedAfter = latestAg.FailClosedAfter
	} else {
		slog.Warn("heartbeat: failed to re-read agent for fail_closed_after; using auth-time value",
			"agent_id", ag.ID, "err", err)
	}

	// Build commands. Inject check_update if agent_version ≠ expected_version.
	commands := buildUpdateCommands(ctx, s, req.AgentVersion)

	writeJSON(w, http.StatusOK, api.V2HeartbeatResponse{
		AckTS:           req.ObservedAt,
		ServerTime:      now.Unix(),
		Policy:          policy,
		Commands:        commands,
		FailClosedAfter: failClosedAfter,
	})
}
