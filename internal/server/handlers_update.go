package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleGetUpdatePlan serves GET /v1/agent/update-plan.
// The caller is an authenticated agent (agent token required).
// Returns the current update policy or an empty struct when none is set.
func (s *Server) handleGetUpdatePlan(w http.ResponseWriter, r *http.Request) {
	policy, err := s.cfg.Store.GetUpdatePolicy(r.Context())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No policy set — return empty response (no update mandated).
			writeJSON(w, http.StatusOK, api.UpdatePlanResponse{})
			return
		}
		writeError(w, http.StatusInternalServerError, "get update policy")
		return
	}
	writeJSON(w, http.StatusOK, api.UpdatePlanResponse{
		ExpectedVersion:   policy.ExpectedVersion,
		AssetURLTemplate:  policy.AssetURLTemplate,
		SHA256URLTemplate: policy.SHA256URLTemplate,
		Force:             policy.Force,
	})
}

// buildUpdateCommands checks the update policy and returns a check_update
// command when the agent's reported version differs from expected.
// Returns an empty (non-nil) slice when no commands are needed.
func buildUpdateCommands(ctx context.Context, s *Server, agentVersion string) []any {
	cmds := make([]any, 0)
	policy, err := s.cfg.Store.GetUpdatePolicy(ctx)
	if err != nil {
		// ErrNotFound = no policy set; any other error = best-effort skip.
		return cmds
	}
	if policy.ExpectedVersion == "" {
		return cmds
	}
	if agentVersion != policy.ExpectedVersion || policy.Force {
		cmds = append(cmds, api.CheckUpdateCommand{
			Type:    "check_update",
			Version: policy.ExpectedVersion,
		})
	}
	return cmds
}

// handleSetUpdatePolicy serves POST /v1/server/update.
// The caller is an authenticated operator (caller token required).
func (s *Server) handleSetUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var req api.SetUpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.ExpectedVersion == "" {
		writeError(w, http.StatusBadRequest, "expected_version is required")
		return
	}
	if err := s.cfg.Store.SetUpdatePolicy(r.Context(), store.SetUpdatePolicyParams{
		ExpectedVersion:   req.ExpectedVersion,
		AssetURLTemplate:  req.AssetURLTemplate,
		SHA256URLTemplate: req.SHA256URLTemplate,
		Force:             req.Force,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "set update policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
