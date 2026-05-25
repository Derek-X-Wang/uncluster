package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleCreateACL handles POST /v1/acl.
//
// Body: { caller, agent, username } where caller is a caller token id and
// agent is an agent id or name. Re-granting is idempotent.
func (s *Server) handleCreateACL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req api.CreateACLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Caller == "" || req.Agent == "" || req.Username == "" {
		writeError(w, http.StatusBadRequest, "caller, agent, and username are required")
		return
	}

	// Resolve caller token: accept token id directly.
	callerTok, err := s.cfg.Store.GetTokenByID(ctx, req.Caller)
	if err != nil {
		writeError(w, http.StatusNotFound, "caller token not found")
		return
	}
	if callerTok.Kind != store.TokenCaller {
		writeError(w, http.StatusBadRequest, "caller must be a caller token id")
		return
	}

	// Resolve agent by id or name.
	agent, err := resolveAgent(ctx, s.cfg.Store, req.Agent)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	entry, err := s.cfg.Store.CreateACL(ctx, store.CreateACLParams{
		CallerTokenID: callerTok.ID,
		AgentID:       agent.ID,
		Username:      req.Username,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, aclSummary(entry))
}

// handleDeleteACL handles DELETE /v1/acl/{id}.
func (s *Server) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if err := s.cfg.Store.DeleteACL(ctx, id); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "acl entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListACL handles GET /v1/acl?caller=&agent=.
func (s *Server) handleListACL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := store.ListACLFilter{
		CallerTokenID: r.URL.Query().Get("caller"),
		AgentID:       r.URL.Query().Get("agent"),
	}
	entries, err := s.cfg.Store.ListACL(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.ACLEntrySummary, 0, len(entries))
	for _, e := range entries {
		out = append(out, aclSummary(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// aclSummary converts a store.ACLEntry to the wire shape.
func aclSummary(e store.ACLEntry) api.ACLEntrySummary {
	return api.ACLEntrySummary{
		ID:            e.ID,
		CallerTokenID: e.CallerTokenID,
		AgentID:       e.AgentID,
		Username:      e.Username,
		CreatedAt:     e.CreatedAt.Unix(),
		CreatedBy:     e.CreatedBy,
	}
}

// resolveAgent looks up an agent by id (ag_ prefix) or name.
func resolveAgent(ctx context.Context, st store.Store, idOrName string) (store.Agent, error) {
	if strings.HasPrefix(idOrName, "ag_") {
		ag, err := st.GetAgent(ctx, idOrName)
		if err == nil {
			return ag, nil
		}
	}
	return st.GetAgentByName(ctx, idOrName)
}
