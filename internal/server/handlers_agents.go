package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleListAgents handles GET /v1/agents.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.cfg.Store.ListAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.AgentDetail, 0, len(agents))
	for _, ag := range agents {
		eps, _ := s.cfg.Store.ListAgentEndpoints(r.Context(), ag.ID)
		out = append(out, agentDetail(ag, eps))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetAgent handles GET /v1/agents/{id} — accepts id or name.
func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idOrName := chi.URLParam(r, "id")

	ag, err := resolveAgent(ctx, s.cfg.Store, idOrName)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	eps, _ := s.cfg.Store.ListAgentEndpoints(ctx, ag.ID)
	writeJSON(w, http.StatusOK, agentDetail(ag, eps))
}

// handleDeleteAgent handles DELETE /v1/agents/{id}.
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idOrName := chi.URLParam(r, "id")

	ag, err := resolveAgent(ctx, s.cfg.Store, idOrName)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if err := s.cfg.Store.RevokeAgent(ctx, ag.ID, time.Now()); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetAgentRequest is the body for PATCH /v1/agents/{id}.
type SetAgentRequest struct {
	FailClosedAfter *int64 `json:"fail_closed_after"` // seconds; null clears it
}

// handleSetAgent handles PATCH /v1/agents/{id}.
func (s *Server) handleSetAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idOrName := chi.URLParam(r, "id")

	ag, err := resolveAgent(ctx, s.cfg.Store, idOrName)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	var req SetAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if err := s.cfg.Store.SetAgentFailClosedAfter(ctx, ag.ID, req.FailClosedAfter); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func agentDetail(ag store.Agent, eps []store.AgentEndpoint) api.AgentDetail {
	endpoints := make([]api.AgentEndpointSummary, 0, len(eps))
	for _, e := range eps {
		endpoints = append(endpoints, api.AgentEndpointSummary{
			Subnet:  e.Subnet,
			Address: e.Address,
		})
	}
	d := api.AgentDetail{
		ID:              ag.ID,
		Name:            ag.Name,
		Status:          string(ag.Status),
		AgentVersion:    ag.AgentVersion,
		CreatedAt:       ag.CreatedAt.Unix(),
		Endpoints:       endpoints,
		FailClosedAfter: ag.FailClosedAfter,
	}
	if ag.LastSeenAt != nil {
		v := ag.LastSeenAt.Unix()
		d.LastSeenAt = &v
	}
	return d
}
