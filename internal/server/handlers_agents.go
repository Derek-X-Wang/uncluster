package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleListAgents handles GET /v1/agents.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	// TODO(S11): replace with a proper ListAgents store method when the nodes
	// table is dropped. For now return an empty list.
	writeJSON(w, http.StatusOK, []api.AgentDetail{})
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

func agentDetail(ag store.Agent, eps []store.AgentEndpoint) api.AgentDetail {
	endpoints := make([]api.AgentEndpointSummary, 0, len(eps))
	for _, e := range eps {
		endpoints = append(endpoints, api.AgentEndpointSummary{
			Subnet:  e.Subnet,
			Address: e.Address,
		})
	}
	d := api.AgentDetail{
		ID:           ag.ID,
		Name:         ag.Name,
		Status:       string(ag.Status),
		AgentVersion: ag.AgentVersion,
		CreatedAt:    ag.CreatedAt.Unix(),
		Endpoints:    endpoints,
	}
	if ag.LastSeenAt != nil {
		v := ag.LastSeenAt.Unix()
		d.LastSeenAt = &v
	}
	return d
}
