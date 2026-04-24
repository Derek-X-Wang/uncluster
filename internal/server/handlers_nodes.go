package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.cfg.Store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		var meta map[string]any
		_ = json.Unmarshal([]byte(n.Metadata), &meta)
		out = append(out, api.NodeSummary{
			ID: n.ID, Name: n.Name, Status: string(n.Status),
			CreatedAt: n.CreatedAt.Unix(), LastSeenAt: api.TimePtr(n.LastSeenAt),
			Metadata: meta,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	node, err := s.cfg.Store.GetNode(r.Context(), idOrName)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), idOrName)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(node.Metadata), &meta)
	writeJSON(w, http.StatusOK, api.NodeSummary{
		ID: node.ID, Name: node.Name, Status: string(node.Status),
		CreatedAt: node.CreatedAt.Unix(), LastSeenAt: api.TimePtr(node.LastSeenAt),
		Metadata: meta,
	})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	node, err := s.cfg.Store.GetNode(r.Context(), idOrName)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), idOrName)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err := s.cfg.Store.RevokeNode(r.Context(), node.ID, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
