package server

import (
	"encoding/json"
	"net/http"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/version"
)

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.HealthResponse{OK: true, Version: version.Version})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
