package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.cfg.Logger))

	r.Get("/healthz", s.handleHealthz)

	// Later phases mount /v1/* subrouters with auth middleware here.

	return r
}
