package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/derek-x-wang/uncluster/internal/store"
)

func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.cfg.Logger))

	r.Get("/healthz", s.handleHealthz)

	r.Route("/v1", func(v1 chi.Router) {
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Post("/tokens", s.handleCreateToken)
			cli.Get("/tokens", s.handleListTokens)
			cli.Delete("/tokens/{id}", s.handleRevokeToken)
		})
	})

	return r
}
