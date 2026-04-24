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
		v1.Group(func(agent chi.Router) {
			// /v1/agent/register is unauthenticated but validates the join token in-handler.
			agent.Post("/agent/register", s.handleAgentRegister)
		})
		v1.Group(func(agent chi.Router) {
			agent.Use(s.requireAuth(store.TokenAgent))
			agent.Post("/agent/heartbeat", s.handleAgentHeartbeat)
		})
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Get("/nodes", s.handleListNodes)
			cli.Get("/nodes/{id}", s.handleGetNode)
			cli.Delete("/nodes/{id}", s.handleDeleteNode)
		})
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Post("/tasks", s.handleCreateTask)
			cli.Get("/tasks", s.handleListTasks)
			cli.Get("/tasks/{id}", s.handleGetTask)
			cli.Get("/tasks/{id}/stream", s.handleTaskStream)
		})
		v1.Group(func(agent chi.Router) {
			agent.Use(s.requireAuth(store.TokenAgent))
			agent.Get("/agent/next-task", s.handleAgentNextTask)
			agent.Post("/agent/tasks/{id}/chunks", s.handleAgentChunks)
			agent.Post("/agent/tasks/{id}/complete", s.handleAgentComplete)
		})
	})

	return r
}
