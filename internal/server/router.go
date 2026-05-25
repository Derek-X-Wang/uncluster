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
		// Caller token — operator management plane.
		v1.Group(func(caller chi.Router) {
			caller.Use(s.requireAuth(store.TokenCaller))
			caller.Post("/tokens", s.handleCreateToken)
			caller.Get("/tokens", s.handleListTokens)
			caller.Delete("/tokens/{id}", s.handleRevokeToken)
		})
		// Agent registration — unauthenticated but validates join token in-handler.
		v1.Group(func(agent chi.Router) {
			agent.Post("/agent/register", s.handleAgentRegister)
		})
		// Agent heartbeat — authenticated with agent token.
		v1.Group(func(agent chi.Router) {
			agent.Use(s.requireAuth(store.TokenAgent))
			agent.Post("/agent/heartbeat", s.handleAgentHeartbeat)
		})
		// ACL management — caller token.
		v1.Group(func(caller chi.Router) {
			caller.Use(s.requireAuth(store.TokenCaller))
			caller.Post("/acl", s.handleCreateACL)
			caller.Delete("/acl/{id}", s.handleDeleteACL)
			caller.Get("/acl", s.handleListACL)
		})
		// V2 agents — caller token for list/detail/revoke/set.
		v1.Group(func(caller chi.Router) {
			caller.Use(s.requireAuth(store.TokenCaller))
			caller.Get("/agents", s.handleListAgents)
			caller.Get("/agents/{id}", s.handleGetAgent)
			caller.Delete("/agents/{id}", s.handleDeleteAgent)
			caller.Patch("/agents/{id}", s.handleSetAgent)
		})
		// Audit log — caller token.
		v1.Group(func(caller chi.Router) {
			caller.Use(s.requireAuth(store.TokenCaller))
			caller.Get("/audit/certs", s.handleListCertEvents)
		})
		// Cert issuance — caller token.
		v1.Group(func(caller chi.Router) {
			caller.Use(s.requireAuth(store.TokenCaller))
			caller.Post("/certs", s.handleIssueCert)
		})
	})

	return r
}
