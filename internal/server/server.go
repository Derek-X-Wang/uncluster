// Package server is the Uncluster control-plane HTTP layer.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

type Config struct {
	Store  store.Store
	Logger *slog.Logger
	// OutputCapBytes is the per-task output cap. Defaults to 10 MiB if zero.
	OutputCapBytes int64
}

type Server struct {
	cfg        Config
	dispatcher *inProcessDispatcher
	handler    http.Handler
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OutputCapBytes == 0 {
		cfg.OutputCapBytes = 10 * 1024 * 1024
	}
	s := &Server{
		cfg:        cfg,
		dispatcher: newInProcessDispatcher(),
	}
	s.handler = s.buildRouter()
	return s
}

// Handler returns the http.Handler for mounting or testing.
func (s *Server) Handler() http.Handler { return s.handler }

// Start runs the server on addr until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	hs := &http.Server{
		Addr:              addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	s.cfg.Logger.Info("server listening", "addr", addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
