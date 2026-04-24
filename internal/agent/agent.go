package agent

import (
	"context"
	"log/slog"
	"time"
)

type Agent struct {
	cfg     Config
	client  *ServerClient
	cancels *cancelDispatcher
	logger  *slog.Logger
}

func New(cfg Config, logger *slog.Logger) *Agent {
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg:     cfg,
		client:  NewServerClient(cfg.Server, cfg.AgentToken),
		cancels: newCancelDispatcher(),
		logger:  logger,
	}
}

// Run blocks until ctx is cancelled or auth fails permanently.
func (a *Agent) Run(ctx context.Context) error {
	hbCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	authErrCh := make(chan error, 2)
	go func() { authErrCh <- a.heartbeatLoop(hbCtx) }()
	go func() { authErrCh <- a.pollLoop(hbCtx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-authErrCh:
		cancelAll()
		return err
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	// fire one immediately so registration status is fresh
	if err := a.heartbeatOnce(ctx); err != nil {
		if err == ErrUnauthorized {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := a.heartbeatOnce(ctx); err != nil {
				if err == ErrUnauthorized {
					return err
				}
				a.logger.Warn("heartbeat error", "err", err)
			}
		}
	}
}

func (a *Agent) heartbeatOnce(ctx context.Context) error {
	resp, err := a.client.Heartbeat(ctx, CollectMetrics())
	if err != nil {
		return err
	}
	if len(resp.CancelTaskIDs) > 0 {
		a.cancels.Signal(resp.CancelTaskIDs)
	}
	return nil
}

// pollLoop is completed in Task 6.5 (needs execute.go).
func (a *Agent) pollLoop(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
