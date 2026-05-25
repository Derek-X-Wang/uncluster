package agent

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/version"
)

// HealthProvider is an optional hook for collecting structured health checks
// to include in V2 heartbeat payloads. It is injected by the CLI layer (which
// can safely import `gatekeeper`) to avoid an import cycle.
// If nil, the agent sends an empty health slice.
type HealthProvider func(ctx context.Context) []api.AgentHealthCheck

// EndpointProvider is an optional hook for reporting agent network endpoints.
// If nil, DetectEndpoints(nil) is called.
type EndpointProvider func() []api.AgentEndpoint

type Agent struct {
	cfg              Config
	client           *ServerClient
	cancels          *cancelDispatcher
	logger           *slog.Logger
	healthProvider   HealthProvider   // optional; injected by CLI
	endpointProvider EndpointProvider // optional; injected by CLI or tests
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

// WithHealthProvider attaches an optional health check provider.
func (a *Agent) WithHealthProvider(hp HealthProvider) *Agent {
	a.healthProvider = hp
	return a
}

// WithEndpointProvider attaches an optional endpoint detection override.
func (a *Agent) WithEndpointProvider(ep EndpointProvider) *Agent {
	a.endpointProvider = ep
	return a
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
	// V2 agents (AgentID starts with "ag_") send the typed V2 envelope.
	if strings.HasPrefix(a.cfg.AgentID, "ag_") {
		return a.heartbeatOnceV2(ctx)
	}
	// V1 fallback: metadata-only heartbeat.
	resp, err := a.client.Heartbeat(ctx, CollectMetrics())
	if err != nil {
		return err
	}
	if len(resp.CancelTaskIDs) > 0 {
		a.cancels.Signal(resp.CancelTaskIDs)
	}
	return nil
}

func (a *Agent) heartbeatOnceV2(ctx context.Context) error {
	// Collect endpoints.
	var endpoints []api.AgentEndpoint
	if a.endpointProvider != nil {
		endpoints = a.endpointProvider()
	} else {
		endpoints = DetectEndpoints(nil)
	}

	// Collect health checks; panics/errors must NOT block heartbeat.
	var health []api.AgentHealthCheck
	if a.healthProvider != nil {
		func() {
			defer func() { recover() }() //nolint:errcheck
			health = a.healthProvider(ctx)
		}()
	}

	req := api.V2HeartbeatRequest{
		AgentID:      a.cfg.AgentID,
		AgentVersion: version.Version,
		ObservedAt:   time.Now().Unix(),
		Endpoints:    endpoints,
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  0,
			AppliedHash:     "",
			LastApplyStatus: "ok",
			LastApplyAt:     0,
		},
		Health: health,
	}
	// Best-effort metrics.
	if m := CollectMetrics(); m != nil {
		req.Metrics = m
	}

	_, err := a.client.HeartbeatV2(ctx, req)
	return err
}

func (a *Agent) pollLoop(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		task, err := a.client.NextTask(ctx)
		if err == ErrUnauthorized {
			return err
		}
		if err != nil {
			a.logger.Warn("next-task error", "err", err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if task == nil {
			continue // 204 → reconnect
		}
		exitCode := a.executeTask(ctx, task.TaskID, task.Command)
		if err := a.client.Complete(ctx, task.TaskID, exitCode); err != nil {
			if err == ErrUnauthorized {
				return err
			}
			a.logger.Warn("complete failed", "err", err)
		}
	}
	return nil
}
