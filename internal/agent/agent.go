package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/version"
)

// ErrDeprovisioned is returned by Run() when the agent is explicitly revoked
// by the control plane (410 Gone). The service supervisor should NOT restart.
var ErrDeprovisioned = errors.New("agent: deprovisioned by control plane")

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
	logger           *slog.Logger
	healthProvider   HealthProvider   // optional; injected by CLI
	endpointProvider EndpointProvider // optional; injected by CLI or tests

	policyMu       sync.Mutex
	policyStateVal policyState      // last-applied policy state; guarded by policyMu
	applyCh        chan applyRequest // serialised policy-apply channel; set in Run; nil until Run called

	// Fail-closed-after: wipe principals if no successful heartbeat for this long.
	fcaMu             sync.Mutex
	failClosedAfterSec *int64    // nil = disabled; updated from heartbeat response
	lastHeartbeatOK   time.Time // last time a heartbeat succeeded
}

func New(cfg Config, logger *slog.Logger) *Agent {
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg:    cfg,
		client: NewServerClient(cfg.Server, cfg.AgentToken),
		logger: logger,
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
//
// Shutdown ordering matters for the apply channel (#45): the heartbeat
// goroutine sends snapshots into applyCh, the apply goroutine receives them.
// Previously Run() closed applyCh via a defer while the heartbeat goroutine
// could still be inside heartbeatOnceV2 — a race-with-shutdown caused a
// send-on-closed-channel panic.
//
// Fix: track the heartbeat goroutine with a WaitGroup and close applyCh only
// after Wait() returns. The apply goroutine then drains and exits on the
// channel close. We also wait for the apply goroutine itself so Run does not
// leak a worker once it returns.
func (a *Agent) Run(ctx context.Context) error {
	hbCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	// Start the serialised policy-apply worker.
	a.applyCh = make(chan applyRequest, 1)
	var applyWG sync.WaitGroup
	applyWG.Add(1)
	go func() {
		defer applyWG.Done()
		for req := range a.applyCh {
			a.runApplyPolicy(req.snapshot)
		}
	}()

	authErrCh := make(chan error, 1)
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		authErrCh <- a.heartbeatLoop(hbCtx)
	}()

	// shutdown drains both goroutines in order: heartbeat first (so it can
	// finish any in-flight send into applyCh), then close applyCh, then wait
	// for the apply worker to drain queued requests and exit.
	shutdown := func() {
		cancelAll()
		hbWG.Wait()
		close(a.applyCh)
		applyWG.Wait()
	}

	var runErr error
	select {
	case <-ctx.Done():
		// Caller cancelled; clean exit.
	case err := <-authErrCh:
		runErr = err
	}
	shutdown()
	return runErr
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	// fire one immediately so registration status is fresh
	if err := a.heartbeatOnce(ctx); err != nil {
		switch {
		case errors.Is(err, ErrUnauthorized):
			a.logger.Error("auth_failed: heartbeat unauthorized; operator intervention required; principals preserved")
			return err
		case errors.Is(err, ErrRevoked):
			a.logger.Error("deprovisioned: control plane revoked this agent; wiping principals")
			return a.onRevoked()
		}
	}
	// Check for fail-closed every 30 seconds.
	fcTicker := time.NewTicker(30 * time.Second)
	defer fcTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := a.heartbeatOnce(ctx); err != nil {
				switch {
				case errors.Is(err, ErrUnauthorized):
					a.logger.Error("auth_failed: heartbeat unauthorized; operator intervention required; principals preserved")
					return err
				case errors.Is(err, ErrRevoked):
					a.logger.Error("deprovisioned: control plane revoked this agent; wiping principals")
					return a.onRevoked()
				default:
					a.logger.Warn("heartbeat error", "err", err)
				}
			}
		case <-fcTicker.C:
			a.checkFailClosed()
		}
	}
}

// checkFailClosed wipes principals if fail_closed_after has elapsed since last
// successful heartbeat. Safe to call concurrently; no-op if fail-closed not set.
func (a *Agent) checkFailClosed() {
	a.fcaMu.Lock()
	fca := a.failClosedAfterSec
	lastOK := a.lastHeartbeatOK
	a.fcaMu.Unlock()

	if fca == nil || *fca <= 0 {
		return
	}
	if lastOK.IsZero() {
		return // no heartbeat yet; don't wipe
	}
	if time.Since(lastOK) >= time.Duration(*fca)*time.Second {
		a.logger.Warn("fail_closed: wiping principals due to heartbeat timeout",
			"fail_closed_after_sec", *fca,
			"last_heartbeat_ok", lastOK)
		// Apply empty policy to wipe all principals.
		a.runApplyPolicy(api.PolicyPayload{
			Version:    0,
			Hash:       "",
			Principals: nil,
		})
	}
}

// onRevoked handles explicit deprovision (410 Gone). Wipes principals,
// writes .deprovisioned marker, returns ErrDeprovisioned so Run() exits
// with an error that supervisors can distinguish.
func (a *Agent) onRevoked() error {
	principalsDir := a.cfg.ExpectedPaths.PrincipalsDir
	if principalsDir != "" {
		// Remove all principal files in the dir.
		entries, err := os.ReadDir(principalsDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					_ = os.Remove(filepath.Join(principalsDir, e.Name()))
				}
			}
		}
	}
	// Write .deprovisioned marker next to agent.toml so the supervisor sees it.
	configDir := a.cfg.ExpectedPaths.CAPubkey // best proxy for config dir; fall back
	if configDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			configDir = filepath.Join(h, ".config", "uncluster")
		}
	} else {
		configDir = filepath.Dir(configDir)
	}
	if configDir != "" {
		marker := filepath.Join(configDir, ".deprovisioned")
		_ = os.WriteFile(marker, []byte("deprovisioned\n"), 0o600)
	}
	return ErrDeprovisioned
}

func (a *Agent) heartbeatOnce(ctx context.Context) error {
	return a.heartbeatOnceV2(ctx)
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

	// Snapshot current policy state (last-applied).
	a.policyMu.Lock()
	ps := a.policyStateVal
	a.policyMu.Unlock()

	req := api.V2HeartbeatRequest{
		AgentID:      a.cfg.AgentID,
		AgentVersion: version.Version,
		ObservedAt:   time.Now().Unix(),
		Endpoints:    endpoints,
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  ps.appliedVersion,
			AppliedHash:     ps.appliedHash,
			LastApplyStatus: ps.lastApplyStatus,
			LastApplyError:  ps.lastApplyError,
			LastApplyAt:     ps.lastApplyAt,
		},
		Health: health,
	}
	if req.PolicyState.LastApplyStatus == "" {
		req.PolicyState.LastApplyStatus = "ok"
	}
	// Best-effort metrics.
	if m := CollectMetrics(); m != nil {
		req.Metrics = m
	}

	resp, err := a.client.HeartbeatV2(ctx, req)
	if err != nil {
		return err
	}

	// Track successful heartbeat time and update fail-closed-after from response.
	a.fcaMu.Lock()
	a.lastHeartbeatOK = time.Now()
	a.failClosedAfterSec = resp.FailClosedAfter
	a.fcaMu.Unlock()

	// If the server sent a policy snapshot, dispatch it for application.
	if resp.Policy != nil && a.applyCh != nil {
		select {
		case a.applyCh <- applyRequest{snapshot: *resp.Policy}:
		default:
			// Channel already has a pending apply; replace it (coalesce).
			// Drain and re-send. Non-blocking drain to avoid deadlock.
			select {
			case <-a.applyCh:
			default:
			}
			select {
			case a.applyCh <- applyRequest{snapshot: *resp.Policy}:
			default:
			}
		}
	}

	// Dispatch server commands (e.g. check_update).
	for _, rawCmd := range resp.Commands {
		if err := a.dispatchCommand(ctx, rawCmd); err != nil {
			a.logger.Warn("command dispatch error", "err", err)
		}
	}

	return nil
}

// dispatchCommand routes a single command from the heartbeat response.
func (a *Agent) dispatchCommand(ctx context.Context, rawCmd any) error {
	// Re-marshal to get the type field.
	b, err := json.Marshal(rawCmd)
	if err != nil {
		return err
	}
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &typed); err != nil {
		return err
	}
	switch typed.Type {
	case "check_update":
		var cmd api.CheckUpdateCommand
		if err := json.Unmarshal(b, &cmd); err != nil {
			return err
		}
		return a.HandleCheckUpdate(ctx, cmd)
	default:
		a.logger.Debug("unknown command type; ignoring", "type", typed.Type)
	}
	return nil
}

