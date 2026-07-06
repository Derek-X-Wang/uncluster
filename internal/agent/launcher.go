package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Launcher is the root-owned-but-unprivileged supervisor that ADR-0004/#187
// interpose between the service manager and the self-updatable payload. The
// service manager runs `<launcher> agent launch` as the low-priv service
// account; the launcher execs the PayloadStore's current version as a child
// (`<payload> agent run`) and:
//
//   - requires a HEALTH COMMIT (config loaded + first successful heartbeat)
//     within healthDeadline; a version that exits early or misses the deadline
//     is rolled back to the previous (last-known-good) payload and quarantined,
//     so the update flow does not immediately re-activate the same bad version
//     while the Control plane still advertises it;
//   - watches a pending-update marker written by the payload's update handler
//     after it stages+activates a new version, and restarts the child onto the
//     new current — re-arming the health watch so a bad update self-heals.
//
// The launcher itself is never self-updated (updating it needs root; that is a
// separate `agent install`), so it stays root-owned at the strict-chain install
// path and doubles as sshd's AuthorizedPrincipalsCommand target (#185). The
// resident-parent model keeps the gatekeeper continuously up: a failed update
// rolls back in-process (well under the ≤30s ADR-0006 budget) without waiting
// on a service-manager restart cycle.
type Launcher struct {
	store  *PayloadStore
	runner PayloadRunner
	health HealthWaiter
	logger *slog.Logger

	// healthDeadline bounds how long a freshly-started version has to commit
	// health before it is judged bad. Kept comfortably under the ≤30s rollback
	// budget so rollback + respawn still fit.
	healthDeadline time.Duration

	// pendingUpdatePath is the marker the payload's update handler touches after
	// staging+activating a new version, asking the launcher to restart onto it.
	pendingUpdatePath string

	// pollInterval is how often the steady-state supervisor checks for the
	// pending-update marker.
	pollInterval time.Duration
}

// PayloadRunner starts a payload binary and returns a running handle. Injected
// so the supervisor state machine is testable without spawning real processes.
type PayloadRunner interface {
	Start(ctx context.Context, binPath string) (PayloadProcess, error)
}

// PayloadProcess is a started payload. Wait blocks until it exits (nil = clean).
// Stop requests graceful termination and returns when the process is gone.
type PayloadProcess interface {
	Wait() error
	Stop(ctx context.Context) error
}

// HealthWaiter blocks until the running payload version signals healthy, or ctx
// is done (deadline/cancel). Injected for tests.
type HealthWaiter interface {
	WaitHealthy(ctx context.Context, version string) error
}

// LauncherConfig parameterises a Launcher.
type LauncherConfig struct {
	Store             *PayloadStore
	Runner            PayloadRunner
	Health            HealthWaiter
	Logger            *slog.Logger
	HealthDeadline    time.Duration
	PendingUpdatePath string
	PollInterval      time.Duration
}

// DefaultHealthDeadline is the default health-commit budget for a freshly
// started payload version (< the ≤30s ADR-0006 rollback budget).
const DefaultHealthDeadline = 25 * time.Second

// DefaultUpdatePollInterval is how often the steady-state supervisor polls the
// pending-update marker.
const DefaultUpdatePollInterval = time.Second

// NewLauncher builds a Launcher, applying defaults for unset timing fields.
func NewLauncher(cfg LauncherConfig) *Launcher {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HealthDeadline <= 0 {
		cfg.HealthDeadline = DefaultHealthDeadline
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultUpdatePollInterval
	}
	return &Launcher{
		store:             cfg.Store,
		runner:            cfg.Runner,
		health:            cfg.Health,
		logger:            cfg.Logger,
		healthDeadline:    cfg.HealthDeadline,
		pendingUpdatePath: cfg.PendingUpdatePath,
		pollInterval:      cfg.PollInterval,
	}
}

// Run supervises the payload until ctx is cancelled (service stop) or an
// unrecoverable error (no current version, or a bad version with no
// last-known-good to roll back to). It returns ctx.Err() on a clean shutdown.
func (l *Launcher) Run(ctx context.Context) error {
	for {
		curBin, curVer, err := l.store.Current()
		if err != nil {
			return fmt.Errorf("launcher: resolve current payload: %w", err)
		}
		l.logger.Info("launcher: starting payload", "version", curVer, "binary", curBin)

		proc, err := l.runner.Start(ctx, curBin)
		if err != nil {
			return fmt.Errorf("launcher: start payload %s: %w", curVer, err)
		}

		outcome, err := l.superviseUntilHealthy(ctx, proc, curVer)
		if err != nil {
			return err
		}
		switch outcome {
		case superviseShutdown:
			return ctx.Err()
		case superviseUnhealthy:
			// Roll back + quarantine, then loop to start the restored version.
			if err := l.demoteBadVersion(curVer); err != nil {
				return err
			}
			continue
		case superviseHealthy:
			// fall through to steady-state supervision below
		}

		outcome, err = l.superviseSteadyState(ctx, proc, curVer)
		if err != nil {
			return err
		}
		switch outcome {
		case superviseShutdown:
			return ctx.Err()
		case supervisePendingUpdate, superviseExited:
			// Either an update asked for a restart (current now points at the
			// new version) or the healthy child exited and the service policy
			// is to keep the gatekeeper up — loop to (re)start current.
			continue
		}
	}
}

type superviseOutcome int

const (
	superviseHealthy superviseOutcome = iota
	superviseUnhealthy
	superviseShutdown
	supervisePendingUpdate
	superviseExited
)

// superviseUntilHealthy waits for the started version to commit health within
// the deadline, race against early exit and shutdown.
func (l *Launcher) superviseUntilHealthy(ctx context.Context, proc PayloadProcess, version string) (superviseOutcome, error) {
	hctx, cancel := context.WithTimeout(ctx, l.healthDeadline)
	defer cancel()

	healthCh := make(chan error, 1)
	go func() { healthCh <- l.health.WaitHealthy(hctx, version) }()
	exitCh := make(chan error, 1)
	go func() { exitCh <- proc.Wait() }()

	select {
	case <-ctx.Done():
		l.stop(proc)
		<-exitCh
		return superviseShutdown, nil
	case exitErr := <-exitCh:
		// Exited before health committed → bad version.
		if ctx.Err() != nil {
			return superviseShutdown, nil
		}
		l.logger.Warn("launcher: payload exited before health commit", "version", version, "err", exitErr)
		return superviseUnhealthy, nil
	case herr := <-healthCh:
		if herr == nil {
			l.logger.Info("launcher: payload health committed", "version", version)
			return superviseHealthy, nil
		}
		// Deadline missed or watch cancelled.
		if ctx.Err() != nil {
			l.stop(proc)
			<-exitCh
			return superviseShutdown, nil
		}
		l.logger.Warn("launcher: payload missed health deadline", "version", version,
			"deadline", l.healthDeadline, "err", herr)
		l.stop(proc)
		<-exitCh
		return superviseUnhealthy, nil
	}
}

// superviseSteadyState watches a healthy child for a pending-update request or
// exit, until shutdown.
func (l *Launcher) superviseSteadyState(ctx context.Context, proc PayloadProcess, version string) (superviseOutcome, error) {
	exitCh := make(chan error, 1)
	go func() { exitCh <- proc.Wait() }()

	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			l.stop(proc)
			<-exitCh
			return superviseShutdown, nil
		case exitErr := <-exitCh:
			if ctx.Err() != nil {
				return superviseShutdown, nil
			}
			l.logger.Warn("launcher: healthy payload exited; restarting", "version", version, "err", exitErr)
			return superviseExited, nil
		case <-ticker.C:
			if l.consumePendingUpdate() {
				l.logger.Info("launcher: pending update detected; restarting onto new current", "from_version", version)
				l.stop(proc)
				<-exitCh
				return supervisePendingUpdate, nil
			}
		}
	}
}

// consumePendingUpdate reports whether the pending-update marker exists, and
// removes it so the restart happens exactly once per update.
func (l *Launcher) consumePendingUpdate() bool {
	if l.pendingUpdatePath == "" {
		return false
	}
	if _, err := os.Stat(l.pendingUpdatePath); err != nil {
		return false
	}
	if err := os.Remove(l.pendingUpdatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		l.logger.Warn("launcher: could not clear pending-update marker", "path", l.pendingUpdatePath, "err", err)
	}
	return true
}

// demoteBadVersion quarantines the failed version and rolls current back to the
// last-known-good payload. A missing last-known-good is unrecoverable (the
// launcher cannot start any payload) and surfaces as a hard error.
func (l *Launcher) demoteBadVersion(version string) error {
	if err := l.store.Quarantine(version); err != nil {
		l.logger.Warn("launcher: could not quarantine bad version", "version", version, "err", err)
	}
	rolledTo, err := l.store.Rollback()
	if err != nil {
		return fmt.Errorf("launcher: bad version %s and no last-known-good to roll back to: %w", version, err)
	}
	l.logger.Warn("launcher: rolled back after failed version", "bad_version", version, "restored_version", rolledTo)
	return nil
}

// stop requests graceful termination of proc with a bounded grace period.
func (l *Launcher) stop(proc PayloadProcess) {
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := proc.Stop(stopCtx); err != nil {
		l.logger.Warn("launcher: error stopping payload", "err", err)
	}
}
