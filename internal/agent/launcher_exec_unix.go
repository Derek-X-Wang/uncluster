//go:build !windows

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// This is the real PayloadRunner backing the #187 launcher on Linux/macOS: it
// spawns the payload binary as `<bin> agent run` and returns a PayloadProcess
// the launcher supervises. Windows self-update relocation is a separate slice
// (#139), so there is no Windows PayloadRunner — the Windows agent keeps its
// in-place self-update posture and is never launched through this supervisor.

// defaultStopGrace is how long Stop waits after SIGTERM before escalating to
// SIGKILL. Comfortably under DefaultHealthDeadline so a stop during the health
// window still fits the ≤30s rollback budget.
const defaultStopGrace = 10 * time.Second

// execRunner starts the payload as a child process, wiring the health-marker
// contract. It clears any stale health marker before each Start so the
// launcher's waiter only accepts a fresh commit from the child it just started.
type execRunner struct {
	args       []string // sub-command run on the payload, e.g. {"agent","run"}
	markerPath string   // UNCLUSTER_HEALTH_MARKER passed to the child; "" disables
	grace      time.Duration
	logger     *slog.Logger
}

// newExecRunner builds the production runner: the payload runs `agent run`, is
// told where to write its health marker, and is stopped SIGTERM→SIGKILL.
func newExecRunner(markerPath string, logger *slog.Logger) *execRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &execRunner{
		args:       []string{"agent", "run"},
		markerPath: markerPath,
		grace:      defaultStopGrace,
		logger:     logger,
	}
}

// Start clears the stale health marker, then spawns `<binPath> agent run` in its
// own process group (so Stop can signal the whole child tree) with the health
// marker env var set. Stdout/stderr are inherited so the payload's slog output
// reaches the service journal exactly as a directly-run agent's would.
func (r *execRunner) Start(_ context.Context, binPath string) (PayloadProcess, error) {
	if r.markerPath != "" {
		// Fresh start: a marker left by a previous version's child must not be
		// read as this child's health commit.
		_ = os.Remove(r.markerPath)
	}
	cmd := exec.Command(binPath, r.args...)
	cmd.Env = os.Environ()
	if r.markerPath != "" {
		cmd.Env = append(cmd.Env, HealthMarkerEnv+"="+r.markerPath)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Give the child its own process group so Stop can SIGTERM/SIGKILL the group
	// (the child plus anything it spawns) rather than just the immediate pid.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("launcher: exec %s: %w", binPath, err)
	}
	return newExecProcess(cmd, r.grace, r.logger), nil
}

// execProcess wraps a started payload child. A single internal reaper goroutine
// calls cmd.Wait() exactly once; Wait() and Stop() both synchronise on its
// completion, so the launcher can safely call Stop() and drain Wait() without
// double-reaping.
type execProcess struct {
	cmd     *exec.Cmd
	grace   time.Duration
	logger  *slog.Logger
	done    chan struct{}
	waitErr error
}

func newExecProcess(cmd *exec.Cmd, grace time.Duration, logger *slog.Logger) *execProcess {
	p := &execProcess{cmd: cmd, grace: grace, logger: logger, done: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	return p
}

// Wait blocks until the child exits and returns its exit status (nil = clean;
// *exec.ExitError carries the code for a non-zero exit), propagating the child's
// outcome to the launcher.
func (p *execProcess) Wait() error {
	<-p.done
	return p.waitErr
}

// Stop requests graceful termination: SIGTERM the child's process group, wait up
// to grace (or until ctx is done), then SIGKILL. Returns once the child is
// reaped. Safe to call after the child has already exited (no-op).
func (p *execProcess) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return nil // already exited
	default:
	}
	p.signalGroup(syscall.SIGTERM)
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
	case <-time.After(p.grace):
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	p.logger.Warn("launcher: payload did not stop on SIGTERM within grace; sending SIGKILL",
		"grace", p.grace, "pid", p.pid())
	p.signalGroup(syscall.SIGKILL)
	<-p.done
	return nil
}

func (p *execProcess) pid() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// signalGroup sends sig to the child's process group (negative pid). Because
// Start set Setpgid, the child is its own group leader and pgid == pid. Falls
// back to signalling just the process if the group signal fails.
func (p *execProcess) signalGroup(sig syscall.Signal) {
	pid := p.pid()
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, sig); err != nil {
		_ = syscall.Kill(pid, sig)
	}
}
