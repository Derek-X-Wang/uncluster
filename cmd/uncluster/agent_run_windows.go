//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/cli"
)

// scmErrorLogName is the diagnostic log the agent writes its stderr to when
// running under SCM. It lives in the same C:\ProgramData\uncluster tree as
// agent.toml so all Windows agent state sits together.
const scmErrorLogName = "agent.err.log"

// scmErrorLogPath returns the SCM stderr-log path, derived from the same
// ProgramData base as the system config (honoring the PROGRAMDATA env override
// agent.SystemConfigPath() uses) — i.e. C:\ProgramData\uncluster\agent.err.log.
func scmErrorLogPath() string {
	return filepath.Join(filepath.Dir(agent.SystemConfigPath()), scmErrorLogName)
}

// openSCMErrorLog opens (append, create) the SCM stderr log and returns it as
// an io.WriteCloser. Under SCM, os.Stderr is wired to NUL, so a RunAgent error
// (config-read failure, unreadable agent.toml, any startup death) would be
// invisible — the #101 lesson made worse on Windows where there isn't even a
// console to read (#128). Redirecting to a real file makes those failures
// diagnosable.
//
// On success it also locks down the log's ACL (SYSTEM + Administrators full,
// agent service account write) best-effort — a failure to tighten the ACL is
// logged but never blocks the agent from starting, since visibility of errors
// is the whole point and a slightly-loose diagnostic log is better than none.
func openSCMErrorLog(path string) (io.WriteCloser, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if aclErr := restrictErrorLogACL(path); aclErr != nil {
		slog.Warn("agent: could not tighten SCM error-log ACL", "path", path, "error", aclErr)
	}
	return f, nil
}

// runAsWindowsService detects whether the binary is running under the
// Windows Service Control Manager. If so — and only if argv indicates
// `agent run` (the only path SCM is ever expected to take, because that's
// what the service unit binds to) — it routes through svc.Run so the
// SCM control-handler handshake completes and Windows reports the
// service as Running.
//
// Pre-#88 the binary returned from main with no svc.Run call: SCM never
// got the "started" status word, hit its 30s timeout, and `net start`
// returned exit 2 even though the agent process was alive and heartbeating
// to the CP. See #88 for the full trace.
//
// The SCM-registered service name is agent.WindowsServiceName, shared with
// the installer and restart paths so the name SCM dispatches on cannot
// drift from the name it was registered under.
//
// Returns:
//   - handled=true with err=nil  → SCM lifecycle completed; main exits 0.
//   - handled=true with err!=nil → SCM lifecycle failed; main exits 1.
//   - handled=false              → not under SCM (or argv doesn't match);
//     control returns to main which falls through to the cobra path.
func runAsWindowsService() (handled bool, err error) {
	isService, sErr := svc.IsWindowsService()
	if sErr != nil {
		// Detection itself failed. Fall through to cobra rather than
		// erroring out — the operator may be running interactively.
		return false, nil
	}
	if !isService {
		return false, nil
	}
	// Sanity check argv: the service unit binds to `<exe> agent run`.
	// If something else is passed, fall through (defensive — should not
	// happen in production).
	if !argvIsAgentRun(os.Args) {
		return false, nil
	}
	if runErr := svc.Run(agent.WindowsServiceName, &agentService{}); runErr != nil {
		return true, fmt.Errorf("svc.Run %s: %w", agent.WindowsServiceName, runErr)
	}
	return true, nil
}

// argvIsAgentRun reports whether argv looks like `<exe> agent run [...]`.
// Defensive against SCM passing other args (it shouldn't, given the
// service unit's BinaryPathName, but check anyway).
func argvIsAgentRun(argv []string) bool {
	if len(argv) < 3 {
		return false
	}
	return argv[1] == "agent" && argv[2] == "run"
}

// agentService implements svc.Handler. The Execute method drives the SCM
// state machine: StartPending → Running → (loop on control requests) →
// StopPending → Stopped. The actual agent work runs via cli.RunAgent in
// a goroutine; svc.Run's caller (Windows) blocks waiting for Execute to
// return, so we cannot run the agent inline.
type agentService struct{}

// reportStopped tells SCM the service has stopped and returns the
// (ssec, errno) pair Execute must return. Both terminal paths in Execute
// (operator-initiated Stop/Shutdown and the run loop exiting on its own)
// converge here. A non-nil err is logged and surfaced to SCM as a
// service-specific error (ssec=true, errno=1) so it lands in the
// Application Event Log; a nil err is a clean stop (false, 0).
func reportStopped(status chan<- svc.Status, err error) (ssec bool, errno uint32) {
	if err != nil {
		slog.Error("agent: run loop returned error under SCM", "error", err)
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	status <- svc.Status{State: svc.Stopped}
	return false, 0
}

// Execute is invoked by svc.Run once SCM has connected. The handler
// contract (per the [Service Control Handler protocol]):
//
//  1. Report StartPending immediately so SCM knows we have begun.
//  2. Start the long-running work asynchronously.
//  3. Report Running with the set of control requests we accept
//     (Stop + Shutdown are sufficient for the agent — no Pause/Continue).
//  4. Loop on the control channel `r` until SCM sends Stop or Shutdown,
//     responding to Interrogate by reflecting the current status back.
//  5. Cancel the agent's context, report StopPending while it drains,
//     then Stopped.
//
// [Service Control Handler protocol]:
// https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function
func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (ssec bool, errno uint32) {
	const acceptedControls = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Under SCM, os.Stderr is wired to NUL — any RunAgent diagnostic (config
	// read failure, unreadable agent.toml, startup death) would vanish (#128).
	// Redirect to C:\ProgramData\uncluster\agent.err.log so failures are
	// visible. If the log can't be opened, fall back to os.Stderr (no worse
	// than before) rather than refusing to start.
	var stderrW io.Writer = os.Stderr
	logPath := scmErrorLogPath()
	if lf, err := openSCMErrorLog(logPath); err != nil {
		slog.Error("agent: could not open SCM error log; falling back to NUL stderr",
			"path", logPath, "error", err)
	} else {
		stderrW = lf
		defer lf.Close()
	}

	// runErr is written exactly once, when RunAgent returns, then closed.
	// Buffered so the goroutine cannot block if Execute has already
	// returned (shouldn't happen, but defensive against SCM oddities).
	runErr := make(chan error, 1)
	go func() {
		defer close(runErr)
		runErr <- cli.RunAgent(ctx, stderrW)
	}()

	status <- svc.Status{State: svc.Running, Accepts: acceptedControls}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// SCM is checking we are alive. Reflect the current
				// status back. Per Microsoft's docs, the handler MAY
				// repeat the same status code multiple times in a row;
				// that's deliberate and SCM tolerates it.
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Drain path: tell SCM we're stopping, cancel the
				// agent's context to start its shutdown, then wait for
				// the run loop to finish and report Stopped.
				status <- svc.Status{State: svc.StopPending}
				cancel()
				return reportStopped(status, <-runErr)
			default:
				slog.Warn("agent: unexpected SCM control request", "cmd", c.Cmd)
			}
		case err := <-runErr:
			// RunAgent returned on its own (graceful deprovision,
			// fatal error, etc.) — tell SCM we're done.
			status <- svc.Status{State: svc.StopPending}
			return reportStopped(status, err)
		}
	}
}
