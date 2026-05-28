//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/derek-x-wang/uncluster/internal/cli"
)

// windowsServiceName must match the service Name registered by
// internal/gatekeeper/service_windows.go's buildService. SCM looks the
// handler up by this string when dispatching control requests.
const windowsServiceName = "UnclusterAgent"

// runAsWindowsService detects whether the binary is running under the
// Windows Service Control Manager. If so — and only if argv indicates
// `agent run` (the only path SCM is ever expected to take, because that's
// what the service unit binds to) — it routes through svc.Run so the
// SCM control-handler handshake completes and Windows reports the
// service as Running.
//
// Pre-#88 the binary returned from main with no svc.Run call: SCM never
// got the "started" status word, hit its 30s timeout, and `net start
// UnclusterAgent` returned exit 2 even though the agent process was
// alive and heartbeating to the CP. See #88 for the full trace.
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
	if runErr := svc.Run(windowsServiceName, &agentService{}); runErr != nil {
		return true, fmt.Errorf("svc.Run %s: %w", windowsServiceName, runErr)
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

	// runErr is written exactly once, when RunAgent returns, then closed.
	// Buffered so the goroutine cannot block if Execute has already
	// returned (shouldn't happen, but defensive against SCM oddities).
	runErr := make(chan error, 1)
	go func() {
		defer close(runErr)
		// RunAgent's stderr destination is os.Stderr here. Under SCM,
		// stdio is wired to NUL by default — operators should look at
		// the Application Event Log or the agent's heartbeat for state.
		runErr <- cli.RunAgent(ctx, os.Stderr)
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
				// agent's context to start its shutdown, wait for
				// the run loop to finish, then report Stopped.
				status <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-runErr
				if err != nil {
					// Service-specific exit code path. Per svc docs:
					// returning ssec=true tells SCM to surface the
					// errno as a service-specific error rather than
					// a Win32 error. Log first so the failure is
					// preserved in the Event Log.
					slog.Error("agent: run loop returned error under SCM", "error", err)
					status <- svc.Status{State: svc.Stopped}
					return true, 1
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				slog.Warn("agent: unexpected SCM control request", "cmd", c.Cmd)
			}
		case err := <-runErr:
			// RunAgent returned on its own (graceful deprovision,
			// fatal error, etc.) — tell SCM we're done.
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				slog.Error("agent: run loop returned error under SCM", "error", err)
				status <- svc.Status{State: svc.Stopped}
				return true, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
