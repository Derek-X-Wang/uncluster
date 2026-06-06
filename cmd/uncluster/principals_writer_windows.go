//go:build windows

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/cli"
)

// writerSCMErrorLogName is the diagnostic log the LocalSystem principals-writer
// writes its stderr to when running under SCM. It sits next to the agent's log
// in C:\ProgramData\uncluster so all Windows agent state is co-located, but is a
// separate file so the two services' diagnostics never interleave (#127, #128).
const writerSCMErrorLogName = "principals-writer.err.log"

// writerSCMErrorLogPath returns the writer's SCM stderr-log path, derived from
// the same ProgramData base as the agent's system config.
func writerSCMErrorLogPath() string {
	return filepath.Join(filepath.Dir(agent.SystemConfigPath()), writerSCMErrorLogName)
}

// principalsWriterService implements svc.Handler for the LocalSystem
// UnclusterPrincipalsWriter service. It mirrors agentService's SCM state-machine
// handshake (StartPending → Running → loop → StopPending → Stopped); the actual
// work runs via cli.RunPrincipalsWriter in a goroutine because svc.Run blocks
// the caller waiting for Execute to return.
type principalsWriterService struct{}

// Execute drives the SCM lifecycle for the writer. Same control-handler
// contract as agentService.Execute (see agent_run_windows.go), accepting Stop +
// Shutdown. The writer is network-less and stateless across restarts (it
// re-reads the spool on start), so a clean cancel-and-drain is sufficient.
func (s *principalsWriterService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (ssec bool, errno uint32) {
	const acceptedControls = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Under SCM os.Stderr is wired to NUL — redirect to a real file so a writer
	// startup death is diagnosable (#128). Fall back to os.Stderr if the log
	// can't be opened rather than refusing to start.
	var stderrW io.Writer = os.Stderr
	logPath := writerSCMErrorLogPath()
	if lf, err := openSCMErrorLog(logPath); err != nil {
		slog.Error("principals-writer: could not open SCM error log; falling back to NUL stderr",
			"path", logPath, "error", err)
	} else {
		stderrW = lf
		defer lf.Close()
	}

	runErr := make(chan error, 1)
	go func() {
		defer close(runErr)
		runErr <- cli.RunPrincipalsWriter(ctx, stderrW)
	}()

	status <- svc.Status{State: svc.Running, Accepts: acceptedControls}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				return reportStopped(status, <-runErr)
			default:
				slog.Warn("principals-writer: unexpected SCM control request", "cmd", c.Cmd)
			}
		case err := <-runErr:
			status <- svc.Status{State: svc.StopPending}
			return reportStopped(status, err)
		}
	}
}
