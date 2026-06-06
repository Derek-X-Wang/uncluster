//go:build windows

package cli

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// RunPrincipalsWriter runs the LocalSystem UnclusterPrincipalsWriter loop until
// ctx is cancelled. It is the single source of truth for the writer's
// foreground behaviour, shared by:
//   - the `uncluster principals-writer run` cobra command (foreground / debug);
//   - the Windows SCM handler (cmd/uncluster/principals_writer_windows.go),
//     which wraps it under svc.Run so the binary completes the SCM
//     control-handler handshake (same pattern as the agent — see #88).
//
// Diagnostic output goes to stderrW (the SCM handler redirects it to a real
// file because os.Stderr is wired to NUL under SCM, #128).
func RunPrincipalsWriter(ctx context.Context, stderrW io.Writer) error {
	if stderrW == nil {
		stderrW = os.Stderr
	}
	logger := slog.New(slog.NewTextHandler(stderrW, nil))
	w := agent.NewPrincipalsWriter(logger)
	return w.Run(ctx)
}
