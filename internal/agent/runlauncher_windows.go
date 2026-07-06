//go:build windows

package agent

import (
	"context"
	"errors"
	"log/slog"
)

// RunLauncher is not supported on Windows. The Windows Agent runs directly via
// `agent run` under the Service Control Manager and keeps its in-place
// self-update posture; relocating the Windows binary to a service-owned path
// (the analog of the Unix payload store) is tracked separately in #139.
func RunLauncher(_ context.Context, _ *slog.Logger) error {
	return errors.New("agent launch is supported only on Linux/macOS; the Windows agent runs via `agent run` under the SCM (binary relocation tracked in #139)")
}
