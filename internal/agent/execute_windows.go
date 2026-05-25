//go:build windows

package agent

import (
	"context"
	"io"
)

// executeTask is a stub on Windows. V1 task execution (bash + process groups)
// is Unix-only; this code is removed entirely in S11 (issue #15).
func (a *Agent) executeTask(_ context.Context, taskID, _ string) int {
	a.logger.Warn("task execution not supported on Windows", "task", taskID)
	return -1
}

// streamPipe is a no-op stub on Windows; only called by executeTask.
func (a *Agent) streamPipe(_ context.Context, _, _ string, _ io.Reader) {}
