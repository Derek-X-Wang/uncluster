//go:build !windows

package agent

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// executeTask runs a shell command and streams stdout/stderr back via chunk
// POSTs. Cancellation is driven by the Agent.cancels dispatcher (taskCtx).
func (a *Agent) executeTask(parent context.Context, taskID, command string) int {
	taskCtx, cancel := context.WithCancel(parent)
	a.cancels.Register(taskID, cancel)
	defer a.cancels.Unregister(taskID)

	cmd := exec.Command("bash", "-lc", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		a.logger.Warn("start failed", "task", taskID, "err", err)
		return -1
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.streamPipe(taskCtx, taskID, "stdout", stdout) }()
	go func() { defer wg.Done(); a.streamPipe(taskCtx, taskID, "stderr", stderr) }()

	// Kill handler: when taskCtx is cancelled, send SIGTERM to the group;
	// after 5s, SIGKILL.
	killDone := make(chan struct{})
	go func() {
		<-taskCtx.Done()
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		}
		select {
		case <-time.After(5 * time.Second):
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			}
		case <-killDone:
		}
	}()

	err := cmd.Wait()
	close(killDone)
	wg.Wait()

	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	if taskCtx.Err() != nil {
		return 143 // conventional "killed by SIGTERM" code when nothing better
	}
	return -1
}

// streamPipe reads a pipe line-by-line with periodic flushes, POSTing chunks
// to the server. Flush triggers: 4 KiB buffer, 200 ms idle, or EOF.
func (a *Agent) streamPipe(ctx context.Context, taskID, stream string, r io.Reader) {
	buf := make([]byte, 0, 4096)
	flushTicker := time.NewTicker(200 * time.Millisecond)
	defer flushTicker.Stop()

	br := bufio.NewReader(r)
	readCh := make(chan []byte, 8)
	readDone := make(chan struct{})

	go func() {
		defer close(readDone)
		tmp := make([]byte, 1024)
		for {
			n, err := br.Read(tmp)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, tmp[:n])
				select {
				case readCh <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		resp, err := a.client.UploadChunk(ctx, taskID, stream, buf)
		buf = buf[:0]
		if err != nil {
			a.logger.Warn("chunk upload failed", "err", err)
			return
		}
		if resp.Truncated {
			// Server says stop flushing — drain reader but drop.
			buf = nil
		}
		if len(resp.CancelTaskIDs) > 0 {
			a.cancels.Signal(resp.CancelTaskIDs)
		}
	}

	for {
		select {
		case b := <-readCh:
			if buf != nil {
				buf = append(buf, b...)
				if len(buf) >= 4096 {
					flush()
				}
			}
		case <-flushTicker.C:
			flush()
		case <-readDone:
			flush()
			return
		case <-ctx.Done():
			flush()
			return
		}
	}
}
