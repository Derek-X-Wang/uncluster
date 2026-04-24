package server

import (
	"context"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

func (s *Server) runReaper(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cutoff := now.Add(-60 * time.Second)
			stale, err := s.cfg.Store.FindStaleRunning(ctx, cutoff)
			if err != nil {
				s.cfg.Logger.Warn("reaper: FindStaleRunning failed", "err", err)
				continue
			}
			for _, task := range stale {
				marker := []byte("\n[uncluster: agent lost, task reaped at " + now.UTC().Format(time.RFC3339) + "]\n")
				_, _ = s.cfg.Store.AppendChunk(ctx, task.ID, "stderr", marker, now, s.cfg.OutputCapBytes)
				if err := s.cfg.Store.MarkTaskFailedLost(ctx, task.ID, now); err != nil {
					s.cfg.Logger.Warn("reaper: mark failed", "task", task.ID, "err", err)
					continue
				}
				s.dispatcher.PublishChunk(task.ID, DispatcherEvent{
					Kind: "done", Payload: map[string]any{"exit_code": -1, "status": string(store.TaskFailed)},
				})
			}
		}
	}
}
