package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleCreateTask creates a new task for a given node (identified by id or name).
// CLI auth is required; the authenticated token's ID is recorded as created_by.
func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	tok := r.Context().Value(ctxAuthedToken).(store.Token)

	var req api.CreateTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Node == "" {
		writeError(w, http.StatusBadRequest, "node is required")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	// Resolve node by id first, fall back to name.
	node, err := s.cfg.Store.GetNode(r.Context(), req.Node)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), req.Node)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if node.Status == store.NodeRevoked {
		writeError(w, http.StatusBadRequest, "node is revoked")
		return
	}

	task, err := s.cfg.Store.CreateTask(r.Context(), node.ID, req.Command, tok.ID, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Wake up the agent's long-poll loop immediately.
	s.dispatcher.Notify(node.ID)

	writeJSON(w, http.StatusCreated, api.CreateTaskResponse{TaskID: task.ID})
}

// handleGetTask returns the detail of a single task by id.
func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	task, err := s.cfg.Store.GetTask(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, toDetail(task))
}

// handleListTasks returns tasks, optionally filtered by node_id, status, and limit query params.
func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	nodeID := q.Get("node_id")
	status := store.TaskStatus(q.Get("status"))
	limit := 0
	if l := q.Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			limit = v
		}
	}

	tasks, err := s.cfg.Store.ListTasks(r.Context(), nodeID, status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.TaskDetail, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, toDetail(t))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAgentNextTask is a long-poll endpoint for agents.
// It blocks up to 30 s waiting for a pending task to claim.
// Returns 200+task when a task is claimed, 204 when the poll times out with nothing.
func (s *Server) handleAgentNextTask(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	for {
		task, err := s.cfg.Store.ClaimNextPending(ctx, node.ID, time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if task != nil {
			writeJSON(w, http.StatusOK, api.NextTaskResponse{
				TaskID:  task.ID,
				Command: task.Command,
			})
			return
		}

		// No task available — wait for a wakeup or timeout.
		waitErr := s.dispatcher.Wait(ctx, node.ID, time.Until(deadline(ctx)))
		if waitErr != nil {
			// ctx cancelled or timed out — check which.
			select {
			case <-ctx.Done():
				w.WriteHeader(http.StatusNoContent)
				return
			default:
				// Spurious or other error; loop to re-try ClaimNextPending.
			}
		}
		// After any wakeup (spurious or real) re-attempt ClaimNextPending.
	}
}

// toDetail converts a store.Task to an api.TaskDetail wire type.
func toDetail(t store.Task) api.TaskDetail {
	return api.TaskDetail{
		ID:              t.ID,
		NodeID:          t.NodeID,
		Command:         t.Command,
		Status:          string(t.Status),
		ExitCode:        t.ExitCode,
		CreatedAt:       t.CreatedAt.Unix(),
		StartedAt:       api.TimePtr(t.StartedAt),
		FinishedAt:      api.TimePtr(t.FinishedAt),
		OutputBytes:     t.OutputBytes,
		OutputTruncated: t.OutputTruncated,
	}
}

// deadline returns the context deadline, or now+30s if the context has no deadline.
func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(30 * time.Second)
}
