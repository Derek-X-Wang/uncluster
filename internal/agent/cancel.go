package agent

import (
	"context"
	"sync"
)

// cancelDispatcher tracks active tasks so cancel signals from the server
// (delivered on heartbeat/chunk responses) can abort the right task's context.
type cancelDispatcher struct {
	mu     sync.Mutex
	active map[string]context.CancelFunc
}

func newCancelDispatcher() *cancelDispatcher {
	return &cancelDispatcher{active: make(map[string]context.CancelFunc)}
}

func (c *cancelDispatcher) Register(taskID string, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active[taskID] = cancel
}

func (c *cancelDispatcher) Unregister(taskID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.active, taskID)
}

func (c *cancelDispatcher) Signal(taskIDs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range taskIDs {
		if fn, ok := c.active[id]; ok {
			fn()
		}
	}
}
