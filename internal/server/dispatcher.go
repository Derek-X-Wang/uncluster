package server

import "sync"

// Dispatcher is filled out properly in Phase 6; stubbed here to make the
// server struct compile.
type inProcessDispatcher struct {
	mu      sync.Mutex
	wakeups map[string]chan struct{}
}

func newInProcessDispatcher() *inProcessDispatcher {
	return &inProcessDispatcher{wakeups: make(map[string]chan struct{})}
}
