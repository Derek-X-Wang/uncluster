package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DispatcherEvent is a typed event published to per-task subscribers (e.g. SSE fans).
type DispatcherEvent struct {
	Kind    string
	Payload any
}

// Dispatcher is the interface that decouples the Server from a specific
// dispatcher implementation (spec §9 future-extensibility seam).
// inProcessDispatcher is the default in-process implementation.
type Dispatcher interface {
	// Notify wakes up any Wait blocked on nodeID (coalesced, non-blocking).
	Notify(nodeID string)
	// Wait blocks until Notify fires for nodeID, timeout elapses, or ctx is cancelled.
	Wait(ctx context.Context, nodeID string, timeout time.Duration) error
	// Subscribe registers a listener for fan-out events on taskID.
	// The caller must invoke the returned unsubscribe func exactly once.
	Subscribe(taskID string) (<-chan DispatcherEvent, func())
	// PublishChunk fans ev out to all current subscribers of taskID.
	PublishChunk(taskID string, ev DispatcherEvent)
}

// inProcessDispatcher routes two kinds of signals:
//
//  1. Wakeup signals (Notify / Wait) — used by long-polling node-task pickup.
//     Wakeups are coalesced: multiple Notify calls before a Wait fires produce
//     exactly one wakeup, not N.
//
//  2. Fan-out events (PublishChunk / Subscribe) — used to push output chunks
//     to SSE streams.  Slow subscribers get events dropped rather than stalling
//     the publisher.
type inProcessDispatcher struct {
	mu          sync.Mutex
	wakeups     map[string]chan struct{}              // node_id → buffered-1 wake channel
	subscribers map[string][]chan DispatcherEvent    // task_id → listener channels
}

func newInProcessDispatcher() *inProcessDispatcher {
	return &inProcessDispatcher{
		wakeups:     make(map[string]chan struct{}),
		subscribers: make(map[string][]chan DispatcherEvent),
	}
}

// wakeChan returns the buffered-1 wake channel for nodeID, creating it if needed.
// Caller must hold d.mu.
func (d *inProcessDispatcher) wakeChan(nodeID string) chan struct{} {
	ch, ok := d.wakeups[nodeID]
	if !ok {
		ch = make(chan struct{}, 1)
		d.wakeups[nodeID] = ch
	}
	return ch
}

// Notify signals any Wait blocked on nodeID.  Non-blocking: if a signal is
// already pending the call is a no-op (coalescing).
func (d *inProcessDispatcher) Notify(nodeID string) {
	d.mu.Lock()
	ch := d.wakeChan(nodeID)
	d.mu.Unlock()

	select {
	case ch <- struct{}{}:
	default:
	}
}

// Wait blocks until Notify is called for nodeID, timeout elapses, or ctx is
// cancelled.  Returns nil on wakeup, a context error on cancellation, and a
// deadline-exceeded error on timeout.
func (d *inProcessDispatcher) Wait(ctx context.Context, nodeID string, timeout time.Duration) error {
	d.mu.Lock()
	ch := d.wakeChan(nodeID)
	d.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return nil
	case <-timer.C:
		return fmt.Errorf("wait %s: %w", nodeID, context.DeadlineExceeded)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Subscribe registers a new listener for events on taskID.
// It returns a receive-only channel and an unsubscribe function.
// The caller must invoke the unsubscribe function exactly once when done to
// avoid leaking the channel.
func (d *inProcessDispatcher) Subscribe(taskID string) (<-chan DispatcherEvent, func()) {
	ch := make(chan DispatcherEvent, 16)

	d.mu.Lock()
	d.subscribers[taskID] = append(d.subscribers[taskID], ch)
	d.mu.Unlock()

	unsub := func() {
		d.mu.Lock()
		defer d.mu.Unlock()

		subs := d.subscribers[taskID]
		for i, s := range subs {
			if s == ch {
				// Remove by swapping with last element.
				subs[i] = subs[len(subs)-1]
				subs[len(subs)-1] = nil
				d.subscribers[taskID] = subs[:len(subs)-1]
				break
			}
		}
		if len(d.subscribers[taskID]) == 0 {
			delete(d.subscribers, taskID)
		}
		close(ch)
	}

	return ch, unsub
}

// PublishChunk fans ev out to all current subscribers of taskID.
// Each send is non-blocking: subscribers that are not ready get the event dropped.
func (d *inProcessDispatcher) PublishChunk(taskID string, ev DispatcherEvent) {
	d.mu.Lock()
	subs := make([]chan DispatcherEvent, len(d.subscribers[taskID]))
	copy(subs, d.subscribers[taskID])
	d.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
