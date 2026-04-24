package server

import (
	"context"
	"testing"
	"time"
)

func TestDispatcher_WaitReturnsOnNotify(t *testing.T) {
	d := newInProcessDispatcher()

	nodeID := "node-abc"

	// Kick Notify in a goroutine shortly after Wait starts.
	go func() {
		time.Sleep(20 * time.Millisecond)
		d.Notify(nodeID)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Wait should return before the context deadline because Notify fires first.
	err := d.Wait(ctx, nodeID, time.Second)
	if err != nil {
		t.Fatalf("Wait returned error %v; expected nil (notify path)", err)
	}
}

func TestDispatcher_WaitTimeout(t *testing.T) {
	d := newInProcessDispatcher()

	ctx := context.Background()
	start := time.Now()
	timeout := 80 * time.Millisecond

	err := d.Wait(ctx, "node-nobody-notifies", timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Wait returned nil; expected timeout error")
	}
	// Should not have taken dramatically longer than the timeout.
	if elapsed > timeout+300*time.Millisecond {
		t.Fatalf("Wait took %v; expected ~%v", elapsed, timeout)
	}
}

func TestDispatcher_PublishSubscribe(t *testing.T) {
	d := newInProcessDispatcher()

	taskID := "task-xyz"
	ch, unsub := d.Subscribe(taskID)

	ev := DispatcherEvent{Kind: "chunk", Payload: "hello"}
	d.PublishChunk(taskID, ev)

	select {
	case received := <-ch:
		if received.Kind != ev.Kind {
			t.Fatalf("got Kind=%q; want %q", received.Kind, ev.Kind)
		}
		if received.Payload != ev.Payload {
			t.Fatalf("got Payload=%v; want %v", received.Payload, ev.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published event")
	}

	// Unsubscribe must close the channel and remove it from the map.
	unsub()

	// Channel should be closed after unsubscribe.
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("channel still open after unsub")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after unsub")
	}

	// Publishing after unsubscribe must not panic or block.
	d.PublishChunk(taskID, DispatcherEvent{Kind: "after-unsub"})
}
