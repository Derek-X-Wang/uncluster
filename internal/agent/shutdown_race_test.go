package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestRun_ShutdownNoSendOnClosedApplyCh stresses the shutdown ordering
// between the heartbeat goroutine (which sends into applyCh) and Run()
// closing applyCh. Pre-fix Run() did `defer close(a.applyCh)` which fired
// the instant Run returned, racing the heartbeat goroutine's in-flight
// `a.applyCh <- ...` send.
//
// To trigger the race deterministically we use an HTTP server that holds
// every heartbeat response open until the test releases it. While the
// response is being read on the agent side, the test cancels the context.
// The heartbeat goroutine then proceeds to the applyCh send — exactly the
// window the bug exploits. Without the fix Run() races to close(applyCh).
//
// Iterating many times surfaces the panic when present. Post-fix the
// shutdown waits for the heartbeat goroutine via a WaitGroup before
// closing applyCh, so the send can never race the close.
func TestRun_ShutdownNoSendOnClosedApplyCh(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		// release controls when the heartbeat HTTP response is allowed to
		// finish being written. Buffered=1 so the handler doesn't block if
		// we never release for this iteration.
		release := make(chan struct{}, 1)
		var hbCount atomic.Int64
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
			hbCount.Add(1)
			// Block until the test signals — or 200ms timeout so a missed
			// release doesn't hang the iteration.
			select {
			case <-release:
			case <-time.After(200 * time.Millisecond):
			}
			resp := api.V2HeartbeatResponse{
				AckTS:      time.Now().Unix(),
				ServerTime: time.Now().Unix(),
				Policy: &api.PolicyPayload{
					Version: 1,
					Hash:    "blake3:racetest",
					Principals: []api.PolicyPrincipal{
						{Username: "test", CallerTokenIDs: []string{"AAAABBBBCCCCDDDD"}},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		srv := httptest.NewServer(mux)

		dir := t.TempDir()
		a := New(Config{
			Server: srv.URL,
			AgentToken: "uct_agent_0123456789ABCDEF_" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			AgentID: "ag_test",
			ExpectedPaths: ExpectedPaths{
				PrincipalsDir: dir,
				CAPubkey:      dir + "/ca.pub",
			},
		}, testLogger(t))

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = a.Run(ctx)
			close(done)
		}()

		// Wait for the heartbeat to actually arrive at our handler. Then
		// release the response first (so the heartbeat goroutine receives
		// the response body and reaches the applyCh send) and cancel
		// IMMEDIATELY after — racing the heartbeat goroutine's send
		// against Run's defer-close(applyCh).
		for hbCount.Load() == 0 {
			time.Sleep(50 * time.Microsecond)
		}
		release <- struct{}{}
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Run did not return within 5s after cancel", i)
		}
		srv.Close()
	}
}
