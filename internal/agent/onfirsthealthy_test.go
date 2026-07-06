package agent

import (
	"context"
	"testing"
)

// The onFirstHealthy hook fires exactly once — on the first successful
// heartbeat — even across multiple heartbeats (health-commit semantics for the
// #187 launcher).
func TestOnFirstHealthy_FiresOnceOnFirstSuccess(t *testing.T) {
	a, _ := heartbeatCaptureAgent(t, nil)
	var fired int
	a.WithOnFirstHealthy(func() { fired++ })

	for i := 0; i < 3; i++ {
		if err := a.heartbeatOnceV2(context.Background()); err != nil {
			t.Fatalf("heartbeatOnceV2 #%d: %v", i, err)
		}
	}
	if fired != 1 {
		t.Errorf("onFirstHealthy fired %d times, want exactly 1", fired)
	}
}
