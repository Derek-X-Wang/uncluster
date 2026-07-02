package gatekeeper

import (
	"context"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// TestFullDoctor_ComposesPrependsThenPlatformChecks pins the single doctor
// composition (#143): the two informational prepends (config-loaded-path,
// update-host-allowlist) come first and in that order, followed by exactly the
// platform Doctor check set, in order. This is the composition every one of the
// six call sites now shares, so the set + ordering can no longer drift between
// them.
func TestFullDoctor_ComposesPrependsThenPlatformChecks(t *testing.T) {
	ctx := context.Background()
	cfg := agent.Config{}

	platform := Doctor(ctx, cfg)
	full := FullDoctor(ctx, cfg, "/etc/uncluster/agent.toml")

	if len(full) < 2 {
		t.Fatalf("FullDoctor returned %d checks, want >= 2 prepends", len(full))
	}
	if full[0].Name != "config-loaded-path" {
		t.Errorf("full[0].Name = %q, want config-loaded-path", full[0].Name)
	}
	if full[1].Name != "update-host-allowlist" {
		t.Errorf("full[1].Name = %q, want update-host-allowlist", full[1].Name)
	}

	// The tail must be exactly the platform Doctor set, in order — proving
	// FullDoctor adds only the prepends and delegates the rest to Doctor.
	if len(full) != len(platform)+2 {
		t.Fatalf("FullDoctor len = %d, want len(Doctor)+2 = %d", len(full), len(platform)+2)
	}
	for i, pc := range platform {
		if full[i+2].Name != pc.Name {
			t.Errorf("full[%d].Name = %q, want platform check %q (ordering drift)", i+2, full[i+2].Name, pc.Name)
		}
	}
}

// TestFullDoctor_EmptyConfigPathWarns pins the one load-bearing prepend: the
// empty-config-path warning. Sites 5 & 6 (reboot precondition, post-reboot
// liveness) called bare Doctor and silently dropped it; FullDoctor must always
// include it so that drift class disappears by construction (#143).
func TestFullDoctor_EmptyConfigPathWarns(t *testing.T) {
	full := FullDoctor(context.Background(), agent.Config{}, "")
	if len(full) < 1 {
		t.Fatal("FullDoctor returned no checks")
	}
	if full[0].Name != "config-loaded-path" || full[0].Status != CheckWarn {
		t.Errorf("empty configPath: full[0] = %+v, want config-loaded-path with CheckWarn", full[0])
	}
}
