package agent_test

import (
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.toml")
	in := agent.Config{
		Server: "https://x", NodeID: "node_a", NodeName: "mac", AgentToken: "uct_agent_xxx_yyy",
	}
	if err := agent.SaveConfig(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := agent.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}
