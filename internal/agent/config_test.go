package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.toml")
	in := agent.Config{
		Server:     "https://x",
		AgentID:    "ag_abc123",
		AgentName:  "mac",
		AgentToken: "uct_agent_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		CAPubkey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest uncluster-ca",
		ExpectedPaths: agent.ExpectedPaths{
			CAPubkey:      "/etc/ssh/uncluster_ca.pub",
			SSHDropIn:     "/etc/ssh/sshd_config.d/uncluster.conf",
			PrincipalsDir: "/etc/ssh/auth_principals",
		},
	}
	if err := agent.SaveConfig(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := agent.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", out, in)
	}
}

// TestConfigAlreadyEnrolledCheck verifies that a config with an AgentToken is
// detected as "already enrolled" — tested via LoadConfig + AgentToken check,
// matching what the join command does.
func TestConfigAlreadyEnrolledCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.toml")
	in := agent.Config{
		Server:     "https://x",
		AgentID:    "ag_existing",
		AgentName:  "my-box",
		AgentToken: "uct_agent_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}
	if err := agent.SaveConfig(p, in); err != nil {
		t.Fatal(err)
	}
	loaded, err := agent.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentToken == "" {
		t.Fatal("expected AgentToken to be set for already-enrolled check")
	}
}

// TestSaveConfigMode0600 verifies that SaveConfig writes the file with mode 0600.
// Acceptance criteria: `uncluster agent join` persists config with mode 0600.
// Skipped on Windows: POSIX mode bits are not enforced by the Windows filesystem.
// TODO(S9a): restore via Windows ACL check (icacls/SetNamedSecurityInfo).
func TestSaveConfigMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits not enforced on Windows; see follow-up for ACL-based check")
	}
	p := filepath.Join(t.TempDir(), "agent.toml")
	if err := agent.SaveConfig(p, agent.Config{Server: "https://x", AgentToken: "tok"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file mode: got %#o want 0600", perm)
	}
}
