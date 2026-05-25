package agent

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// ExpectedPaths mirrors api.ExpectedPaths as a persisted struct so the agent
// config can store the paths returned by the Control plane at enrollment.
type ExpectedPaths struct {
	CAPubkey      string `toml:"ca_pubkey"`
	SSHDropIn     string `toml:"sshd_drop_in"`
	PrincipalsDir string `toml:"principals_dir"`
}

// Config is the agent's persisted configuration. Written by `uncluster agent
// join` and read by `uncluster agent run`. Mode 0600 on disk.
type Config struct {
	Server         string        `toml:"server"`
	AgentID        string        `toml:"agent_id"`
	AgentName      string        `toml:"agent_name"`
	AgentToken     string        `toml:"agent_token"`
	CAPubkey       string        `toml:"ca_pubkey"`
	ServerHTTPSPin string        `toml:"server_https_pin,omitempty"`
	ExpectedPaths  ExpectedPaths `toml:"expected_paths"`
	// PinnedVersion overrides the server's expected_version. Set by
	// `uncluster agent update --pin`. Empty = follow server's expected.
	PinnedVersion  string `toml:"pinned_version,omitempty"`
}

func DefaultConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "uncluster", "agent.toml"), nil
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	_, err = toml.Decode(string(b), &cfg)
	return cfg, err
}

func SaveConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := toml.NewEncoder(f).Encode(cfg); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// On Windows, apply a DACL restricting access to SYSTEM + Administrators
	// (equivalent of mode 0600 which is a no-op on Windows NTFS).
	return restrictConfigACL(path)
}
