package agent

import (
	"os"
	"path/filepath"
	"runtime"

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
	// UpdateHostAllowlist is the install-time-pinned list of hostnames
	// the Agent will accept for self-update binary + checksum downloads
	// (#39, ADR-0006).
	//
	// Semantics:
	//   - nil (field absent in agent.toml) → use DefaultUpdateHostAllowlist
	//     (= ["github.com"]). Preserves pre-#39 install behaviour.
	//   - []  (explicit empty)             → reject all update URLs;
	//                                         updates disabled.
	//   - non-empty                        → exact-match (case-insensitive)
	//                                         host check; `github.com`
	//                                         allows ONLY `github.com`
	//                                         (NOT `evil.github.com`).
	//
	// Callers should resolve via Config.AllowedUpdateHosts() rather than
	// reading this field directly, so the absent-vs-empty distinction is
	// applied uniformly.
	UpdateHostAllowlist []string `toml:"update_host_allowlist,omitempty"`
}

// DefaultConfigPath returns the per-user config path. Used by `agent join`
// (which is invoked interactively before any service exists). For
// service-side resolution use ResolveConfigPath which also considers the
// system-wide path.
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

// SystemConfigPath returns the canonical system-wide config path. Used by
// `agent install` to make the config readable by the low-privilege service
// account (which has its own HOME with a different per-user path). Per OS:
//   - linux:   /etc/uncluster/agent.toml
//   - darwin:  /etc/uncluster/agent.toml
//   - windows: C:\ProgramData\uncluster\agent.toml
//
// Fixes #77: the service runs under a different identity than the operator
// who ran `agent join`, so the per-user path is unreadable from the service.
// Install copies agent.toml here; ResolveConfigPath prefers it for service-
// side reads.
func SystemConfigPath() string {
	return systemConfigPathFn()
}

// systemConfigPathFn is the package-private indirection that tests swap out
// to redirect the system-config lookup to a temp dir. Production code uses
// SystemConfigPath() which calls through this var.
var systemConfigPathFn = defaultSystemConfigPath

func defaultSystemConfigPath() string {
	if runtime.GOOS == "windows" {
		// ProgramData is the canonical Windows system-app data location.
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "uncluster", "agent.toml")
	}
	return "/etc/uncluster/agent.toml"
}

// ResolveConfigPath returns the path that an `agent run`-style consumer
// should read. Preference order:
//  1. SystemConfigPath if it exists (the install step copies it there).
//  2. DefaultConfigPath as a fallback (lets ad-hoc / pre-install runs work).
//
// Returns the chosen path and nil error if either path resolves; or the
// per-user path with the error from DefaultConfigPath if both lookups fail.
func ResolveConfigPath() (string, error) {
	if sys := SystemConfigPath(); sys != "" {
		if _, err := os.Stat(sys); err == nil {
			return sys, nil
		}
	}
	return DefaultConfigPath()
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

// SaveConfigSystem writes the config to the system-wide path and arranges
// permissions so the low-privilege service account can read it. On Linux/
// macOS the directory is 0755 (traversable) and the file is 0640 owned
// root:<service-account>. On Windows we rely on SaveConfig + an additional
// icacls grant to NT SERVICE\UnclusterAgent in restrictSystemConfigACL.
//
// Returns an error if the OS-specific permission grant fails — partial
// writes are not desirable because the service would then see agent.toml
// but be unable to read it.
func SaveConfigSystem(path string, cfg Config) error {
	// Directory needs to be traversable by the service account (which
	// reads its config but does not need to list the dir).
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
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
	return restrictSystemConfigACL(path)
}
