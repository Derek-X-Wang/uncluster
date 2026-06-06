//go:build windows

package agent

import (
	"os"
	"path/filepath"
)

// PrincipalsDir is the fixed, hardcoded location of the per-user
// AuthorizedPrincipalsFile directory on Windows. The UnclusterPrincipalsWriter
// NEVER reads this path from the (untrusted) spool desired-state — it is
// compiled in, so a compromised agent cannot redirect the writer to render
// files anywhere else (#127). This MUST match the gatekeeper installer's
// windowsPaths.PrincipalsDir.
const WindowsPrincipalsDir = `C:\ProgramData\ssh\auth_principals`

// SpoolDir returns the agent↔writer spool directory, e.g.
// C:\ProgramData\uncluster\spool. It is derived from the same ProgramData base
// as the system config (honoring the PROGRAMDATA env override that
// SystemConfigPath uses) so all Windows agent state sits under one tree and
// tests can redirect it.
func SpoolDir() string {
	return filepath.Join(filepath.Dir(SystemConfigPath()), "spool")
}

// spoolPolicyPath / spoolAppliedPath are the two spool files. The agent writes
// policy.json (desired-state) and reads applied.json (writer status); the
// writer does the reverse.
func spoolPolicyPath() string  { return filepath.Join(SpoolDir(), spoolPolicyFile) }
func spoolAppliedPath() string { return filepath.Join(SpoolDir(), spoolAppliedFile) }

// ensureSpoolDir creates the spool dir if absent. Install also creates it (with
// the right ACL); this is a defensive no-op-if-present so an apply on a freshly
// started service does not fail on a missing dir.
func ensureSpoolDir() error {
	return os.MkdirAll(SpoolDir(), 0o755)
}
