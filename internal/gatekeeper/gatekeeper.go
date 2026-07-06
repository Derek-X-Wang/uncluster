// Package gatekeeper manages the privileged SSH-CA gatekeeper setup:
// writing sshd config, CA pubkey, principals directory, service account,
// and system service installation. Used by `uncluster agent install` and
// `uncluster agent doctor`.
package gatekeeper

import (
	"fmt"
	"os"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// CheckStatus is the result of a single doctor check.
type CheckStatus int

const (
	CheckOK      CheckStatus = iota // check passed
	CheckWarn                       // non-fatal issue
	CheckFail                       // fatal failure
)

// CheckResult holds the outcome of one doctor check.
type CheckResult struct {
	Name    string
	Status  CheckStatus
	Message string
	// Informational marks a check whose Message is the payload even when
	// Status is CheckOK (e.g. "which config path loaded", "which update
	// hosts are allowed"). Consumers that suppress OK-status messages
	// should still surface the Message for these. Avoids enumerating
	// such checks by Name at every consumer.
	Informational bool
}

// DoctorResults is the collection of all check results.
type DoctorResults []CheckResult

// CheckConfigLoadedPath emits a structured check identifying which file
// the agent loaded its config from. Surfaced as the first row of doctor
// output and as a health check on the heartbeat (#77 acceptance).
//
// The check is informational — always reports CheckOK — so the operator
// can confirm post-install that the service is reading the system path
// (vs. silently falling back to a stale per-user file). Empty path is the
// only condition that produces a warn, and that only happens if the
// caller fails to resolve a path at all.
func CheckConfigLoadedPath(path string) CheckResult {
	if path == "" {
		return CheckResult{
			Name:          "config-loaded-path",
			Status:        CheckWarn,
			Message:       "no config path resolved",
			Informational: true,
		}
	}
	return CheckResult{
		Name:          "config-loaded-path",
		Status:        CheckOK,
		Message:       path,
		Informational: true,
	}
}

// CheckUpdateHostAllowlist surfaces the configured allowlist for binary
// self-update downloads (#39, ADR-0006). Always informational:
//
//   - non-empty allowlist → CheckOK, message lists the hosts
//   - empty allowlist     → CheckOK, message "updates disabled (empty
//     allowlist)" — this is a valid operator posture (rejecting all
//     updates), not a misconfiguration.
//
// Operators can read this to confirm that an install correctly pinned
// the expected hosts. The Agent enforces the allowlist directly in the
// update flow — this check is purely observability.
func CheckUpdateHostAllowlist(allowlist []string) CheckResult {
	if len(allowlist) == 0 {
		return CheckResult{
			Name:          "update-host-allowlist",
			Status:        CheckOK,
			Message:       "updates disabled (empty allowlist)",
			Informational: true,
		}
	}
	return CheckResult{
		Name:          "update-host-allowlist",
		Status:        CheckOK,
		Message:       strings.Join(allowlist, ", "),
		Informational: true,
	}
}

// ExitCode returns 0 for all-ok, 1 for any warn, 2 for any fail.
func (r DoctorResults) ExitCode() int {
	code := 0
	for _, c := range r {
		switch c.Status {
		case CheckFail:
			return 2
		case CheckWarn:
			code = 1
		}
	}
	return code
}

// sshdDropInContent is the FILE-based managed directive block used ONLY on
// Windows (via managedDirectiveBlock): the SYSTEM PrincipalsWriter renders
// root/SYSTEM-owned per-user files, which sshd StrictModes accepts, so Windows
// stays on AuthorizedPrincipalsFile (working post-#179). Unix/macOS instead use
// AuthorizedPrincipalsCommand (see sshdDropInContentUnix) because the low-priv
// agent writes agent-owned files that sshd's StrictModes rejects (#185).
func sshdDropInContent(caPubkeyPath, principalsDirPattern string) string {
	return fmt.Sprintf("TrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s\n",
		caPubkeyPath, principalsDirPattern)
}

// sshdDropInContentUnix is the sshd_config.d snippet written by install on
// Unix/macOS (#185). It uses AuthorizedPrincipalsCommand instead of
// AuthorizedPrincipalsFile so sshd invokes `<uncluster> agent principals %u` to
// obtain a Caller's principals rather than reading a file: the agent runs as the
// low-priv service account (ADR-0004) and its atomic tmp→rename leaves per-user
// files owned by that account in a group-writable dir, which OpenSSH StrictModes
// rejects ("bad ownership or modes"). The command's OUTPUT is not StrictModes-
// checked, so the agent keeps writing its low-priv files unchanged and the
// command (a dumb read) echoes them.
//
// sshd DOES require the command BINARY to be an absolute path owned by root and
// not group/world-writable — the installed `/usr/local/bin/uncluster` (root,
// 0755) qualifies; doctor asserts it (checkPrincipalsCommandBinary). commandBin
// is assumed whitespace-free (the install path is); sshd would need it quoted
// otherwise.
func sshdDropInContentUnix(caPubkeyPath, commandBin, commandUser string) string {
	return fmt.Sprintf(
		"TrustedUserCAKeys %s\nAuthorizedPrincipalsCommand %s agent principals %%u\nAuthorizedPrincipalsCommandUser %s\n",
		caPubkeyPath, commandBin, commandUser)
}

// writeCAPubkey writes the CA pubkey to the path from agent config with mode 0644.
func writeCAPubkey(paths agent.ExpectedPaths, caPubkey string) error {
	if err := os.MkdirAll(dirOf(paths.CAPubkey), 0o755); err != nil {
		return fmt.Errorf("mkdir ca pubkey dir: %w", err)
	}
	return os.WriteFile(paths.CAPubkey, []byte(strings.TrimSpace(caPubkey)+"\n"), 0o644)
}

// writeSSHDropIn writes the Unix/macOS sshd_config.d snippet (#185): the
// AuthorizedPrincipalsCommand form. commandBin is the absolute path to the
// installed uncluster binary (root-owned, sshd runs it) and commandUser is the
// service account sshd drops to when running it. Overwriting the file wholesale
// self-heals from the pre-#185 AuthorizedPrincipalsFile shape on re-install.
// (Windows writes its directives via the base-config managed block instead — see
// install_windows.go / managedDirectiveBlock — and stays file-based.)
func writeSSHDropIn(paths agent.ExpectedPaths, commandBin, commandUser string) error {
	if err := os.MkdirAll(dirOf(paths.SSHDropIn), 0o755); err != nil {
		return fmt.Errorf("mkdir sshd drop-in dir: %w", err)
	}
	content := sshdDropInContentUnix(paths.CAPubkey, commandBin, commandUser)
	return os.WriteFile(paths.SSHDropIn, []byte(content), 0o644)
}

// ensurePrincipalsDir creates the principals directory (mode 0755).
func ensurePrincipalsDir(paths agent.ExpectedPaths) error {
	return os.MkdirAll(paths.PrincipalsDir, 0o755)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
