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
			Name:    "config-loaded-path",
			Status:  CheckWarn,
			Message: "no config path resolved",
		}
	}
	return CheckResult{
		Name:    "config-loaded-path",
		Status:  CheckOK,
		Message: path,
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

// sshdDropInContent is the sshd_config.d snippet written by install.
func sshdDropInContent(caPubkeyPath, principalsDirPattern string) string {
	return fmt.Sprintf("TrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s\n",
		caPubkeyPath, principalsDirPattern)
}

// writeCAPubkey writes the CA pubkey to the path from agent config with mode 0644.
func writeCAPubkey(paths agent.ExpectedPaths, caPubkey string) error {
	if err := os.MkdirAll(dirOf(paths.CAPubkey), 0o755); err != nil {
		return fmt.Errorf("mkdir ca pubkey dir: %w", err)
	}
	return os.WriteFile(paths.CAPubkey, []byte(strings.TrimSpace(caPubkey)+"\n"), 0o644)
}

// writeSSHDropIn writes the sshd_config.d snippet.
func writeSSHDropIn(paths agent.ExpectedPaths) error {
	if err := os.MkdirAll(dirOf(paths.SSHDropIn), 0o755); err != nil {
		return fmt.Errorf("mkdir sshd drop-in dir: %w", err)
	}
	content := sshdDropInContent(paths.CAPubkey, paths.PrincipalsDir+"/%u")
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
