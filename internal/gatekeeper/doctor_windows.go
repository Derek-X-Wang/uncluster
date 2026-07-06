//go:build windows

package gatekeeper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// Doctor checks the gatekeeper configuration state on Windows.
// It is non-destructive: read-only checks, no mutations.
func Doctor(_ context.Context, cfg agent.Config) DoctorResults {
	paths := cfg.ExpectedPaths
	var results DoctorResults

	// 1. sshd installed.
	out, err := exec.Command("sc.exe", "query", "sshd").CombinedOutput()
	if err != nil {
		results = append(results, CheckResult{
			Name: "sshd-installed", Status: CheckFail,
			Message: "OpenSSH Server (sshd) not found. Install: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
		})
	} else {
		results = append(results, CheckResult{Name: "sshd-installed", Status: CheckOK})
		// 2. sshd running.
		if containsState(string(out), "RUNNING") {
			results = append(results, CheckResult{Name: "sshd-running", Status: CheckOK})
		} else {
			results = append(results, CheckResult{
				Name: "sshd-running", Status: CheckFail,
				Message: "sshd service not RUNNING. Start: Start-Service sshd",
			})
		}
	}

	// 3. CA pubkey present.
	caPath := paths.CAPubkey
	if caPath == "" {
		caPath = windowsPaths.CAPubkey
	}
	if _, err := os.Stat(caPath); err == nil {
		results = append(results, CheckResult{Name: "ca-pubkey", Status: CheckOK})
	} else {
		results = append(results, CheckResult{
			Name: "ca-pubkey", Status: CheckFail,
			Message: caPath + " not found. Run: uncluster agent install",
		})
	}

	// 4. sshd drop-in present, carries the required directives, AND is Included
	// GLOBALLY (before any Match block) by the base sshd_config. A drop-in that
	// merely EXISTS but whose Include is appended after `Match Group
	// administrators` applies to admins only — non-admin cert login then fails
	// silently (#177). The old presence-only check stayed green through that
	// whole outage: the same doctor-blindness class as #175's spool write-bit
	// check. Assert the effective global scope by reading the base config
	// (non-mutating, ADR-0009 inspect).
	dropIn := paths.SSHDropIn
	if dropIn == "" {
		dropIn = windowsPaths.SSHDropIn
	}
	results = append(results, checkSSHDropInWindows(dropIn, windowsBaseSSHDConfig))

	// 5. Principals dir is locked down for the #127 role-split: it exists, is a
	// directory, and the low-priv `NT SERVICE\UnclusterAgent` account holds NO
	// write grant (INVERTED from pre-#127 — an agent write grant inherits onto
	// the per-user files and makes Win32-OpenSSH silently ignore them). Verified
	// by READING the DACL (non-mutating, ADR-0009 inspect contract).
	pDir := paths.PrincipalsDir
	if pDir == "" {
		pDir = windowsPaths.PrincipalsDir
	}
	results = append(results, checkPrincipalsACLWindows(pDir))

	// 5a. Per-user principals files carry a safe owner/DACL (owned by
	// SYSTEM/Administrators, no write-class ACE for any other principal). A file
	// failing this is silently ignored by sshd, denying login even with the
	// right principal present (#127). Non-mutating: reads owner + DACL.
	results = append(results, checkPerUserPrincipalsFilesWindows(pDir))

	// 5b. The agent↔writer spool dir exists and the agent can submit
	// desired-state to it (#127).
	results = append(results, checkSpoolACLWindows(agent.SpoolDir()))

	// 6. UnclusterAgent service installed.
	svcOut, svcErr := exec.Command("sc.exe", "query", agent.WindowsServiceName).CombinedOutput()
	if svcErr != nil {
		results = append(results, CheckResult{
			Name: "service-installed", Status: CheckFail,
			Message: "UnclusterAgent service not installed. Run: uncluster agent install",
		})
	} else {
		results = append(results, CheckResult{Name: "service-installed", Status: CheckOK})
		// 7. Service running.
		if containsState(string(svcOut), "RUNNING") {
			results = append(results, CheckResult{Name: "service-running", Status: CheckOK})
		} else {
			results = append(results, CheckResult{
				Name: "service-running", Status: CheckFail,
				Message: "UnclusterAgent service not RUNNING. Start: net start UnclusterAgent",
			})
		}
	}

	// 7a. UnclusterPrincipalsWriter (LocalSystem) service installed and running
	// — the only identity that writes principals files in the #127 role-split.
	// Its absence breaks policy apply. Non-mutating: read-only `sc query`.
	results = append(results, checkWriterServiceWindows())

	// 8. System config ownership (#104). The Unix doctor checks the system
	// agent.toml is owned root:<service account> 0640 (readable by the service
	// account, not world). The Windows equivalent is the DACL granting
	// `NT SERVICE\UnclusterAgent` READ — without it the SCM service cannot read
	// its config and fails to start (#77). Non-mutating: reads the DACL.
	results = append(results, checkConfigACLWindows(agent.SystemConfigPath()))

	return results
}

// checkSSHDropInWindows verifies the sshd drop-in is actually EFFECTIVE, not just
// present: the file exists, carries TrustedUserCAKeys + AuthorizedPrincipalsFile,
// and the base sshd_config Includes the drop-in dir GLOBALLY (before any Match
// block). A post-Match Include scopes the CA trust + principals to admins only,
// so non-admin cert login fails while file-presence stays green (#177 — the same
// blindness class as #175). Non-mutating: reads two files (ADR-0009 inspect).
func checkSSHDropInWindows(dropInPath, baseConfigPath string) CheckResult {
	const name = "sshd-drop-in"
	b, err := os.ReadFile(dropInPath)
	if err != nil {
		return CheckResult{Name: name, Status: CheckFail,
			Message: dropInPath + " not found. Run: uncluster agent install"}
	}
	content := string(b)
	if !strings.Contains(content, "TrustedUserCAKeys") || !strings.Contains(content, "AuthorizedPrincipalsFile") {
		return CheckResult{Name: name, Status: CheckWarn,
			Message: fmt.Sprintf("drop-in at %s is missing TrustedUserCAKeys/AuthorizedPrincipalsFile (run install to repair)", dropInPath)}
	}
	base, berr := os.ReadFile(baseConfigPath)
	if berr != nil {
		return CheckResult{Name: name, Status: CheckWarn,
			Message: fmt.Sprintf("drop-in present at %s but base sshd_config %s is unreadable — cannot confirm it is Included globally (%v)", dropInPath, baseConfigPath, berr)}
	}
	if !sshdConfigHasDropInInclude(string(base)) {
		return CheckResult{Name: name, Status: CheckFail,
			Message: fmt.Sprintf("drop-in at %s is present but %s does not Include sshd_config.d BEFORE its first Match block — the CA trust + principals apply to admins only, so non-admin cert login fails. Run: uncluster agent install (#177)", dropInPath, baseConfigPath)}
	}
	return CheckResult{Name: name, Status: CheckOK,
		Message: fmt.Sprintf("drop-in ok at %s (globally Included; has TrustedUserCAKeys + AuthorizedPrincipalsFile)", dropInPath)}
}
