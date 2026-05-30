//go:build windows

package gatekeeper

import (
	"context"
	"os"
	"os/exec"

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

	// 4. sshd drop-in present.
	dropIn := paths.SSHDropIn
	if dropIn == "" {
		dropIn = windowsPaths.SSHDropIn
	}
	if _, err := os.Stat(dropIn); err == nil {
		results = append(results, CheckResult{Name: "sshd-drop-in", Status: CheckOK})
	} else {
		results = append(results, CheckResult{
			Name: "sshd-drop-in", Status: CheckFail,
			Message: dropIn + " not found. Run: uncluster agent install",
		})
	}

	// 5. Principals dir exists, is a directory, and grants the service
	// account write access — verified by READING the DACL (non-mutating).
	// The prior implementation write-probed by creating + removing a temp
	// file, which violates the ADR-0009 `inspect` contract that lets the
	// auto-invoke hook run `doctor`. CI asserted the grant by grepping
	// `icacls` for "UnclusterAgent" (#104).
	pDir := paths.PrincipalsDir
	if pDir == "" {
		pDir = windowsPaths.PrincipalsDir
	}
	results = append(results, checkPrincipalsACLWindows(pDir))

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

	// 8. System config ownership (#104). The Unix doctor checks the system
	// agent.toml is owned root:<service account> 0640 (readable by the service
	// account, not world). The Windows equivalent is the DACL granting
	// `NT SERVICE\UnclusterAgent` READ — without it the SCM service cannot read
	// its config and fails to start (#77). Non-mutating: reads the DACL.
	results = append(results, checkConfigACLWindows(agent.SystemConfigPath()))

	return results
}
