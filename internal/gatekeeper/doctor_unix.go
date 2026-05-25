//go:build !windows

package gatekeeper

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// Doctor runs all gatekeeper checks without making mutations and returns
// results. The slice is ordered: sshd → ca pubkey → drop-in → include →
// principals dir → service account → service running → sshd config loaded.
func Doctor(_ context.Context, cfg agent.Config) DoctorResults {
	paths := cfg.ExpectedPaths
	var results DoctorResults

	// 1. sshd present.
	results = append(results, checkSSHDBinary())

	// 2. sshd running.
	results = append(results, checkSSHDRunning())

	// 3. CA pubkey file exists and matches config.
	results = append(results, checkCAPubkey(paths, cfg.CAPubkey))

	// 4. sshd drop-in.
	results = append(results, checkSSHDropIn(paths))

	// 5. macOS Include.
	if runtime.GOOS == "darwin" {
		results = append(results, checkMacOSInclude())
	}

	// 6. Principals directory.
	results = append(results, checkPrincipalsDir(paths))

	// 7. Service account.
	results = append(results, checkServiceAccount())

	// 8. Service running.
	results = append(results, checkServiceRunning())

	// 9. sshd effective config (via `sshd -T`).
	results = append(results, checkSSHDEffectiveConfig(paths))

	return results
}

func checkSSHDBinary() CheckResult {
	_, err := exec.LookPath("sshd")
	if err != nil {
		return CheckResult{Name: "sshd-binary", Status: CheckFail,
			Message: "sshd not found in PATH"}
	}
	return CheckResult{Name: "sshd-binary", Status: CheckOK, Message: "sshd found"}
}

func checkSSHDRunning() CheckResult {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("launchctl", "list", "com.openssh.sshd")
	default:
		cmd = exec.Command("systemctl", "is-active", "--quiet", "ssh")
		if cmd.Run() == nil {
			return CheckResult{Name: "sshd-running", Status: CheckOK, Message: "sshd active"}
		}
		cmd = exec.Command("systemctl", "is-active", "--quiet", "sshd")
	}
	if cmd.Run() != nil {
		return CheckResult{Name: "sshd-running", Status: CheckFail, Message: "sshd not running"}
	}
	return CheckResult{Name: "sshd-running", Status: CheckOK, Message: "sshd active"}
}

func checkCAPubkey(paths agent.ExpectedPaths, wantPubkey string) CheckResult {
	b, err := os.ReadFile(paths.CAPubkey)
	if err != nil {
		return CheckResult{Name: "ca-pubkey", Status: CheckFail,
			Message: fmt.Sprintf("missing %s: %v", paths.CAPubkey, err)}
	}
	got := strings.TrimSpace(string(b))
	want := strings.TrimSpace(wantPubkey)
	if got != want {
		return CheckResult{Name: "ca-pubkey", Status: CheckFail,
			Message: fmt.Sprintf("ca pubkey mismatch at %s", paths.CAPubkey)}
	}
	return CheckResult{Name: "ca-pubkey", Status: CheckOK,
		Message: fmt.Sprintf("ca pubkey ok at %s", paths.CAPubkey)}
}

func checkSSHDropIn(paths agent.ExpectedPaths) CheckResult {
	b, err := os.ReadFile(paths.SSHDropIn)
	if err != nil {
		return CheckResult{Name: "sshd-drop-in", Status: CheckFail,
			Message: fmt.Sprintf("missing %s: %v", paths.SSHDropIn, err)}
	}
	want := sshdDropInContent(paths.CAPubkey, paths.PrincipalsDir+"/%u")
	if string(b) != want {
		return CheckResult{Name: "sshd-drop-in", Status: CheckWarn,
			Message: fmt.Sprintf("drop-in content mismatch at %s (run install to repair)", paths.SSHDropIn)}
	}
	return CheckResult{Name: "sshd-drop-in", Status: CheckOK,
		Message: fmt.Sprintf("drop-in ok at %s", paths.SSHDropIn)}
}

func checkMacOSInclude() CheckResult {
	const sshdConfig = "/etc/ssh/sshd_config"
	b, err := os.ReadFile(sshdConfig)
	if err != nil {
		// File missing — likely Sonoma+ where drop-in dir is always included.
		return CheckResult{Name: "macos-include", Status: CheckOK,
			Message: "sshd_config absent (Sonoma+ implicit include assumed)"}
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		if strings.EqualFold(strings.TrimSpace(scanner.Text()), sshdConfigIncludeLine) {
			return CheckResult{Name: "macos-include", Status: CheckOK,
				Message: "Include directive present in sshd_config"}
		}
	}
	return CheckResult{Name: "macos-include", Status: CheckWarn,
		Message: "Include /etc/ssh/sshd_config.d/* missing from sshd_config (run install to add)"}
}

func checkPrincipalsDir(paths agent.ExpectedPaths) CheckResult {
	info, err := os.Stat(paths.PrincipalsDir)
	if err != nil {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("missing %s: %v", paths.PrincipalsDir, err)}
	}
	if !info.IsDir() {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s exists but is not a directory", paths.PrincipalsDir)}
	}
	return CheckResult{Name: "principals-dir", Status: CheckOK,
		Message: fmt.Sprintf("principals dir ok at %s", paths.PrincipalsDir)}
}

func checkServiceAccount() CheckResult {
	username := serviceAccountName()
	if exec.Command("id", "-u", username).Run() != nil {
		return CheckResult{Name: "service-account", Status: CheckFail,
			Message: fmt.Sprintf("service account %q not found", username)}
	}
	return CheckResult{Name: "service-account", Status: CheckOK,
		Message: fmt.Sprintf("service account %q exists", username)}
}

func checkServiceRunning() CheckResult {
	switch runtime.GOOS {
	case "darwin":
		if exec.Command("launchctl", "list", "com.uncluster.agent").Run() == nil {
			return CheckResult{Name: "service-running", Status: CheckOK,
				Message: "com.uncluster.agent loaded"}
		}
		return CheckResult{Name: "service-running", Status: CheckFail,
			Message: "com.uncluster.agent not loaded (run install)"}
	default:
		if exec.Command("systemctl", "is-active", "--quiet", "com.uncluster.agent").Run() == nil {
			return CheckResult{Name: "service-running", Status: CheckOK,
				Message: "uncluster-agent service active"}
		}
		return CheckResult{Name: "service-running", Status: CheckFail,
			Message: "uncluster-agent service not active (run install)"}
	}
}

func checkSSHDEffectiveConfig(paths agent.ExpectedPaths) CheckResult {
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		return CheckResult{Name: "sshd-effective-config", Status: CheckWarn,
			Message: fmt.Sprintf("sshd -T failed: %v", err)}
	}
	content := strings.ToLower(string(out))
	wantCA := strings.ToLower(paths.CAPubkey)
	wantPrincipals := strings.ToLower(paths.PrincipalsDir)
	var missing []string
	if !strings.Contains(content, wantCA) {
		missing = append(missing, "TrustedUserCAKeys")
	}
	if !strings.Contains(content, wantPrincipals) {
		missing = append(missing, "AuthorizedPrincipalsFile")
	}
	if len(missing) > 0 {
		return CheckResult{Name: "sshd-effective-config", Status: CheckFail,
			Message: fmt.Sprintf("sshd effective config missing: %s", strings.Join(missing, ", "))}
	}
	return CheckResult{Name: "sshd-effective-config", Status: CheckOK,
		Message: "sshd effective config has TrustedUserCAKeys + AuthorizedPrincipalsFile"}
}
