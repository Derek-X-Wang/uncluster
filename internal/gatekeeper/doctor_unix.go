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
// principals dir → service account → service group → config ownership →
// service running → sshd config loaded.
//
// Doctor is strictly side-effect-free (the ADR-0009 `inspect` contract): every
// check reads (os.Stat, exec read-only queries, file reads) — none writes.
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

	// Resolve the service-account group once and share it across the
	// principals-dir and config-ownership checks (both grade against it). An
	// empty result means the group record is absent — checkServiceGroup
	// surfaces that as its own fail, so the owner/group/mode checks degrade to
	// owner+mode-only rather than double-reporting the missing group.
	wantGroup := lookupServiceGroupName()

	// 6. Principals directory: existence + owner/group/mode (#104). CI
	// asserted owner=root group=<service account> mode group-writable inline;
	// bringing it here makes doctor the strong source of truth, not a weaker
	// signal than CI.
	results = append(results, checkPrincipalsDirPerms(paths.PrincipalsDir, wantGroup))

	// 7. Service account.
	results = append(results, checkServiceAccount())

	// 7a. Service-account group (#96). The macOS group record is created
	// separately from the user; an absent group silently disables the
	// config-ownership ACL grant, so it gets its own legible check.
	results = append(results, checkServiceGroup())

	// 7b. System config ownership (#104). The macOS t2 job asserted
	// /etc/uncluster/agent.toml is root:<service account> 0640 inline; without
	// that ownership the low-priv service account cannot read its config and
	// the service fails to start (#96). Absent file → warn (doctor may run
	// pre-install), wrong ownership/mode → fail.
	results = append(results, checkConfigOwnership(agent.SystemConfigPath(), wantGroup))

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
	var err error
	switch runtime.GOOS {
	case "darwin":
		err = runServiceCmd("launchctl", "list", "com.openssh.sshd")
	default:
		if runServiceCmd("systemctl", "is-active", "--quiet", "ssh") == nil {
			return CheckResult{Name: "sshd-running", Status: CheckOK, Message: "sshd active"}
		}
		err = runServiceCmd("systemctl", "is-active", "--quiet", "sshd")
	}
	if err != nil {
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

func checkServiceAccount() CheckResult {
	username := serviceAccountName()
	if exec.Command("id", "-u", username).Run() != nil {
		return CheckResult{Name: "service-account", Status: CheckFail,
			Message: fmt.Sprintf("service account %q not found", username)}
	}
	return CheckResult{Name: "service-account", Status: CheckOK,
		Message: fmt.Sprintf("service account %q exists", username)}
}

// checkServiceGroup verifies the service-account GROUP record exists (#96).
// On macOS the group is a separate dscl record that install must create
// explicitly (Linux's useradd auto-creates it). If it is absent,
// restrictSystemConfigACL no-ops and the system agent.toml stays
// root:wheel 0640 — unreadable by the low-priv account — so the service
// cannot start. Surfacing this as its own check makes the failure legible
// to operators instead of presenting only as a downstream "config
// unreadable" / service-not-running symptom.
func checkServiceGroup() CheckResult {
	return serviceGroupResult(lookupServiceGroupName())
}

// serviceGroupResult maps a resolved group name to a CheckResult. Split out
// from the probe so the OK/Fail mapping is unit-testable; the lookup itself
// is integration-only.
func serviceGroupResult(group string) CheckResult {
	if group == "" {
		return CheckResult{Name: "service-group", Status: CheckFail,
			Message: fmt.Sprintf("service account group %q not found (config will be unreadable by the service account)", serviceAccountName())}
	}
	return CheckResult{Name: "service-group", Status: CheckOK,
		Message: fmt.Sprintf("service account group %q exists", group)}
}

// lookupServiceGroupName probes for the service-account group record and
// returns its name, or "" if absent. getent covers Linux (glibc/musl); dscl
// covers macOS (no getent). Mirrors agent.lookupServiceGroup but lives here so
// the gatekeeper doctor does not import the agent package's unexported helper.
func lookupServiceGroupName() string {
	for _, name := range []string{"uncluster", "_uncluster"} {
		if exec.Command("getent", "group", name).Run() == nil {
			return name
		}
		if exec.Command("dscl", ".", "-read", "/Groups/"+name).Run() == nil {
			return name
		}
	}
	return ""
}

func checkServiceRunning() CheckResult {
	switch runtime.GOOS {
	case "darwin":
		if runServiceCmd("launchctl", "list", agentServiceName) == nil {
			return CheckResult{Name: "service-running", Status: CheckOK,
				Message: agentServiceName + " loaded"}
		}
		return CheckResult{Name: "service-running", Status: CheckFail,
			Message: agentServiceName + " not loaded (run install)"}
	default:
		if runServiceCmd("systemctl", "is-active", "--quiet", agentServiceName) == nil {
			return CheckResult{Name: "service-running", Status: CheckOK,
				Message: "uncluster-agent service active"}
		}
		return CheckResult{Name: "service-running", Status: CheckFail,
			Message: "uncluster-agent service not active (run install)"}
	}
}

func checkSSHDEffectiveConfig(paths agent.ExpectedPaths) CheckResult {
	out, err := runServiceCmdOutput("sshd", "-T")
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
