//go:build !windows

package gatekeeper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

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

	// 4b. AuthorizedPrincipalsCommand binary is sshd-acceptable (#185): the
	// StrictModes-equivalent that now gates cert login on Unix.
	results = append(results, checkPrincipalsCommandBinary(paths))

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

// checkSSHDropIn asserts the Unix/macOS drop-in carries the #185
// AuthorizedPrincipalsCommand directives. It checks the directives are PRESENT
// (not a byte-exact match) so it is robust to the absolute command-binary path
// differing between hosts: TrustedUserCAKeys <ca>, an AuthorizedPrincipalsCommand
// invoking `... agent principals %u`, and AuthorizedPrincipalsCommandUser
// <service account>.
func checkSSHDropIn(paths agent.ExpectedPaths) CheckResult {
	b, err := os.ReadFile(paths.SSHDropIn)
	if err != nil {
		return CheckResult{Name: "sshd-drop-in", Status: CheckFail,
			Message: fmt.Sprintf("missing %s: %v", paths.SSHDropIn, err)}
	}
	content := string(b)
	user := serviceAccountName()
	var missing []string
	if !strings.Contains(content, "TrustedUserCAKeys "+paths.CAPubkey) {
		missing = append(missing, "TrustedUserCAKeys "+paths.CAPubkey)
	}
	if parseAuthorizedPrincipalsCommandBin(content) == "" || !strings.Contains(content, "agent principals %u") {
		missing = append(missing, "AuthorizedPrincipalsCommand <uncluster> agent principals %u")
	}
	if !strings.Contains(content, "AuthorizedPrincipalsCommandUser "+user) {
		missing = append(missing, "AuthorizedPrincipalsCommandUser "+user)
	}
	if len(missing) > 0 {
		return CheckResult{Name: "sshd-drop-in", Status: CheckWarn,
			Message: fmt.Sprintf("drop-in at %s missing/mismatched directive(s): %s (run install to repair)",
				paths.SSHDropIn, strings.Join(missing, "; "))}
	}
	return CheckResult{Name: "sshd-drop-in", Status: CheckOK,
		Message: fmt.Sprintf("drop-in ok at %s (AuthorizedPrincipalsCommand)", paths.SSHDropIn)}
}

// parseAuthorizedPrincipalsCommandBin extracts the command BINARY (the first
// token after the directive keyword) from an AuthorizedPrincipalsCommand line, or
// "" if the directive is absent. sshd checks THIS path's ownership/mode.
func parseAuthorizedPrincipalsCommandBin(content string) string {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "AuthorizedPrincipalsCommand") {
			return fields[1]
		}
	}
	return ""
}

// principalsCommandCheckName is the doctor check id for the
// AuthorizedPrincipalsCommand path-chain check (health.go maps it to
// "principals_command_binary").
const principalsCommandCheckName = "sshd-principals-command-binary"

// errUnsupportedStatPlatform signals that a path's POSIX ownership is not
// readable via *syscall.Stat_t. Unreachable on real Unix (this file is
// //go:build !windows), kept so walkCommandPathChain can degrade to the same
// defensive CheckWarn the prior leaf-only check emitted rather than a false
// fail.
var errUnsupportedStatPlatform = errors.New("ownership not readable on this platform")

// pathOwnership holds the ownership/mode facts sshd's safe_path needs about one
// path component. Extracted (with an injectable stat) so walkCommandPathChain is
// unit-testable on any OS without requiring real root-owned files (#195).
type pathOwnership struct {
	uid       uint32
	perm      os.FileMode // permission bits only
	isRegular bool
}

func statPathOwnership(p string) (pathOwnership, error) {
	info, err := os.Stat(p)
	if err != nil {
		return pathOwnership{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pathOwnership{}, errUnsupportedStatPlatform
	}
	return pathOwnership{uid: st.Uid, perm: info.Mode().Perm(), isRegular: info.Mode().IsRegular()}, nil
}

func principalsChainComponentKind(leaf bool) string {
	if leaf {
		return "binary"
	}
	return "ancestor directory"
}

// walkCommandPathChain mirrors sshd's safe_path (openssh misc.c) exactly as it
// is invoked for AuthorizedPrincipalsCommand. auth2-pubkey.c runs the command
// via subprocess(), which — with no SSH_SUBPROCESS_UNSAFE_PATH flag — calls
// safe_path(av[0], &st, NULL, /*uid=*/0, ...). safe_path walks the canonical
// path from the command binary up to "/" and rejects any component that is
// neither root-owned (platform_sys_dir_uid accepts only uid 0 on Linux/macOS;
// uid 2 "bin" only where PLATFORM_SYS_DIR_UID is compiled in, which excludes
// Linux/Darwin) nor owned by the passed uid (0 here) — and any component that is
// group/other-writable (mode & 022). The leaf must additionally be a regular
// file. So EVERY component of the command path must be root-owned and not
// group/world-writable; a loose ancestor (e.g. a non-root-strict /usr/local/bin
// on a hosted runner, #168/#184) is rejected by sshd even when the leaf binary
// is fine.
//
// #195: the prior check stat-ed only the leaf binary, so a loose ancestor passed
// doctor while sshd rejected the command ("Unsafe AuthorizedPrincipalsCommand
// ...: bad ownership or modes for directory /usr/local/bin") and cert login
// failed — the same doctor-blindness class as #175/#177/#179. This walks the
// full chain and names the offending component, mirroring sshd's own message.
//
// Note the AuthorizedPrincipalsCommandUser does NOT relax this: sshd runs the
// command as that user but still safe_path-checks with uid=0, so command-user
// ownership of a path component is rejected regardless. stat is injected for
// testability.
func walkCommandPathChain(bin string, stat func(string) (pathOwnership, error)) CheckResult {
	name := principalsCommandCheckName
	p := bin
	leaf := true
	for {
		own, err := stat(p)
		if err != nil {
			if errors.Is(err, errUnsupportedStatPlatform) {
				return CheckResult{Name: name, Status: CheckWarn,
					Message: "cannot read ownership of the command path on this platform"}
			}
			return CheckResult{Name: name, Status: CheckFail,
				Message: fmt.Sprintf("AuthorizedPrincipalsCommand %s %q not stat-able: %v",
					principalsChainComponentKind(leaf), p, err)}
		}
		if leaf && !own.isRegular {
			return CheckResult{Name: name, Status: CheckFail,
				Message: fmt.Sprintf("AuthorizedPrincipalsCommand binary %q is not a regular file; sshd rejects it", p)}
		}
		if own.uid != 0 {
			return CheckResult{Name: name, Status: CheckFail,
				Message: fmt.Sprintf("AuthorizedPrincipalsCommand %s %q owned by uid %d; sshd requires root (uid 0) for every component of the command path",
					principalsChainComponentKind(leaf), p, own.uid)}
		}
		if own.perm&0o022 != 0 {
			return CheckResult{Name: name, Status: CheckFail,
				Message: fmt.Sprintf("AuthorizedPrincipalsCommand %s %q is group/world-writable (mode %04o); sshd rejects the command path",
					principalsChainComponentKind(leaf), p, own.perm)}
		}
		parent := filepath.Dir(p)
		if parent == p { // reached "/" (or a volume root) — walk complete
			break
		}
		p = parent
		leaf = false
	}
	return CheckResult{Name: name, Status: CheckOK,
		Message: fmt.Sprintf("AuthorizedPrincipalsCommand binary %q and its full path chain (to /) are root-owned and not group/world-writable", bin)}
}

// checkPrincipalsCommandBinary asserts the AuthorizedPrincipalsCommand path is
// sshd-acceptable (#185): sshd refuses to run the command unless the binary AND
// every ancestor directory up to "/" is root-owned and not group/world-writable.
// This is the StrictModes-equivalent that now gates cert login on Unix — the
// principals FILES no longer are (they are the command's output, which sshd does
// not stat). Parses the actual path from the drop-in and canonicalises it
// (realpath, like sshd) so it verifies exactly what sshd verifies, walking the
// whole chain (#195), not just the leaf binary.
func checkPrincipalsCommandBinary(paths agent.ExpectedPaths) CheckResult {
	name := principalsCommandCheckName
	b, err := os.ReadFile(paths.SSHDropIn)
	if err != nil {
		return CheckResult{Name: name, Status: CheckFail,
			Message: fmt.Sprintf("cannot read drop-in %s: %v", paths.SSHDropIn, err)}
	}
	bin := parseAuthorizedPrincipalsCommandBin(string(b))
	if bin == "" {
		return CheckResult{Name: name, Status: CheckWarn,
			Message: fmt.Sprintf("no AuthorizedPrincipalsCommand directive in %s (run install to repair)", paths.SSHDropIn)}
	}
	if !filepath.IsAbs(bin) {
		return CheckResult{Name: name, Status: CheckFail,
			Message: fmt.Sprintf("AuthorizedPrincipalsCommand binary %q is not absolute (sshd requires an absolute path)", bin)}
	}
	// sshd canonicalises via realpath(3) before walking, so a symlinked install
	// dir is graded on its real components. Mirror that; a broken/unresolvable
	// path is a fail (sshd's realpath failure).
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return CheckResult{Name: name, Status: CheckFail,
			Message: fmt.Sprintf("AuthorizedPrincipalsCommand binary %q cannot be resolved: %v", bin, err)}
	}
	return walkCommandPathChain(resolved, statPathOwnership)
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
	var missing []string
	if !strings.Contains(content, strings.ToLower(paths.CAPubkey)) {
		missing = append(missing, "TrustedUserCAKeys")
	}
	// #185: Unix/macOS serve principals via AuthorizedPrincipalsCommand, so the
	// effective config reports `authorizedprincipalsfile none` and instead carries
	// `authorizedprincipalscommand <bin> agent principals %u`. Assert the command
	// is effective, not the (now-absent) file path.
	if !strings.Contains(content, "authorizedprincipalscommand") || !strings.Contains(content, "agent principals") {
		missing = append(missing, "AuthorizedPrincipalsCommand")
	}
	if len(missing) > 0 {
		return CheckResult{Name: "sshd-effective-config", Status: CheckFail,
			Message: fmt.Sprintf("sshd effective config missing: %s", strings.Join(missing, ", "))}
	}
	return CheckResult{Name: "sshd-effective-config", Status: CheckOK,
		Message: "sshd effective config has TrustedUserCAKeys + AuthorizedPrincipalsCommand"}
}
