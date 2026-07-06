//go:build windows

package gatekeeper

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
)

// windowsBaseSSHDConfig is the stock Win32-OpenSSH base config that the
// drop-in (sshd_config.d\uncluster.conf) is only honored through if it is
// Included. Win32-OpenSSH ships this file WITHOUT any Include directive
// (verified against openssh-portable contrib/win32/openssh/sshd_config), so
// on a stock host the drop-in is never read and cert login can never work.
const windowsBaseSSHDConfig = `C:\ProgramData\ssh\sshd_config`

// windowsIncludeLine is appended to the base sshd_config when no covering
// Include is found. Forward slashes work on Win32-OpenSSH and avoid any
// backslash-escaping ambiguity in the config grammar.
const windowsIncludeLine = "Include __PROGRAMDATA__/ssh/sshd_config.d/*"

// dropInIncludeMarker tags the line we append so re-installs can recognise
// (and never duplicate) our own edit.
const dropInIncludeMarker = "# Added by uncluster agent install"

// windowsPaths holds the canonical Windows paths for all SSH-related files
// managed by the Uncluster gatekeeper. It resolves from api.ExpectedPathsFor —
// the single source of truth also used by the Control plane's expected_paths
// response, the Windows principals writer, and doctor — so the installer can
// never create files in a directory sshd (per the same canonical paths) does
// not read (#145).
var windowsPaths = api.ExpectedPathsFor("windows")

// Install performs the privileged gatekeeper setup for Windows.
// It is idempotent: re-running repairs drift without clobbering existing state.
// Must run as Administrator (elevated).
//
// The #127 role-split: TWO services are registered. The low-priv
// `NT SERVICE\UnclusterAgent` (network-facing) gets NO write access to
// auth_principals; a LocalSystem, network-less, privilege-stripped
// `UnclusterPrincipalsWriter` is the only identity that writes principals files.
// Win32-OpenSSH silently ignores any AuthorizedPrincipalsFile carrying a
// write-class ACE for a principal outside {SYSTEM, Administrators}, so the agent
// could never hold such a grant and still have login work (ADR-0004 amendment).
//
// Steps:
//  1. Check sshd installed + running (OpenSSH server).
//  2. Write CA pubkey.
//  3. Write sshd drop-in config (+ ensure base config Includes the drop-in dir).
//  4. Create principals directory.
//  5. Install BOTH SCM services (agent + writer); set writer required-privileges.
//  6. Lock principals dir to {SYSTEM, Administrators} (NO agent ACE) and create
//     the spool dir with the agent↔writer ACL.
//  7. Save agent.toml to the system path (readable by the agent account).
//  8. Start both services.
//  9. Restart sshd.
func Install(ctx context.Context, cfg agent.Config, serviceExe string) error {
	paths := cfg.ExpectedPaths

	// 1. Check sshd installed and running.
	if err := checkSSHDWindows(ctx); err != nil {
		return err
	}

	// 2. Write CA pubkey.
	if err := writeCAPubkey(paths, cfg.CAPubkey); err != nil {
		return fmt.Errorf("write ca pubkey: %w", err)
	}

	// 3. Write sshd drop-in.
	if err := writeSSHDropIn(paths); err != nil {
		return fmt.Errorf("write sshd drop-in: %w", err)
	}

	// 3a. Ensure the base sshd_config Includes the drop-in dir. Win32-OpenSSH's
	// stock sshd_config has NO Include directive, so without this the drop-in
	// written in step 3 (TrustedUserCAKeys + AuthorizedPrincipalsFile) is never
	// read and cert login can never succeed (#126). The existing sshd restart
	// in step 9 picks up the edit. Mirrors ensureMacOSInclude on the Unix path.
	if err := ensureWindowsInclude(); err != nil {
		return fmt.Errorf("windows sshd_config include: %w", err)
	}

	// 4. Create principals directory.
	if err := ensurePrincipalsDir(paths); err != nil {
		return fmt.Errorf("create principals dir: %w", err)
	}

	// 5. Install BOTH SCM services. MUST happen before the principals-dir / spool
	// ACL step (#83): the `NT SERVICE\UnclusterAgent` virtual account is created
	// lazily by SCM when the agent service is registered, so its SID is only
	// resolvable for the spool ACE after this. The LocalSystem writer needs no
	// lazy SID (SYSTEM is well-known), but registering it here lets us strip its
	// privileges in the same step.
	if err := installService(ctx, cfg, serviceExe); err != nil {
		return fmt.Errorf("install agent service: %w", err)
	}
	if err := installPrincipalsWriterService(ctx, serviceExe); err != nil {
		return fmt.Errorf("install principals-writer service: %w", err)
	}
	if err := setWriterRequiredPrivileges(); err != nil {
		return fmt.Errorf("set writer required-privileges: %w", err)
	}

	// 6. Lock down the principals dir to {SYSTEM, Administrators} with NO ACE for
	// the agent (#127 — supersedes the pre-#127 grantPrincipalsAccessWindows
	// Modify grant, which inherited onto every per-user file and tripped
	// Win32-OpenSSH's secure-permission check). PROTECTED so a re-install over a
	// host carrying the old agent grant scrubs it. Then create the spool dir
	// (the ONLY place the agent gets write) with the agent↔writer ACL.
	if err := restrictPrincipalsDirACLWindows(paths.PrincipalsDir); err != nil {
		return fmt.Errorf("lock principals dir acl: %w", err)
	}
	if err := createSpoolDirWithACL(agent.SpoolDir()); err != nil {
		return fmt.Errorf("create spool dir: %w", err)
	}

	// 7. Save agent.toml to the system path. MUST happen AFTER installService
	// (step 5) so the `NT SERVICE\UnclusterAgent` SID is resolvable for the file
	// ACL grant, and BEFORE startServiceWindows (step 8) so the service can read
	// the file on first start (#77).
	sysPath := agent.SystemConfigPath()
	if err := agent.SaveConfigSystem(sysPath, cfg); err != nil {
		return fmt.Errorf("save system config to %s: %w", sysPath, err)
	}

	// 8. Start both services. The writer must be up so the agent's first policy
	// apply (which hands desired-state to the spool) can be serviced.
	if err := startServiceWindows(ctx); err != nil {
		return fmt.Errorf("start agent service: %w", err)
	}
	if err := startPrincipalsWriterServiceWindows(ctx); err != nil {
		return fmt.Errorf("start principals-writer service: %w", err)
	}

	// 9. Restart sshd so it picks up the new config.
	if err := reloadSSHDWindows(ctx); err != nil {
		return fmt.Errorf("restart sshd: %w", err)
	}

	return nil
}

// checkSSHDWindows checks that the Windows OpenSSH Server service is installed
// and running. Returns a descriptive error with install instructions if not.
func checkSSHDWindows(ctx context.Context) error {
	// Query SCM via sc.exe — simpler and more reliable than PowerShell in
	// constrained environments.
	out, err := exec.CommandContext(ctx,
		"sc.exe", "query", "sshd",
	).CombinedOutput()
	if err != nil {
		// Service not found — provide install instructions.
		return fmt.Errorf(
			"OpenSSH Server service (sshd) not found.\n"+
				"Install it with (run in an elevated PowerShell):\n\n"+
				"  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n"+
				"  Start-Service sshd\n"+
				"  Set-Service sshd -StartupType Automatic\n\n"+
				"error: %w\noutput: %s", err, string(out))
	}
	// Check if state is RUNNING.
	if !containsState(string(out), "RUNNING") {
		return fmt.Errorf(
			"OpenSSH Server (sshd) is installed but not running.\n" +
				"Start it with:\n\n" +
				"  Start-Service sshd\n" +
				"  Set-Service sshd -StartupType Automatic\n")
	}
	return nil
}

// containsState checks whether the sc.exe output contains the given state
// (case-insensitive, per line).
func containsState(output, state string) bool {
	stateLow := strings.ToLower(state)
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), stateLow) {
			return true
		}
	}
	return false
}

// NOTE (#127): the pre-role-split grantPrincipalsAccessWindows — which granted
// `NT SERVICE\UnclusterAgent` Modify on the principals dir via icacls — has been
// REMOVED. Win32-OpenSSH silently ignores any AuthorizedPrincipalsFile carrying
// a write-class ACE for a principal outside {SYSTEM, Administrators}, and that
// agent grant inherited onto every per-user file, so it was the root cause of
// "bad ownership or modes" cert-login failures. The agent now writes nothing
// under auth_principals; the LocalSystem UnclusterPrincipalsWriter does (see
// install_principalswriter_windows.go). doctor FAILS if the old agent grant is
// ever found again.

// ensureWindowsInclude ensures the stock base sshd_config Includes the
// sshd_config.d drop-in directory. It is the Windows analog of
// ensureMacOSInclude. Idempotent — never double-appends.
func ensureWindowsInclude() error {
	return ensureWindowsIncludeAt(windowsBaseSSHDConfig)
}

// ensureWindowsIncludeAt reads the base config at path; if it lacks a covering
// GLOBAL (pre-Match) drop-in Include directive, it inserts windowsIncludeLine
// (tagged with dropInIncludeMarker) BEFORE the first `Match` block so the
// included directives (TrustedUserCAKeys, AuthorizedPrincipalsFile) apply
// globally — not only to the connections a trailing Match matches.
//
// This is load-bearing (#177): the Win32-OpenSSH stock sshd_config ends with a
// `Match Group administrators` block, so APPENDING the Include at EOF (the old
// behaviour) scoped every drop-in directive to administrators only. For a
// non-admin connection the CA trust never applied and a CA-signed cert was
// rejected — Windows cert login never worked. A host carrying that old
// post-Match Include self-heals here, because sshdConfigHasDropInInclude only
// counts a pre-Match Include as covering.
//
// A missing base config is tolerated (not an error). Pure detection +
// transformation live in sshdConfigHasDropInInclude / insertIncludeBeforeFirstMatch
// so the matrix can unit-test the placement.
func ensureWindowsIncludeAt(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Base config absent — nothing to patch. sshd_config.d may still
			// be honored implicitly; do not fail the install.
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	content := string(b)
	if sshdConfigHasDropInInclude(content) {
		return nil // already covered by a global (pre-Match) include — idempotent
	}
	if err := os.WriteFile(path, []byte(insertIncludeBeforeFirstMatch(content)), 0o644); err != nil {
		return fmt.Errorf("write include into %s: %w", path, err)
	}
	return nil
}

// insertIncludeBeforeFirstMatch returns content with the drop-in Include block
// (marker + windowsIncludeLine) inserted immediately before the first `Match`
// line so the include is global. If there is no Match block, the block is
// appended at EOF (still global). A leading blank line separates it from
// surrounding content.
func insertIncludeBeforeFirstMatch(content string) string {
	block := "\n" + dropInIncludeMarker + "\n" + windowsIncludeLine + "\n"
	if idx := firstMatchLineOffset(content); idx >= 0 {
		return content[:idx] + block[1:] + content[idx:] // no leading blank before a Match line
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + block
}

// firstMatchLineOffset returns the byte offset of the start of the first line
// whose first token is `Match` (case-insensitive), or -1 if there is none.
func firstMatchLineOffset(content string) int {
	offset := 0
	for _, line := range strings.SplitAfter(content, "\n") {
		if fields := strings.Fields(strings.TrimSpace(line)); len(fields) > 0 && strings.EqualFold(fields[0], "Match") {
			return offset
		}
		offset += len(line)
	}
	return -1
}

// sshdConfigHasDropInInclude reports whether the given sshd_config content
// already carries an uncommented `Include` directive that pulls in the
// sshd_config.d drop-in directory. Matching is:
//   - case-insensitive on the `Include` keyword (sshd treats it so);
//   - tolerant of both `\` and `/` path separators;
//   - blind to whether the include ends in a glob (`*`) — a bare directory
//     include still pulls in the drop-in files;
//   - skips commented (`#`-prefixed) lines.
//
// It looks for the literal `sshd_config.d` path component (normalised to
// forward slashes) so an Include of some unrelated file does not match.
//
// Only a GLOBAL include counts (#177): an Include that appears AFTER the first
// `Match` line is scoped to that conditional block, so it does NOT make the
// drop-in's directives apply globally. Scanning stops at the first `Match` — an
// include found only past it is treated as not-covering, which is what lets a
// host with the old post-Match include self-heal on re-install.
func sshdConfigHasDropInInclude(content string) bool {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// A Match block begins here; any Include past it is not global.
		if strings.EqualFold(fields[0], "Match") {
			return false
		}
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}
		// Normalise the remainder's separators and look for the drop-in dir.
		rest := strings.ToLower(strings.ReplaceAll(line, `\`, "/"))
		if strings.Contains(rest, "sshd_config.d") {
			return true
		}
	}
	return false
}

// installService installs the Windows SCM service.
// On "already installed," queries the existing service config via `sc qc`
// and re-installs if the BINARY_PATH_NAME or SERVICE_START_NAME has drifted
// (see #50 — matches the Unix path's drift detection).
func installService(ctx context.Context, cfg agent.Config, serviceExe string) error {
	svc, err := buildService(cfg, serviceExe)
	if err != nil {
		return err
	}
	err = svc.Install()
	if err == nil {
		return nil
	}
	if !isAlreadyInstalledErr(err) {
		return err
	}
	// Already installed. Probe for drift via sc qc.
	out, qcErr := exec.CommandContext(ctx, "sc", "qc", agent.WindowsServiceName).CombinedOutput()
	if qcErr != nil {
		// Couldn't query; preserve pre-fix idempotent behaviour.
		return nil
	}
	drift := detectServiceUnitDrift(string(out), serviceExe, windowsServiceAccountName)
	if drift == "" {
		return nil
	}
	// Drift detected — rebuild.
	_ = exec.CommandContext(ctx, "net", "stop", agent.WindowsServiceName).Run()
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall drifted service (%s): %w", drift, err)
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("reinstall service after drift (%s): %w", drift, err)
	}
	return nil
}

// startServiceWindows starts (or restarts) the UnclusterAgent SCM service.
func startServiceWindows(ctx context.Context) error {
	// Stop first (idempotent — ignore errors from not-running).
	_ = exec.CommandContext(ctx, "net", "stop", agent.WindowsServiceName).Run()
	out, err := exec.CommandContext(ctx, "net", "start", agent.WindowsServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("net start %s: %w\noutput: %s", agent.WindowsServiceName, err, string(out))
	}
	return nil
}

// reloadSSHDWindows restarts the sshd service to pick up config changes.
func reloadSSHDWindows(ctx context.Context) error {
	// Windows OpenSSH Server doesn't support graceful reload — must restart.
	out, err := exec.CommandContext(ctx, "net", "stop", "sshd").CombinedOutput()
	if err != nil {
		// Log warning but don't fail — sshd may already be stopped.
		_ = out
	}
	out2, err2 := exec.CommandContext(ctx, "net", "start", "sshd").CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("net start sshd: %w\noutput: %s", err2, string(out2))
	}
	return nil
}

// isAlreadyInstalledErr checks if the error indicates the service already exists.
func isAlreadyInstalledErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already") || strings.Contains(s, "exists") ||
		strings.Contains(s, "1073")
}
