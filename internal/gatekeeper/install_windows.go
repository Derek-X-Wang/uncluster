//go:build windows

package gatekeeper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
)

// windowsBaseSSHDConfig is the stock Win32-OpenSSH base config. On Windows the
// running OpenSSH service does NOT honour `sshd_config.d` Includes (#179 —
// verified on OpenSSH_for_Windows_9.5p2: `sshd -T` does not expand them and a
// service connection with the drop-in Included still rejects the cert). So the
// gatekeeper writes its directives DIRECTLY into this file, before the first
// `Match` block — see ensureWindowsBaseConfigDirectives.
const windowsBaseSSHDConfig = `C:\ProgramData\ssh\sshd_config`

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

	// 3. Write the CA-trust + principals directives DIRECTLY into the base
	// sshd_config (before the first Match block). Win32-OpenSSH's service does
	// NOT honour sshd_config.d Includes (#179), so a drop-in never takes effect;
	// a base-config directive does. Idempotent and self-healing from every older
	// shape (post-Match Include #126, pre-Match Include #177, prior managed
	// block), and it removes the now-unused drop-in file. The sshd restart in
	// step 9 picks up the edit.
	if err := ensureWindowsBaseConfigDirectives(paths); err != nil {
		return fmt.Errorf("windows sshd base-config directives: %w", err)
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

// ensureWindowsBaseConfigDirectives writes the uncluster-managed directive block
// (TrustedUserCAKeys + AuthorizedPrincipalsFile) DIRECTLY into the base
// sshd_config, before the first `Match` block, so the running Win32-OpenSSH
// service actually honours it (#179 — it ignores sshd_config.d Includes; probe
// on OpenSSH_for_Windows_9.5p2 in PR #174). It is idempotent and self-heals from
// every older shape (post-Match Include #126, pre-Match Include #177, a prior
// managed block) via upsertManagedBlock, and it removes the now-unused drop-in
// file. A missing base config is tolerated (not an error); doctor surfaces that.
func ensureWindowsBaseConfigDirectives(paths agent.ExpectedPaths) error {
	block := managedDirectiveBlock(paths.CAPubkey, paths.PrincipalsDir+"/%u")
	b, err := os.ReadFile(windowsBaseSSHDConfig)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", windowsBaseSSHDConfig, err)
	}
	if updated := upsertManagedBlock(string(b), block); updated != string(b) {
		if err := os.WriteFile(windowsBaseSSHDConfig, []byte(updated), 0o644); err != nil {
			return fmt.Errorf("write directives into %s: %w", windowsBaseSSHDConfig, err)
		}
	}
	// Self-heal: the drop-in file was never honoured on Windows; remove it.
	if paths.SSHDropIn != "" {
		_ = os.Remove(paths.SSHDropIn)
	}
	return nil
}

// RemoveWindowsManagedDirectives removes the uncluster-managed directive block
// from the base sshd_config (deprovision). Exported for the CLI deprovision
// cleanup hook. Removing an absent block is a no-op.
func RemoveWindowsManagedDirectives() error {
	b, err := os.ReadFile(windowsBaseSSHDConfig)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", windowsBaseSSHDConfig, err)
	}
	updated := removeManagedBlock(string(b))
	if updated == string(b) {
		return nil
	}
	if err := os.WriteFile(windowsBaseSSHDConfig, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("remove directives from %s: %w", windowsBaseSSHDConfig, err)
	}
	return nil
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
	drift := detectServiceUnitDrift(string(out), serviceExe, windowsServiceAccountName, "agent", "run")
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
