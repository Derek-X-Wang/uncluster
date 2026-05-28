//go:build windows

package gatekeeper

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// windowsPaths holds the canonical Windows paths for all SSH-related files
// managed by the Uncluster gatekeeper.
var windowsPaths = struct {
	CAPubkey      string
	SSHDropIn     string
	PrincipalsDir string
}{
	CAPubkey:      `C:\ProgramData\ssh\uncluster_ca.pub`,
	SSHDropIn:     `C:\ProgramData\ssh\sshd_config.d\uncluster.conf`,
	PrincipalsDir: `C:\ProgramData\ssh\auth_principals`,
}

// Install performs the privileged gatekeeper setup for Windows.
// It is idempotent: re-running repairs drift without clobbering existing state.
// Must run as Administrator (elevated).
//
// Steps:
//  1. Check sshd installed + running (OpenSSH server).
//  2. Write CA pubkey.
//  3. Write sshd drop-in config.
//  4. Create principals directory.
//  5. Grant service account write access to principals dir via icacls.
//  6. Install SCM service (kardianos/service).
//  7. Start SCM service.
//  8. Restart sshd.
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

	// 4. Create principals directory.
	if err := ensurePrincipalsDir(paths); err != nil {
		return fmt.Errorf("create principals dir: %w", err)
	}

	// 5. Install SCM service. MUST happen before grantPrincipalsAccessWindows
	// (#83): the `NT SERVICE\UnclusterAgent` virtual account is created
	// lazily by SCM when the service is registered. Granting an ACL to a
	// not-yet-existing SID returns icacls error 1332 ("No mapping between
	// account names and security IDs was done.").
	if err := installService(ctx, cfg, serviceExe); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	// 6. Grant service account write access to principals dir via icacls.
	// Safe to call now that the virtual account SID exists.
	if err := grantPrincipalsAccessWindows(paths.PrincipalsDir); err != nil {
		return fmt.Errorf("grant principals dir access: %w", err)
	}

	// 7. Save agent.toml to the system path. MUST happen AFTER
	// installService (step 5) so the `NT SERVICE\UnclusterAgent` SID is
	// resolvable for the file ACL grant, and BEFORE startServiceWindows
	// (step 8) so the service can read the file on first start.
	//
	// Hotfix for #77: previously SaveConfigSystem was called from the CLI
	// install command BEFORE gatekeeper.Install ran — so the first pass
	// produced an ACL without the UnclusterAgent ACE (SID didn't exist
	// yet), and the second pass (after Install returned) was too late:
	// `net start UnclusterAgent` had already failed with exit 2 ("service
	// did not respond") because the service couldn't read its config.
	// Putting the save here, AFTER the SID exists and BEFORE start,
	// means the file lands with the right ACL on first try.
	sysPath := agent.SystemConfigPath()
	if err := agent.SaveConfigSystem(sysPath, cfg); err != nil {
		return fmt.Errorf("save system config to %s: %w", sysPath, err)
	}

	// 8. Start service.
	if err := startServiceWindows(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
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
			"OpenSSH Server (sshd) is installed but not running.\n"+
				"Start it with:\n\n"+
				"  Start-Service sshd\n"+
				"  Set-Service sshd -StartupType Automatic\n")
	}
	return nil
}

// containsState checks whether the sc.exe output contains the given state.
func containsState(output, state string) bool {
	for _, line := range splitLines(output) {
		if containsInsensitive(line, state) {
			return true
		}
	}
	return false
}

// splitLines splits s on newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// containsInsensitive checks if s contains substr case-insensitively.
func containsInsensitive(s, substr string) bool {
	sLow := toLower(s)
	subLow := toLower(substr)
	for i := 0; i <= len(sLow)-len(subLow); i++ {
		if sLow[i:i+len(subLow)] == subLow {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// grantPrincipalsAccessWindows grants the service virtual account write access
// to the principals directory using icacls.
func grantPrincipalsAccessWindows(dir string) error {
	// Grant: (OI)(CI) = object-inherit + container-inherit for recursive access.
	// M = Modify, which includes read+write+delete (enough for writing principal files).
	out, err := exec.Command(
		"icacls", dir,
		"/grant", windowsServiceAccountName+":(OI)(CI)M",
		"/T", // apply recursively
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls grant: %w\noutput: %s", err, string(out))
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
	out, qcErr := exec.CommandContext(ctx, "sc", "qc", "UnclusterAgent").CombinedOutput()
	if qcErr != nil {
		// Couldn't query; preserve pre-fix idempotent behaviour.
		return nil
	}
	drift := detectServiceUnitDrift(string(out), serviceExe, windowsServiceAccountName)
	if drift == "" {
		return nil
	}
	// Drift detected — rebuild.
	_ = exec.CommandContext(ctx, "net", "stop", "UnclusterAgent").Run()
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
	_ = exec.CommandContext(ctx, "net", "stop", "UnclusterAgent").Run()
	out, err := exec.CommandContext(ctx, "net", "start", "UnclusterAgent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("net start UnclusterAgent: %w\noutput: %s", err, string(out))
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
	s := err.Error()
	return containsInsensitive(s, "already") || containsInsensitive(s, "exists") ||
		containsInsensitive(s, "1073")
}

// writePrincipalsFile writes the principals file for the given username.
// On Windows, ensures the directory exists first (mode bits not relevant).
func writePrincipalsFile(dir, username string, principals []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	content := ""
	for _, p := range principals {
		content += p + "\n"
	}
	return os.WriteFile(dir+"\\"+username, []byte(content), 0o644)
}
