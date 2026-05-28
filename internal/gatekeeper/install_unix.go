//go:build !windows

package gatekeeper

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// sshdConfigIncludeLine is added to the base sshd_config on macOS pre-Sonoma
// when it is missing.
const sshdConfigIncludeLine = "Include /etc/ssh/sshd_config.d/*"

// Install performs the privileged gatekeeper setup for Linux/macOS.
// It is idempotent: re-running repairs drift without clobbering existing state.
// Must run as root.
func Install(ctx context.Context, cfg agent.Config, serviceExe string) error {
	paths := cfg.ExpectedPaths

	// 1. Verify sshd installed + running.
	if err := checkSSHD(); err != nil {
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

	// 4. macOS pre-Sonoma: ensure base sshd_config includes the drop-in dir.
	if runtime.GOOS == "darwin" {
		if err := ensureMacOSInclude(); err != nil {
			return fmt.Errorf("macos sshd_config include: %w", err)
		}
	}

	// 5. Create principals directory.
	if err := ensurePrincipalsDir(paths); err != nil {
		return fmt.Errorf("create principals dir: %w", err)
	}

	// 6. Create service account.
	if err := ensureServiceAccount(); err != nil {
		return fmt.Errorf("create service account: %w", err)
	}

	// 7. Grant service account write access to principals dir.
	if err := grantPrincipalsAccess(paths.PrincipalsDir); err != nil {
		return fmt.Errorf("grant principals dir access: %w", err)
	}

	// 8. Save agent.toml to the system path with the correct ownership.
	// MUST happen AFTER ensureServiceAccount (step 6) so the `uncluster`
	// group exists for the chown root:uncluster, and BEFORE startService
	// (step 10) so the service can read the file on first start.
	//
	// Hotfix for #77: previously SaveConfigSystem was called from the CLI
	// install command BEFORE gatekeeper.Install ran — so the first pass
	// produced a root:root file (no group to chown to), and the second
	// pass (after Install returned) was too late: the service had already
	// crashed with "permission denied" and systemd was in its restart
	// backoff. Putting the save here makes the file land with correct
	// ownership BEFORE the service ever starts.
	sysPath := agent.SystemConfigPath()
	if err := agent.SaveConfigSystem(sysPath, cfg); err != nil {
		return fmt.Errorf("save system config to %s: %w", sysPath, err)
	}

	// 8a. Grant the service account WRITE access to the system config
	// directory so the agent (running as the low-priv service account)
	// can land the .deprovisioned marker next to agent.toml on a 410
	// Gone response.
	//
	// Knock-on fix for the #77 family: pre-#77, the marker landed in
	// the operator's HOME (always writable by the agent, who pre-#77
	// ran as the operator). Post-#77 the marker tries to land in
	// /etc/uncluster/ which defaults to root:root 0755 — the agent
	// has read access to agent.toml (group: uncluster) but no write
	// access to the parent dir, so the marker write silently fails
	// (#46's err-ignored os.WriteFile).
	//
	// Same chown+0775 shape as grantPrincipalsAccess. Marker is the
	// only file the agent ever writes into this dir, so over-granting
	// write is bounded.
	if err := grantConfigDirAccess(filepath.Dir(sysPath)); err != nil {
		return fmt.Errorf("grant config dir access: %w", err)
	}

	// 9. Install system service (kardianos/service: launchd or systemd).
	if err := installService(ctx, cfg, serviceExe); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	// 10. Start service.
	if err := startService(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	// 11. Reload sshd.
	if err := reloadSSHD(); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}

	return nil
}

// checkSSHD checks that sshd is installed and running.
// Returns a descriptive error with platform-specific install instructions if not.
func checkSSHD() error {
	// Check binary present.
	if _, err := exec.LookPath("sshd"); err != nil {
		return fmt.Errorf("sshd not found in PATH. Install it first:\n%s", sshdInstallHint())
	}
	// Check running.
	var checkCmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// On macOS, sshd is managed by launchd.
		checkCmd = exec.Command("launchctl", "list", "com.openssh.sshd")
	default:
		checkCmd = exec.Command("systemctl", "is-active", "--quiet", "ssh")
	}
	if err := checkCmd.Run(); err != nil {
		// Try alternate name on Debian/Ubuntu.
		if runtime.GOOS == "linux" {
			alt := exec.Command("systemctl", "is-active", "--quiet", "sshd")
			if alt.Run() != nil {
				return fmt.Errorf("sshd is not running. Start it with:\n%s", sshdStartHint())
			}
		} else {
			return fmt.Errorf("sshd is not running. Start it with:\n%s", sshdStartHint())
		}
	}
	return nil
}

func sshdInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "  System Preferences → Sharing → Remote Login (enable)"
	default:
		return "  sudo apt-get install openssh-server   # Debian/Ubuntu\n" +
			"  sudo dnf install openssh-server        # Fedora/RHEL"
	}
}

func sshdStartHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "  sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist"
	default:
		return "  sudo systemctl enable --now ssh   # Debian/Ubuntu\n" +
			"  sudo systemctl enable --now sshd  # Fedora/RHEL"
	}
}

// ensureMacOSInclude checks /etc/ssh/sshd_config for the Include directive
// and appends it if missing. Needed on macOS prior to Sonoma (14.0).
func ensureMacOSInclude() error {
	const sshdConfig = "/etc/ssh/sshd_config"
	b, err := os.ReadFile(sshdConfig)
	if err != nil {
		// File missing is acceptable — sshd_config.d still works if sshd supports it.
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.EqualFold(line, sshdConfigIncludeLine) {
			return nil // already present
		}
	}
	// Append the Include line.
	f, err := os.OpenFile(sshdConfig, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n# Added by uncluster agent install\n%s\n", sshdConfigIncludeLine)
	return err
}

// serviceAccountName returns the low-priv service account name for the platform.
func serviceAccountName() string {
	switch runtime.GOOS {
	case "darwin":
		return "_uncluster"
	default:
		return "uncluster"
	}
}

// ensureServiceAccount creates the service account if it does not exist.
func ensureServiceAccount() error {
	username := serviceAccountName()
	switch runtime.GOOS {
	case "darwin":
		return ensureServiceAccountDarwin(username)
	default:
		return ensureServiceAccountLinux(username)
	}
}

func ensureServiceAccountLinux(username string) error {
	// Check if user exists.
	if exec.Command("id", "-u", username).Run() == nil {
		return nil // already exists
	}
	return exec.Command("useradd",
		"--system",
		"--no-create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", "Uncluster agent service account",
		username,
	).Run()
}

func ensureServiceAccountDarwin(username string) error {
	// Check if user exists.
	if exec.Command("id", "-u", username).Run() == nil {
		return nil
	}
	// Find a free UID < 500 (macOS system accounts range).
	uid, gid, err := findFreeSystemIDDarwin()
	if err != nil {
		return fmt.Errorf("find free uid/gid: %w", err)
	}
	cmds := [][]string{
		{"dscl", ".", "-create", "/Users/" + username},
		{"dscl", ".", "-create", "/Users/" + username, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", "/Users/" + username, "RealName", "Uncluster Agent"},
		{"dscl", ".", "-create", "/Users/" + username, "UniqueID", fmt.Sprintf("%d", uid)},
		{"dscl", ".", "-create", "/Users/" + username, "PrimaryGroupID", fmt.Sprintf("%d", gid)},
		{"dscl", ".", "-create", "/Users/" + username, "NFSHomeDirectory", "/var/empty"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("dscl %v: %w\n%s", c, err, out)
		}
	}
	return nil
}

// findFreeSystemIDDarwin scans 200-499 (Apple's documented operator-
// system-account window per System User Accounts) downward and returns
// the first UID/GID pair where neither is in use. Iterating high-first
// keeps low IDs free for future Apple-reserved expansion and reduces
// collision risk with operator-created accounts.
//
// Range rationale: 0-199 is Apple-reserved; 200-499 is the operator
// system-account window; 500+ is reserved for regular users. The prior
// 200-300 bound was conservative without a documented reason and was
// exhausted on hosted macos-latest runners where Apple's preinstalled
// accounts plus the GitHub runner's own bootstrap accounts pack the
// low end densely (see #92).
func findFreeSystemIDDarwin() (uid, gid int, err error) {
	for id := 499; id >= 200; id-- {
		checkUID := exec.Command("dscl", ".", "-search", "/Users", "UniqueID", fmt.Sprintf("%d", id))
		checkGID := exec.Command("dscl", ".", "-search", "/Groups", "PrimaryGroupID", fmt.Sprintf("%d", id))
		if checkUID.Run() != nil && checkGID.Run() != nil {
			return id, id, nil
		}
	}
	return 0, 0, fmt.Errorf("no free system UID/GID found in 200-499 range")
}

// grantConfigDirAccess grants the service account write access to the
// system config directory (/etc/uncluster). Same shape as
// grantPrincipalsAccess. The agent uses this directory to land the
// .deprovisioned marker (#46) on a 410 Gone response — without write
// access, the marker write silently fails and the supervisor flap-
// restarts the agent against a revoked token forever.
//
// Linux: chown root:<service-account> + 0775. The file inside
// (agent.toml mode 0640) stays restricted; only the dir grants write.
// macOS: ACL-grant write+delete to the service user.
func grantConfigDirAccess(dir string) error {
	username := serviceAccountName()
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("chmod", "+a", username+" allow write,readattr,readextattr,list,add_file,add_subdirectory,delete_child,delete", dir).Run()
	default:
		if err := exec.Command("chown", "root:"+username, dir).Run(); err != nil {
			return fmt.Errorf("chown root:%s %s: %w", username, dir, err)
		}
		if err := exec.Command("chmod", "0775", dir).Run(); err != nil {
			return fmt.Errorf("chmod 0775 %s: %w", dir, err)
		}
		return nil
	}
}

// grantPrincipalsAccess grants the service account write access to the
// principals directory using chown (Linux) or ACL (macOS).
func grantPrincipalsAccess(dir string) error {
	username := serviceAccountName()
	switch runtime.GOOS {
	case "darwin":
		// macOS: use chmod_acl to grant write access without changing owner.
		return exec.Command("chmod", "+a", username+" allow write,readattr,readextattr,list,add_file,add_subdirectory,delete_child,delete", dir).Run()
	default:
		// Linux: chown root:uncluster + 0775 so service account can write files.
		if err := exec.Command("chown", "root:"+username, dir).Run(); err != nil {
			return err
		}
		return exec.Command("chmod", "0775", dir).Run()
	}
}

// installService installs the system service using kardianos/service.
// On "already installed," checks whether the on-disk unit file's executable
// path, username, and command arguments match the intended config. If any
// have drifted (operator moved the agent binary, changed the service
// account, etc.), the unit is rebuilt: Stop → Uninstall → Install. See #50.
// Pre-fix the "already installed" branch was silently suppressed, so a
// re-install with a different binary path quietly kept the old unit file.
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
	// Already installed. Check for drift and re-install if needed.
	drift, drErr := checkServiceUnitDrift(serviceExe, serviceAccountName())
	if drErr != nil {
		// Could not read the unit file (permission, missing, etc.). Keep the
		// idempotent behaviour rather than tearing down on stat error — the
		// pre-fix path was a no-op too.
		return nil
	}
	if drift == "" {
		return nil // no drift
	}
	// Drift detected — rebuild the unit.
	_ = stopServiceForReinstall(ctx)
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall drifted service (%s): %w", drift, err)
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("reinstall service after drift (%s): %w", drift, err)
	}
	return nil
}

// checkServiceUnitDrift reads the on-disk service unit and delegates to
// detectServiceUnitDrift for the substring comparisons. Returns an error
// only if the unit file cannot be read.
func checkServiceUnitDrift(intendedExe, intendedUser string) (string, error) {
	path := serviceUnitPath()
	if path == "" {
		return "", fmt.Errorf("unknown service unit path for GOOS=%s", runtime.GOOS)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return detectServiceUnitDrift(string(data), intendedExe, intendedUser), nil
}


// serviceUnitPath returns the on-disk location of the agent's system service
// unit file (systemd .service or launchd .plist).
func serviceUnitPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/LaunchDaemons/com.uncluster.agent.plist"
	case "linux":
		return "/etc/systemd/system/com.uncluster.agent.service"
	default:
		return ""
	}
}

// stopServiceForReinstall best-effort stops the service before uninstall.
// Errors are non-fatal because Uninstall doesn't require a running service.
func stopServiceForReinstall(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "launchctl", "stop", "com.uncluster.agent").Run()
	default:
		return exec.CommandContext(ctx, "systemctl", "stop", "com.uncluster.agent").Run()
	}
}

// startService starts (or restarts) the system service.
func startService(ctx context.Context) error {
	// Use platform command directly — kardianos/service.Start can fail if
	// already running; we want to restart idempotently.
	switch runtime.GOOS {
	case "darwin":
		_ = exec.CommandContext(ctx, "launchctl", "stop", "com.uncluster.agent").Run()
		return exec.CommandContext(ctx, "launchctl", "start", "com.uncluster.agent").Run()
	default:
		return exec.CommandContext(ctx, "systemctl", "restart", "com.uncluster.agent").Run()
	}
}

// reloadSSHD sends a graceful reload to sshd.
func reloadSSHD() error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("launchctl", "kickstart", "-k", "system/com.openssh.sshd").Run()
	default:
		// Try both service names used by different distros.
		if exec.Command("systemctl", "reload", "ssh").Run() == nil {
			return nil
		}
		return exec.Command("systemctl", "reload", "sshd").Run()
	}
}

func isAlreadyInstalledErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "already") || strings.Contains(s, "exists")
}
