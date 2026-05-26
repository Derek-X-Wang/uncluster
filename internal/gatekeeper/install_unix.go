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

	// 8. Install system service (kardianos/service: launchd or systemd).
	if err := installService(ctx, cfg, serviceExe); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	// 9. Start service.
	if err := startService(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	// 10. Reload sshd.
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

func findFreeSystemIDDarwin() (uid, gid int, err error) {
	// Scan from 300 downward to find an unused UID/GID pair.
	for id := 300; id >= 200; id-- {
		checkUID := exec.Command("dscl", ".", "-search", "/Users", "UniqueID", fmt.Sprintf("%d", id))
		checkGID := exec.Command("dscl", ".", "-search", "/Groups", "PrimaryGroupID", fmt.Sprintf("%d", id))
		if checkUID.Run() != nil && checkGID.Run() != nil {
			return id, id, nil
		}
	}
	return 0, 0, fmt.Errorf("no free system UID/GID found in 200-300 range")
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
func installService(ctx context.Context, cfg agent.Config, serviceExe string) error {
	svc, err := buildService(cfg, serviceExe)
	if err != nil {
		return err
	}
	// Install is idempotent — ignore "already installed" errors.
	err = svc.Install()
	if err != nil && !isAlreadyInstalledErr(err) {
		return err
	}
	return nil
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
