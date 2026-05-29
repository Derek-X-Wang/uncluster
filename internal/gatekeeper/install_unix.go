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
	"strconv"
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
	// Allocate a free UID and a free GID INDEPENDENTLY (#96 Bug 1). The UID
	// and GID namespaces are separate on macOS; the prior implementation
	// required the SAME number free as both, which fails on a dense host
	// (hosted macos-latest) where free UIDs and free GIDs exist but never
	// share a number. They need not match.
	uid, err := findFreeSystemUIDDarwin()
	if err != nil {
		return fmt.Errorf("find free uid: %w", err)
	}
	gid, err := findFreeSystemGIDDarwin()
	if err != nil {
		return fmt.Errorf("find free gid: %w", err)
	}

	// Create the GROUP record BEFORE the user (#96 Bug 2). Without this the
	// `_uncluster` group never exists, so lookupServiceGroup() returns "",
	// restrictSystemConfigACL() no-ops, and agent.toml stays root:wheel 0640
	// — unreadable by `_uncluster`, so the launchd service fails to start.
	// Linux's `useradd --system` auto-creates a matching group (USERGROUPS_
	// ENAB); macOS dscl does not, so we create it explicitly here.
	groupCmds := [][]string{
		{"dscl", ".", "-create", "/Groups/" + username},
		{"dscl", ".", "-create", "/Groups/" + username, "PrimaryGroupID", fmt.Sprintf("%d", gid)},
		{"dscl", ".", "-create", "/Groups/" + username, "RealName", "Uncluster Agent"},
	}
	// Then create the user, pointing PrimaryGroupID at the now-existing group.
	userCmds := [][]string{
		{"dscl", ".", "-create", "/Users/" + username},
		{"dscl", ".", "-create", "/Users/" + username, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", "/Users/" + username, "RealName", "Uncluster Agent"},
		{"dscl", ".", "-create", "/Users/" + username, "UniqueID", fmt.Sprintf("%d", uid)},
		{"dscl", ".", "-create", "/Users/" + username, "PrimaryGroupID", fmt.Sprintf("%d", gid)},
		{"dscl", ".", "-create", "/Users/" + username, "NFSHomeDirectory", "/var/empty"},
	}
	for _, c := range append(groupCmds, userCmds...) {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("dscl %v: %w\n%s", c, err, out)
		}
	}
	return nil
}

// macOS operator system-account window. 0-199 is Apple-reserved; 200-499 is
// the operator system-account window; 500+ is reserved for regular/interactive
// users (the hosted-runner user is 501). Widening past this in either
// direction is a rejected approach per #96 (collides with Apple-reserved or
// interactive accounts).
const (
	darwinSystemIDMin = 200
	darwinSystemIDMax = 499
)

// usedUIDsDarwin and usedGIDsDarwin return the set of currently-allocated
// UIDs/GIDs by listing the directory and parsing it. They are package-level
// vars so unit tests can inject fakes; the dscl calls themselves are
// integration-only.
//
// We list-and-parse rather than probe per ID because `dscl . -search /Users
// UniqueID <n>` exits 0 WHETHER OR NOT <n> matches (it succeeds with empty
// output on a miss). The prior per-ID `-search` predicate therefore reported
// every id as "in use", so findFreeIDDarwin found nothing and install failed
// with "no free system ID found in 200-499" even on a host with hundreds of
// free ids — the latent defect behind the original #92/#94 symptom, confirmed
// on the first t2-mac run of the #96 fix. `dscl . -list` returns the actual
// allocation, which is the reliable signal.
var (
	usedUIDsDarwin = func() (map[int]bool, error) {
		return listUsedIDsDarwin("/Users", "UniqueID")
	}
	usedGIDsDarwin = func() (map[int]bool, error) {
		return listUsedIDsDarwin("/Groups", "PrimaryGroupID")
	}
)

// listUsedIDsDarwin runs `dscl . -list <path> <key>` and parses the result.
func listUsedIDsDarwin(path, key string) (map[int]bool, error) {
	out, err := exec.Command("dscl", ".", "-list", path, key).Output()
	if err != nil {
		return nil, fmt.Errorf("dscl -list %s %s: %w", path, key, err)
	}
	return parseUsedIDsDarwin(string(out)), nil
}

// parseUsedIDsDarwin parses `dscl . -list <path> <key>` output — lines of
// "<record-name><whitespace><id>" — into the set of in-use numeric ids.
// Malformed lines (blank, missing id column, non-numeric id) are skipped so a
// dscl quirk or localized header cannot corrupt the set.
func parseUsedIDsDarwin(out string) map[int]bool {
	used := make(map[int]bool)
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		id, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		used[id] = true
	}
	return used
}

// findFreeSystemUIDDarwin returns the first free UID in the operator system-
// account window, scanned high-first.
func findFreeSystemUIDDarwin() (int, error) {
	used, err := usedUIDsDarwin()
	if err != nil {
		return 0, err
	}
	return findFreeIDDarwin(func(id int) bool { return used[id] })
}

// findFreeSystemGIDDarwin returns the first free GID in the operator system-
// account window, scanned high-first.
func findFreeSystemGIDDarwin() (int, error) {
	used, err := usedGIDsDarwin()
	if err != nil {
		return 0, err
	}
	return findFreeIDDarwin(func(id int) bool { return used[id] })
}

// findFreeIDDarwin scans the operator system-account window (200-499) downward
// and returns the first value for which inUse reports false. Iterating
// high-first keeps low IDs free for future Apple-reserved expansion and
// reduces collision risk with operator-created accounts.
//
// This is a pure scanner parameterised on an `inUse` predicate so UID and GID
// can be allocated INDEPENDENTLY in their own namespaces (#96 Bug 1): the
// returned UID and GID need not — and on a dense host will not — match.
func findFreeIDDarwin(inUse func(int) bool) (int, error) {
	for id := darwinSystemIDMax; id >= darwinSystemIDMin; id-- {
		if !inUse(id) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free system ID found in %d-%d range", darwinSystemIDMin, darwinSystemIDMax)
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
