//go:build !windows

package gatekeeper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/version"
)

// sshdConfigIncludeLine is added to the base sshd_config on macOS pre-Sonoma
// when it is missing.
const sshdConfigIncludeLine = "Include /etc/ssh/sshd_config.d/*"

// Install performs the privileged gatekeeper setup for Linux/macOS.
// It is idempotent: re-running repairs drift without clobbering existing state.
// Must run as root.
//
// installExe is the binary the operator invoked (e.g. /usr/local/bin/uncluster).
// Under the #187 hybrid-launcher model the installer does NOT point the service
// at that package-manager/user path (#139 coherence item 6). Instead it:
//
//   - copies installExe to the stable, root-owned LAUNCHER path
//     (agent.LauncherPath(), /opt/uncluster/uncluster), used for BOTH the
//     service ExecStart (`agent launch`) and sshd's AuthorizedPrincipalsCommand
//     — its whole path chain is root-owned so sshd's safe-path check passes;
//   - seeds a service-account-writable versioned PAYLOAD store
//     (agent.ManagedPayloadDir()) with installExe as the first version. The
//     low-priv agent self-updates the payload there, never the root-owned
//     launcher, and never touches sshd's command path.
func Install(ctx context.Context, cfg agent.Config, installExe string) error {
	paths := cfg.ExpectedPaths

	// 1. Verify sshd installed + running.
	if err := checkSSHD(); err != nil {
		return err
	}

	// 2. Install the stable, root-owned launcher binary. Done before the drop-in
	// so sshd's AuthorizedPrincipalsCommand points at a binary that already
	// exists with a strict path chain.
	launcherPath := agent.LauncherPath()
	if err := installLauncherBinary(installExe, launcherPath); err != nil {
		return fmt.Errorf("install launcher binary: %w", err)
	}

	// 3. Write CA pubkey.
	if err := writeCAPubkey(paths, cfg.CAPubkey); err != nil {
		return fmt.Errorf("write ca pubkey: %w", err)
	}

	// 4. Write sshd drop-in (#185: AuthorizedPrincipalsCommand form). The
	// launcher path is what sshd runs as the AuthorizedPrincipalsCommand — a
	// root-owned, strict-chain, NON-self-updating binary — NOT the service-
	// writable payload (pointing sshd there would re-break every cert login,
	// #187/#185). The service account is the AuthorizedPrincipalsCommandUser.
	if err := writeSSHDropIn(paths, launcherPath, serviceAccountName()); err != nil {
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

	// 7b. Set up the service-account-writable managed payload store and seed it
	// with the install-time binary (#187). Done AFTER ensureServiceAccount so the
	// account exists to own the tree. The low-priv agent self-updates the payload
	// here; the launcher execs the current version.
	if err := setupPayloadStore(installExe); err != nil {
		return fmt.Errorf("set up managed payload store: %w", err)
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

	// 9. Install system service (kardianos/service: launchd or systemd). The
	// ExecStart is the root-owned launcher running `agent launch` (buildService),
	// NOT the operator's install path.
	if err := installService(ctx, cfg, launcherPath); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	// 9b. Bound launcher-crash restart to ≤30s (ADR-0006). kardianos hardcodes
	// RestartSec=120 in v1.2.4; a systemd drop-in overrides it. Restart only on
	// failure so a clean shutdown or deprovision (launcher exits 0) does not
	// flap-restart. Linux/systemd only.
	if err := writeSystemdRestartOverride(ctx); err != nil {
		return fmt.Errorf("configure launcher restart timing: %w", err)
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
	// Check running. Routed through runServiceCmd so the probe is unit-testable
	// without a live init system (#151); default behavior is unchanged.
	var runErr error
	switch runtime.GOOS {
	case "darwin":
		// On macOS, sshd is managed by launchd.
		runErr = runServiceCmd("launchctl", "list", "com.openssh.sshd")
	default:
		runErr = runServiceCmd("systemctl", "is-active", "--quiet", "ssh")
	}
	if runErr != nil {
		// Try alternate name on Debian/Ubuntu.
		if runtime.GOOS == "linux" {
			if runServiceCmd("systemctl", "is-active", "--quiet", "sshd") != nil {
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

// restartOverrideConf is the systemd drop-in content that bounds launcher-crash
// restart to ≤30s (ADR-0006) and restarts only on failure. Exposed as a const so
// a unit test can assert its shape without a live systemd.
const restartOverrideConf = "[Service]\nRestart=on-failure\nRestartSec=5\n"

// writeSystemdRestartOverride drops a RestartSec/Restart override next to the
// kardianos-generated unit and reloads systemd. Linux only (launchd has its own
// respawn throttle and is not adjusted here; the launcher's in-process rollback,
// not the service restart, is what meets the ≤30s budget on a bad UPDATE — the
// service restart only matters if the launcher itself crashes).
func writeSystemdRestartOverride(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	unitPath := serviceUnitPath()
	if unitPath == "" {
		return fmt.Errorf("unknown systemd unit path for GOOS=%s", runtime.GOOS)
	}
	dropInDir := unitPath + ".d"
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		return fmt.Errorf("mkdir drop-in dir %s: %w", dropInDir, err)
	}
	override := filepath.Join(dropInDir, "restart.conf")
	if err := os.WriteFile(override, []byte(restartOverrideConf), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", override, err)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w\n%s", err, out)
	}
	return nil
}

// installLauncherBinary copies the install-time binary to the stable, root-owned
// launcher path and locks down ownership/mode so sshd's AuthorizedPrincipalsCommand
// safe-path check accepts it (the binary AND every ancestor dir must be root-
// owned and not group/world-writable). The copy is atomic (temp + rename) so a
// concurrent cert auth never execs a half-written launcher. A no-op copy when the
// operator invoked the launcher binary itself (re-install), but ownership/mode
// are still re-asserted.
func installLauncherBinary(srcExe, launcherPath string) error {
	dir := filepath.Dir(launcherPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir launcher dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return fmt.Errorf("chown launcher dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("chmod launcher dir %s: %w", dir, err)
	}
	if !sameFile(srcExe, launcherPath) {
		if err := copyFileAtomic(srcExe, launcherPath, 0o755); err != nil {
			return err
		}
	}
	if err := os.Chown(launcherPath, 0, 0); err != nil {
		return fmt.Errorf("chown launcher %s: %w", launcherPath, err)
	}
	if err := os.Chmod(launcherPath, 0o755); err != nil {
		return fmt.Errorf("chmod launcher %s: %w", launcherPath, err)
	}
	return nil
}

// sameFile reports whether a and b resolve to the same on-disk file.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// copyFileAtomic copies src to dst via a temp file in dst's dir + rename, so a
// reader/executor never observes a partial file.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, dst, err)
	}
	cleanup = false
	return nil
}

// setupPayloadStore creates the service-account-writable managed payload dir,
// initialises the versioned store, and — on a FRESH install only — seeds it with
// the install-time binary as the first version and activates it. Seeding once is
// deliberate: on re-install the store may already hold a newer, self-updated
// current version (Current() resolves), which the installer must not downgrade.
// The whole tree is then handed to the service account so the low-priv agent can
// stage+activate future updates and the launcher (same account) can exec current.
func setupPayloadStore(installExe string) error {
	dir := agent.ManagedPayloadDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir payload dir %s: %w", dir, err)
	}
	// Not world-writable (doctor hygiene requirement).
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("chmod payload dir %s: %w", dir, err)
	}
	store := agent.NewPayloadStore(dir)
	if err := store.Init(); err != nil {
		return err
	}
	if _, _, err := store.Current(); errors.Is(err, agent.ErrNoCurrent) {
		f, err := os.Open(installExe)
		if err != nil {
			return fmt.Errorf("open install binary %s: %w", installExe, err)
		}
		defer f.Close()
		if _, err := store.Stage(version.Version, f); err != nil {
			return fmt.Errorf("seed payload version %s: %w", version.Version, err)
		}
		if err := store.Activate(version.Version); err != nil {
			return fmt.Errorf("activate seed payload %s: %w", version.Version, err)
		}
	} else if err != nil {
		return fmt.Errorf("resolve current payload: %w", err)
	}
	if err := chownTreeToServiceAccount(dir); err != nil {
		return fmt.Errorf("chown payload tree to service account: %w", err)
	}
	return nil
}

// chownTreeToServiceAccount recursively chowns dir to the low-priv service
// account (user only) so it can create version dirs, swap the current/previous
// symlinks, and write markers. The launcher (same account) execs the current
// version's binary. Exec permission comes from the 0755 file mode staging sets;
// write permission comes from the account owning the directories.
func chownTreeToServiceAccount(dir string) error {
	if out, err := exec.Command("chown", "-R", serviceAccountName(), dir).CombinedOutput(); err != nil {
		return fmt.Errorf("chown -R %s %s: %w\n%s", serviceAccountName(), dir, err, out)
	}
	return nil
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
	// #187: the Unix service ExecStart is `<launcher> agent launch`.
	return detectServiceUnitDrift(string(data), intendedExe, intendedUser, "agent", "launch"), nil
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

// stopServiceForReinstall best-effort stops the service and removes it from the
// launchd domain (darwin) before uninstall. Errors are non-fatal because
// Uninstall doesn't require a running or bootstrapped service.
//
// Darwin: `launchctl bootout` removes the job from the system domain BEFORE
// kardianos/service Uninstall deletes the plist. Without bootout, the domain
// retains a tombstone for the deleted plist and a subsequent `launchctl
// bootstrap` on the new plist exits 17 (EEXIST) which, though treated as
// idempotent, can leave stale domain state pointing at the old binary path.
func stopServiceForReinstall(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		// Best-effort bootout: unregisters the job from the system domain.
		// Ignore error — the job may not be bootstrapped yet (failed mid-install).
		_ = darwinLaunchctlBootout(ctx)
		return nil
	default:
		return exec.CommandContext(ctx, "systemctl", "stop", "com.uncluster.agent").Run()
	}
}

// startService starts (or restarts) the system service.
//
// Darwin: on modern macOS, dropping a plist into /Library/LaunchDaemons does
// not automatically register the job in the system domain. kardianos/service
// Install() writes the plist but does NOT bootstrap it, so the legacy
// `launchctl start <label>` (which requires a pre-loaded job) exits 3 with
// "Could not find service in domain for system" — the #99 failure. The fix:
//  1. bootstrapServiceDarwin: `launchctl bootstrap system <plist>` to
//     register the job in the system domain (idempotent — EEXIST treated
//     as success so re-running agent install stays green).
//  2. darwinLaunchctlKickstart: `launchctl kickstart -k system/<label>` to
//     (re)start the now-bootstrapped job. -k makes it safe on an already-
//     running job. Same domain-qualified verb the existing reloadSSHD uses
//     for sshd.
func startService(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		if err := bootstrapServiceDarwin(ctx); err != nil {
			return err
		}
		return darwinLaunchctlKickstart(ctx)
	default:
		return exec.CommandContext(ctx, "systemctl", "restart", "com.uncluster.agent").Run()
	}
}

// reloadSSHD sends a graceful reload to sshd. Routed through runServiceCmd so the
// restart path is unit-testable without root (#151); real behavior is unchanged.
func reloadSSHD() error {
	switch runtime.GOOS {
	case "darwin":
		return runServiceCmd("launchctl", "kickstart", "-k", "system/com.openssh.sshd")
	default:
		// Try both service names used by different distros.
		if runServiceCmd("systemctl", "reload", "ssh") == nil {
			return nil
		}
		return runServiceCmd("systemctl", "reload", "sshd")
	}
}

func isAlreadyInstalledErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "already") || strings.Contains(s, "exists")
}
