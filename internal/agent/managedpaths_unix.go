//go:build !windows

package agent

import (
	"path/filepath"
	"runtime"
)

// This file centralises the two on-disk locations the #187 hybrid-launcher model
// introduces on Linux/macOS, plus the launcher↔payload marker paths derived from
// them. Windows self-update relocation is a separate slice (#139); these are
// Unix-only, so the file is //go:build !windows and Windows keeps its in-place
// swap posture.
//
// Two roles, two locations (ADR-0004/ADR-0006):
//
//   - LAUNCHER: root-owned, strict-chain, NEVER self-updated. It is the service
//     ExecStart target AND sshd's AuthorizedPrincipalsCommand binary (#185); its
//     whole path chain must be root-owned and not group/world-writable or sshd
//     refuses every cert login. It lives under /opt/uncluster because /opt is
//     root-owned by default on mainstream Linux (and, unlike /usr/local on hosted
//     CI runners, is not loosened for sudo-less tooling), so the strict chain
//     holds without per-host normalisation.
//
//   - PAYLOAD store: service-account-writable, versioned, self-updatable. The
//     low-priv Agent stages+activates new versions here (never touching the
//     root-owned launcher), which is exactly why sshd must NOT be pointed at it.

// managedPayloadDirFn is the package-private indirection tests swap out to
// redirect the payload store (and its derived marker paths) into a temp dir.
// Production code calls managedPayloadDir()/ManagedPayloadDir() through this var.
var managedPayloadDirFn = defaultManagedPayloadDir

// defaultManagedPayloadDir is the service-account-writable root of the versioned
// payload store (PayloadStore.Root()). Per-OS convention:
//   - linux:  /var/lib/uncluster        (FHS state dir for a system service)
//   - darwin: /usr/local/var/uncluster  (Homebrew-style var tree)
func defaultManagedPayloadDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/var/uncluster"
	default:
		return "/var/lib/uncluster"
	}
}

func managedPayloadDir() string { return managedPayloadDirFn() }

// ManagedPayloadDir returns the managed payload directory for this platform.
// Exported so the gatekeeper installer/doctor (which import this package) share
// one definition with the agent's launcher/self-update code.
func ManagedPayloadDir() string { return managedPayloadDir() }

// launcherDir is the root-owned directory holding the stable launcher binary.
// It and every ancestor must satisfy sshd's AuthorizedPrincipalsCommand
// safe-path rule (root-owned, not group/world-writable). /opt qualifies on both
// Linux and macOS with no per-host fix-ups.
func launcherDir() string { return "/opt/uncluster" }

// LauncherDir returns the root-owned launcher install directory.
func LauncherDir() string { return launcherDir() }

// launcherBinaryName is the fixed leaf name of the installed launcher binary.
const launcherBinaryName = "uncluster"

// LauncherPath returns the canonical, stable, root-owned launcher binary path.
// The installer COPIES the install-time binary here (root:root 0755) and uses
// THIS path — not the package-manager/user path the operator invoked (#139
// coherence item 6) — for both the service ExecStart and the sshd drop-in
// AuthorizedPrincipalsCommand. The launcher is never self-updated (that needs
// root; it is a fresh `agent install`), so it stays strict-chain-valid.
func LauncherPath() string {
	return filepath.Join(launcherDir(), launcherBinaryName)
}

// pendingUpdateMarkerName / healthMarkerName are the launcher↔payload
// coordination files under the managed payload dir. Both are service-writable
// (the low-priv Agent writes the pending marker; the payload child writes the
// health marker) and both carry a schema-versioned body (see healthmarker.go)
// so the contract can evolve without a flag day.
const (
	pendingUpdateMarkerName = "pending-update"
	healthMarkerName        = "health-marker"
)

// PendingUpdateMarkerPath is the marker the payload's update handler writes
// after it stages+activates a new version; the launcher polls it and restarts
// the child onto the new current version.
func PendingUpdateMarkerPath() string {
	return filepath.Join(managedPayloadDir(), pendingUpdateMarkerName)
}

// HealthMarkerPath is where the payload child writes its health-commit marker
// (after its first successful heartbeat) and where the launcher's health waiter
// polls. Passed to the child via the UNCLUSTER_HEALTH_MARKER env var so the two
// always agree even if the default location changes.
func HealthMarkerPath() string {
	return filepath.Join(managedPayloadDir(), healthMarkerName)
}
