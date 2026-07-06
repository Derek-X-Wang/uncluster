package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PayloadStore manages the Agent's self-updatable binary ("payload") under a
// service-account-writable directory, decoupled from the root-owned launcher
// binary that supervises it (ADR-0004 / ADR-0006, #187).
//
// Layout (root is owned by the low-priv service account; the launcher is NOT
// here — it lives root-owned at the stable install path and is never
// self-updated):
//
//	<root>/
//	  versions/<version>/uncluster   one immutable dir per staged version
//	  current   -> versions/<v>/uncluster   symlink; the version the launcher execs
//	  previous  -> versions/<v>/uncluster   symlink; last-known-good for rollback
//	  quarantine/<version>                   marker: this version failed its health
//	                                         commit; never re-activate it
//
// The current pointer is a symlink swapped atomically (write a temp symlink,
// rename it over `current`, fsync the root dir). Because rename(2) is atomic
// within a directory, there is never a window where `current` fails to resolve
// — fixing the rename(current→.prev)+rename(new→current) no-current-binary gap
// in the pre-#187 in-place swap.
type PayloadStore struct {
	root string
}

// NewPayloadStore returns a store rooted at dir. The directory is not created
// here; Init (called by install) or the caller must create it with the right
// ownership/mode first.
func NewPayloadStore(dir string) *PayloadStore {
	return &PayloadStore{root: dir}
}

// Root returns the managed payload directory.
func (s *PayloadStore) Root() string { return s.root }

func (s *PayloadStore) versionsDir() string   { return filepath.Join(s.root, "versions") }
func (s *PayloadStore) quarantineDir() string { return filepath.Join(s.root, "quarantine") }
func (s *PayloadStore) currentLink() string   { return filepath.Join(s.root, "current") }
func (s *PayloadStore) previousLink() string  { return filepath.Join(s.root, "previous") }

// payloadBinaryName is the fixed leaf name of the payload binary inside a
// version dir. Windows self-update relocation is out of scope for #187 (tracked
// in #139), but the name stays extension-free for cross-platform symmetry; the
// launcher execs it directly.
const payloadBinaryName = "uncluster"

// ErrNoCurrent is returned by Current when no version has been activated yet.
var ErrNoCurrent = errors.New("payloadstore: no current version")

// versionPathComponent validates a version string is safe to use as a single
// path component. Versions originate from the Control plane's update plan, so
// this is a defense-in-depth check against path traversal / separator
// injection into the versioned layout.
func versionPathComponent(version string) (string, error) {
	if version == "" {
		return "", fmt.Errorf("payloadstore: empty version")
	}
	if version == "." || version == ".." {
		return "", fmt.Errorf("payloadstore: invalid version %q", version)
	}
	for _, r := range version {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '+' || r == '-':
		default:
			return "", fmt.Errorf("payloadstore: version %q contains disallowed character %q", version, r)
		}
	}
	return version, nil
}

// versionBinaryPath returns the on-disk path of a version's payload binary.
func (s *PayloadStore) versionBinaryPath(version string) (string, error) {
	v, err := versionPathComponent(version)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.versionsDir(), v, payloadBinaryName), nil
}

// Init creates the store's directory skeleton (versions/, quarantine/) under an
// already-existing, correctly-owned root. Idempotent.
func (s *PayloadStore) Init() error {
	for _, d := range []string{s.versionsDir(), s.quarantineDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("payloadstore: mkdir %s: %w", d, err)
		}
	}
	return nil
}

// Stage writes a new version's binary from r into versions/<version>/uncluster
// with mode 0755, fsyncing the file. It does not touch the current pointer;
// call Activate to make it live. Staging a version that is already present
// overwrites it (the download was re-verified upstream). Returns the staged
// binary path.
func (s *PayloadStore) Stage(version string, r io.Reader) (string, error) {
	binPath, err := s.versionBinaryPath(version)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(binPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("payloadstore: mkdir version dir: %w", err)
	}
	// Write to a temp file in the same dir, fsync, then rename into place so a
	// crash mid-write never leaves a truncated binary at the version path.
	tmp, err := os.CreateTemp(dir, ".stage-*")
	if err != nil {
		return "", fmt.Errorf("payloadstore: create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("payloadstore: write payload: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("payloadstore: fsync payload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("payloadstore: close payload: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", fmt.Errorf("payloadstore: chmod payload: %w", err)
	}
	if err := os.Rename(tmpName, binPath); err != nil {
		return "", fmt.Errorf("payloadstore: install payload: %w", err)
	}
	cleanup = false
	if err := fsyncDir(dir); err != nil {
		return "", err
	}
	return binPath, nil
}

// Activate atomically points current at version's binary, moving the prior
// current to previous (last-known-good for rollback). fsyncs the root dir so
// the pointer swap is durable. Refuses to activate a quarantined version.
func (s *PayloadStore) Activate(version string) error {
	binPath, err := s.versionBinaryPath(version)
	if err != nil {
		return err
	}
	if s.IsQuarantined(version) {
		return fmt.Errorf("payloadstore: refusing to activate quarantined version %q", version)
	}
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("payloadstore: version %q not staged: %w", version, err)
	}
	// Roll the current pointer's target into previous first, so a later
	// Rollback has a known-good target.
	if cur, err := os.Readlink(s.currentLink()); err == nil {
		if err := swapSymlink(s.previousLink(), cur); err != nil {
			return err
		}
	}
	if err := swapSymlink(s.currentLink(), binPath); err != nil {
		return err
	}
	return fsyncDir(s.root)
}

// Current resolves the current pointer to (binaryPath, version). Returns
// ErrNoCurrent if nothing is activated.
func (s *PayloadStore) Current() (string, string, error) {
	return s.resolve(s.currentLink())
}

// Previous resolves the previous (last-known-good) pointer.
func (s *PayloadStore) Previous() (string, string, error) {
	return s.resolve(s.previousLink())
}

func (s *PayloadStore) resolve(link string) (string, string, error) {
	target, err := os.Readlink(link)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", ErrNoCurrent
		}
		return "", "", fmt.Errorf("payloadstore: read pointer %s: %w", link, err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	return target, s.versionOf(target), nil
}

// versionOf extracts the version component from a versions/<v>/uncluster path.
func (s *PayloadStore) versionOf(binPath string) string {
	return filepath.Base(filepath.Dir(binPath))
}

// Rollback repoints current at the previous (last-known-good) target and
// returns the version rolled back TO. Errors if there is no previous pointer.
func (s *PayloadStore) Rollback() (string, error) {
	prevTarget, prevVersion, err := s.Previous()
	if err != nil {
		if errors.Is(err, ErrNoCurrent) {
			return "", fmt.Errorf("payloadstore: no previous version to roll back to")
		}
		return "", err
	}
	if err := swapSymlink(s.currentLink(), prevTarget); err != nil {
		return "", err
	}
	if err := fsyncDir(s.root); err != nil {
		return "", err
	}
	return prevVersion, nil
}

// Quarantine records that version failed its post-update health commit so the
// update flow does not immediately re-download and re-activate the same bad
// version while the Control plane still advertises it (#187 spec item 1).
func (s *PayloadStore) Quarantine(version string) error {
	v, err := versionPathComponent(version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.quarantineDir(), 0o755); err != nil {
		return fmt.Errorf("payloadstore: mkdir quarantine: %w", err)
	}
	marker := filepath.Join(s.quarantineDir(), v)
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		return fmt.Errorf("payloadstore: write quarantine marker: %w", err)
	}
	return nil
}

// IsQuarantined reports whether version has a quarantine marker.
func (s *PayloadStore) IsQuarantined(version string) bool {
	v, err := versionPathComponent(version)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(s.quarantineDir(), v))
	return err == nil
}

// swapSymlink atomically points link at target: create link.tmp → target, then
// rename over link. The temp+rename keeps the swap atomic even when link
// already exists (a plain os.Symlink fails on an existing path).
func swapSymlink(link, target string) error {
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("payloadstore: create symlink %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("payloadstore: swap symlink %s: %w", link, err)
	}
	return nil
}

// fsyncDir fsyncs a directory so a rename/symlink swap within it is durable
// across a crash. A directory that cannot be opened read-only (should not
// happen for a store we own) is a hard error — durability is the point.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("payloadstore: open dir for fsync %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some filesystems (or platforms) reject fsync on a directory handle;
		// treat EINVAL/ENOTSUP as non-fatal since the rename is already durable
		// on mainstream Linux/macOS filesystems. Any other error propagates.
		if errors.Is(err, os.ErrInvalid) || isDirSyncUnsupported(err) {
			return nil
		}
		return fmt.Errorf("payloadstore: fsync dir %s: %w", dir, err)
	}
	return nil
}

// isDirSyncUnsupported reports whether a directory-fsync error is a platform
// "not supported on this fd" signal that is safe to ignore.
func isDirSyncUnsupported(err error) bool {
	// EINVAL / ENOTSUP surface as syscall errnos wrapped in *os.PathError.
	msg := err.Error()
	return strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "operation not supported")
}
