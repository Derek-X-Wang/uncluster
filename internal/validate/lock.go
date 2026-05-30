package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrLocked is returned when another mutating validation run holds the lock.
var ErrLocked = errors.New("validate: another mutating run holds the validation lock")

// staleLockAfter is how long a lock may sit before it is considered abandoned
// by a crashed run and safe to break. Mutating validation runs are minutes-
// scale; an hour-old lock means the holder died without releasing.
const staleLockAfter = time.Hour

// Lock is a held validation lock. Release() removes the lockfile. A mutating
// validation run holds exactly one of these so two runs cannot mutate the same
// real machine concurrently (ADR-0009: "no two agents mutating the same real
// machine concurrently").
type Lock struct {
	path string
	// token is written into the lockfile and re-checked on Release so we only
	// remove a lockfile we still own (not one a stale-break handed to someone
	// else in a pathological interleave).
	token string
}

// lockInfo is the lockfile payload: who holds it and since when. PID + start
// time let a later run decide whether a lock is stale (dead holder).
type lockInfo struct {
	PID   int    `json:"pid"`
	TS    int64  `json:"ts"` // unix seconds the lock was taken
	Token string `json:"token"`
}

// AcquireLock takes the validation lock at path, creating the parent dir. It
// uses O_CREATE|O_EXCL for atomic, cross-process mutual exclusion: the first
// creator wins; a concurrent attempt gets ErrLocked. A lock left by a crashed
// run (older than staleLockAfter, or whose PID is no longer alive) is broken
// once and the acquire retried, so a crash cannot wedge validation forever.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	tok := randHex(8)
	if lk, err := tryCreateLock(path, tok); err == nil {
		return lk, nil
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}

	// Lockfile exists. Break it iff stale, then retry exactly once.
	if breakIfStale(path) {
		if lk, err := tryCreateLock(path, tok); err == nil {
			return lk, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, ErrLocked
}

// tryCreateLock attempts the atomic O_EXCL create. Returns os.ErrExist
// (wrapped) when the lock is already held.
func tryCreateLock(path, token string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err // may be os.ErrExist
	}
	defer f.Close()
	info := lockInfo{PID: os.Getpid(), TS: time.Now().Unix(), Token: token}
	b, _ := json.Marshal(info)
	if _, err := f.Write(b); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write lock info: %w", err)
	}
	return &Lock{path: path, token: token}, nil
}

// breakIfStale removes the lockfile iff it is ABANDONED — unparseable, older
// than staleLockAfter, or held by a dead PID. Returns true only when it
// actually removed a stale lock.
//
// Crucially it does NOT treat a vanished lockfile as "broken": a file that
// disappeared between our EEXIST and this read is a live holder that just
// Release()d under normal contention, and racing a retry into that gap is how
// two acquirers could both win. In that case we return false so the caller
// gets ErrLocked rather than retrying into the just-freed slot. (The next
// caller to attempt AcquireLock will win it cleanly via O_EXCL.) Only a
// genuinely stale lock — dead holder / aged-out — is broken here.
func breakIfStale(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		// Vanished (live holder released) or unreadable — NOT stale; do not
		// retry into the gap.
		return false
	}
	var info lockInfo
	if json.Unmarshal(b, &info) != nil {
		// Empty or partially-written lockfile. This is almost always a lock
		// CREATION IN PROGRESS (tryCreateLock O_EXCL-creates the file, then
		// writes the JSON in a second step) — NOT an abandoned lock. Breaking
		// it here would let a second creator win and both proceed, which is the
		// exact mutual-exclusion bug this primitive must not have. Treat it as
		// held (return false → caller gets ErrLocked); a genuinely corrupt
		// lockfile will age out via its absent/zero TS only once it parses, or
		// the operator removes it.
		return false
	}
	if time.Since(time.Unix(info.TS, 0)) > staleLockAfter || !processAlive(info.PID) {
		return removeIfUnchanged(path, b)
	}
	return false
}

// removeIfUnchanged removes the lockfile only if its current contents still
// match what breakIfStale read — so we never delete a lock that a different
// process re-created in the meantime (which would let two winners coexist).
// Returns true only on a confirmed removal of the same stale file.
func removeIfUnchanged(path string, want []byte) bool {
	cur, err := os.ReadFile(path)
	if err != nil || string(cur) != string(want) {
		return false
	}
	return os.Remove(path) == nil
}

// Release removes the lockfile if we still own it (token matches). It is safe
// to call more than once.
func (l *Lock) Release() error {
	if l == nil || l.path == "" {
		return nil
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return err
	}
	var info lockInfo
	if json.Unmarshal(b, &info) == nil && info.Token != l.token {
		// A stale-break handed the lock to someone else; do not remove theirs.
		return nil
	}
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DefaultLockPath returns the validation lockfile path alongside the breadcrumb
// in the durable state dir.
func DefaultLockPath() (string, error) {
	bc, err := DefaultBreadcrumbPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(bc), "validation.lock"), nil
}

// writeStaleLockForTest writes a lockfile with a given pid + timestamp, used by
// the stale-break test. Kept in the production file (not _test.go) only because
// it must touch the unexported lockInfo shape; it is otherwise test-only.
func writeStaleLockForTest(path string, pid int, ts time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(lockInfo{PID: pid, TS: ts.Unix(), Token: "stale"})
	return os.WriteFile(path, b, 0o600)
}
