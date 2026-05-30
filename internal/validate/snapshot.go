package validate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// fileState captures one path's pre-mutation state: either present (with its
// bytes + mode) or absent. Restore returns the path to exactly this.
type fileState struct {
	path    string
	existed bool
	mode    fs.FileMode
	content []byte
}

// Snap is a preflight snapshot of the state a mutating check will touch. Per
// ADR-0009 + ADR-0004, a mutating validation snapshots its install footprint
// (sshd drop-in, CA pubkey, principals dir, system agent.toml, service
// registration) BEFORE mutating, then Restore()s on failure so the machine is
// left clean. This generic file-set snapshotter is exercised first by the
// harmless bounded fixture (#108) and reused by the real install-smoke (#109).
type Snap struct {
	states []fileState
}

// Snapshot records the current state of each path so a later Restore can undo
// any create/modify/delete the mutating check performs. Directories and
// symlinks are out of scope for this slice (the footprint is regular files);
// a path that is a directory is recorded as "skip" so Restore leaves it alone.
func Snapshot(paths []string) (*Snap, error) {
	s := &Snap{}
	for _, p := range paths {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			s.states = append(s.states, fileState{path: p, existed: false})
		case err != nil:
			return nil, fmt.Errorf("snapshot stat %s: %w", p, err)
		case fi.IsDir():
			// Regular-file footprint only; recording a dir's bytes is
			// meaningless. Skip — Restore will not touch it.
			continue
		default:
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil, fmt.Errorf("snapshot read %s: %w", p, rerr)
			}
			s.states = append(s.states, fileState{
				path:    p,
				existed: true,
				mode:    fi.Mode().Perm(),
				content: b,
			})
		}
	}
	return s, nil
}

// Restore returns every snapshotted path to its recorded state: a file that
// existed is rewritten with its original bytes+mode; a file that did NOT exist
// is removed (undoing a create). Restore attempts every path even if one fails,
// and returns the first error — so a single un-restorable path does not strand
// the rest in a mutated state.
func (s *Snap) Restore() error {
	if s == nil {
		return nil
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, st := range s.states {
		if st.existed {
			if err := os.WriteFile(st.path, st.content, st.mode); err != nil {
				note(fmt.Errorf("restore write %s: %w", st.path, err))
				continue
			}
			// WriteFile only applies mode on create; force it for the
			// overwrite case so a mode change is also undone.
			if err := os.Chmod(st.path, st.mode); err != nil {
				note(fmt.Errorf("restore chmod %s: %w", st.path, err))
			}
		} else {
			if err := os.Remove(st.path); err != nil && !os.IsNotExist(err) {
				note(fmt.Errorf("restore remove %s: %w", st.path, err))
			}
		}
	}
	return firstErr
}

// Paths returns the snapshotted paths, for logging into evidence.
func (s *Snap) Paths() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.states))
	for _, st := range s.states {
		out = append(out, st.path)
	}
	return out
}
