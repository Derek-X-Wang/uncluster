//go:build !windows

package gatekeeper

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// fakeFI is a minimal os.FileInfo whose Sys() yields a *syscall.Stat_t so
// tightenChain can read the owning uid.
type fakeFI struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeFI) Name() string       { return "" }
func (f fakeFI) Size() int64        { return 0 }
func (f fakeFI) Mode() os.FileMode  { return f.mode }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFI) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestTightenChain(t *testing.T) {
	dirMode := func(perm os.FileMode) os.FileMode { return os.ModeDir | perm }

	t.Run("root-owned loose ancestor is tightened, strict leaf untouched", func(t *testing.T) {
		fs := map[string]fakeFI{
			"/opt/uncluster": {mode: dirMode(0o755), uid: 0}, // already strict
			"/opt":           {mode: dirMode(0o777), uid: 0}, // loose, root-owned → tighten
		}
		chmods := map[string]os.FileMode{}
		err := tightenChain("/opt/uncluster",
			func(p string) (os.FileInfo, error) { return fs[p], nil },
			func(p string, m os.FileMode) error { chmods[p] = m; return nil })
		if err != nil {
			t.Fatalf("tightenChain: %v", err)
		}
		if _, ok := chmods["/opt/uncluster"]; ok {
			t.Errorf("strict leaf should not be chmod'd")
		}
		if got, ok := chmods["/opt"]; !ok || got != 0o755 {
			t.Errorf("/opt chmod = %04o present=%v, want 0755", got, ok)
		}
	})

	t.Run("non-root loose ancestor is left alone", func(t *testing.T) {
		fs := map[string]fakeFI{
			"/opt/uncluster": {mode: dirMode(0o755), uid: 0},
			"/opt":           {mode: dirMode(0o777), uid: 1000}, // loose but NOT root-owned
		}
		chmods := map[string]os.FileMode{}
		if err := tightenChain("/opt/uncluster",
			func(p string) (os.FileInfo, error) { return fs[p], nil },
			func(p string, m os.FileMode) error { chmods[p] = m; return nil }); err != nil {
			t.Fatal(err)
		}
		if len(chmods) != 0 {
			t.Errorf("non-root ancestor must not be chmod'd, got %v", chmods)
		}
	})

	t.Run("fully strict chain does nothing", func(t *testing.T) {
		fs := map[string]fakeFI{
			"/usr/lib/uncluster": {mode: dirMode(0o755), uid: 0},
			"/usr/lib":           {mode: dirMode(0o755), uid: 0},
			"/usr":               {mode: dirMode(0o755), uid: 0},
		}
		chmods := map[string]os.FileMode{}
		if err := tightenChain("/usr/lib/uncluster",
			func(p string) (os.FileInfo, error) { return fs[p], nil },
			func(p string, m os.FileMode) error { chmods[p] = m; return nil }); err != nil {
			t.Fatal(err)
		}
		if len(chmods) != 0 {
			t.Errorf("strict chain should chmod nothing, got %v", chmods)
		}
	})
}
