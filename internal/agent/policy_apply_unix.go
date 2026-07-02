//go:build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// doApplyPolicy on Unix rewrites the principals dir in-process. The low-priv
// service account holds the directory grant from install (ADR-0004), and
// sshd's StrictModes accepts a root/service-owned principals file, so the agent
// can write the files directly with no privilege handoff. This is byte-for-byte
// the pre-#127 behaviour; the Windows path (policy_apply_windows.go) differs.
//
// ctx is accepted for signature parity with the Windows path (which waits on the
// LocalSystem writer and must honour shutdown, #153). The Unix render is a fast,
// synchronous in-process operation with nothing to wait on, so ctx is unused
// here — keeping the non-Windows behaviour byte-identical.
func (a *Agent) doApplyPolicy(_ context.Context, dir string, snap api.PolicyPayload) error {
	return renderPrincipalsDir(dir, snap)
}

// wipePrincipals on Unix removes every per-user principals file in dir directly.
// The Unix service account owns the dir (ADR-0004) and can delete its files, so
// this is byte-identical to the pre-#127 onRevoked behaviour. Best-effort: a
// removal error is ignored (deprovision proceeds regardless). ctx is accepted
// for parity with the Windows writer-routed wipe (#153) and is unused here.
func (a *Agent) wipePrincipals(_ context.Context, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
