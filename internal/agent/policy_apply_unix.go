//go:build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// doApplyPolicy on Unix rewrites the principals dir in-process. The low-priv
// service account owns the directory grant from install (ADR-0004) and writes
// agent-owned per-user files directly.
//
// #185: sshd does NOT StrictModes-check these files — that assumption (the prior
// comment claimed "sshd's StrictModes accepts a root/service-owned principals
// file") was FALSE and broke cert login through the real low-priv install, since
// StrictModes requires an AuthorizedPrincipalsFile to be root- or connecting-
// user-owned and not group/other-writable, which an `uncluster`-owned file in a
// group-writable dir is not. The fix routes principals to sshd via
// AuthorizedPrincipalsCommand (`uncluster agent principals %u`), whose OUTPUT sshd
// does not stat — so the agent keeps writing its low-priv files unchanged and no
// privileged writer/root-owned file is needed on Unix. (Windows still renders
// SYSTEM-owned files via the LocalSystem PrincipalsWriter — policy_apply_windows.go.)
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
