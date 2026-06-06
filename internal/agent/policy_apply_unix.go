//go:build !windows

package agent

import (
	"os"
	"path/filepath"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// doApplyPolicy on Unix rewrites the principals dir in-process. The low-priv
// service account holds the directory grant from install (ADR-0004), and
// sshd's StrictModes accepts a root/service-owned principals file, so the agent
// can write the files directly with no privilege handoff. This is byte-for-byte
// the pre-#127 behaviour; the Windows path (policy_apply_windows.go) differs.
func (a *Agent) doApplyPolicy(dir string, snap api.PolicyPayload) error {
	return renderPrincipalsDir(dir, snap)
}

// wipePrincipals on Unix removes every per-user principals file in dir directly.
// The Unix service account owns the dir (ADR-0004) and can delete its files, so
// this is byte-identical to the pre-#127 onRevoked behaviour. Best-effort: a
// removal error is ignored (deprovision proceeds regardless).
func (a *Agent) wipePrincipals(dir string) {
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
