//go:build !windows

package cli

import (
	"context"
	"fmt"
	"io"
)

// RunPrincipalsWriter is a no-op-with-error on non-Windows platforms. The
// LocalSystem AuthorizedPrincipalsFile writer exists only to satisfy
// Win32-OpenSSH's secure-permission check (#127); on Unix the agent writes the
// principals files in-process (ADR-0004), so there is nothing for a separate
// writer to do.
func RunPrincipalsWriter(_ context.Context, _ io.Writer) error {
	return fmt.Errorf("principals-writer is a Windows-only service")
}
