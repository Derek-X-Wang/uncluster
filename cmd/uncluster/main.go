package main

import (
	"fmt"
	"os"

	"github.com/derek-x-wang/uncluster/internal/cli"
)

// exitCoder is satisfied by errors that carry a specific exit code (e.g.,
// `uncluster agent doctor` exits 1=warn, 2=fail per the acceptance criteria).
type exitCoder interface {
	ExitCode() int
}

func main() {
	// On Windows, if launched by the Service Control Manager, the binary
	// must complete the SCM control-handler handshake before SCM's 30s
	// timeout or `net start UnclusterAgent` returns exit 2 ("service did
	// not respond"). runAsWindowsService detects that context, routes the
	// agent run loop through svc.Run, and exits when SCM tells it to.
	// On non-Windows (or Windows but not under SCM), it is a no-op
	// returning false — control falls through to the cobra path below.
	// See #88.
	if handled, err := runAsWindowsService(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if err := cli.NewRoot().Execute(); err != nil {
		// Check for typed exit codes first (e.g., doctor warn/fail).
		if ec, ok := err.(exitCoder); ok {
			os.Exit(ec.ExitCode())
		}
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, "error:", msg)
		}
		os.Exit(1)
	}
}
