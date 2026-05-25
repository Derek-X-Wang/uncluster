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
