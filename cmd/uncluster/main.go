package main

import (
	"fmt"
	"os"

	"github.com/derek-x-wang/uncluster/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
