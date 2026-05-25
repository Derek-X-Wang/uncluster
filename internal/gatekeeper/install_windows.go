//go:build windows

package gatekeeper

import (
	"context"
	"fmt"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// Install is not implemented on Windows (S9a handles Windows agent).
func Install(_ context.Context, _ agent.Config, _ string) error {
	return fmt.Errorf("uncluster agent install is not supported on Windows; see issue #8 (S9a)")
}
