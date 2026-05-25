//go:build !windows

package agent

import (
	"testing"
)

// TestUnixPrevSuffix verifies that Unix uses .prev (not .old).
func TestUnixPrevSuffix(t *testing.T) {
	if prevSuffix != ".prev" {
		t.Errorf("prevSuffix on Unix = %q, want .prev", prevSuffix)
	}
}
