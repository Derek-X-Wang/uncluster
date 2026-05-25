//go:build windows

package agent

import (
	"testing"
)

// TestWindowsPrevSuffix verifies that Windows uses .old (not .prev).
func TestWindowsPrevSuffix(t *testing.T) {
	if prevSuffix != ".old" {
		t.Errorf("prevSuffix on Windows = %q, want .old", prevSuffix)
	}
}
