//go:build !windows

package agent

// prevSuffix is the extension appended to the binary path when swapping.
// On Unix: .prev (conventional; .old would also work but .prev is clearer).
const prevSuffix = ".prev"
