//go:build windows

package agent

// prevSuffix is the extension appended to the binary path when swapping.
// On Windows: .old (per S10a — Windows uses .new/.old naming convention
// to avoid confusion with PowerShell/Windows service naming conventions).
const prevSuffix = ".old"
