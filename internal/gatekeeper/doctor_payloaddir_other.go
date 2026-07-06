//go:build !windows && !linux && !darwin

package gatekeeper

// payloadDirIsNoexec is unimplemented on other Unix variants (the project ships
// linux/darwin/windows); returning known=false makes the doctor skip the noexec
// assertion rather than emit a false fail.
func payloadDirIsNoexec(_ string) (noexec bool, known bool) { return false, false }
