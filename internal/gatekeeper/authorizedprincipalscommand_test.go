//go:build !windows

package gatekeeper

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// TestSSHDropInContentUnix asserts the Unix drop-in carries the #185
// AuthorizedPrincipalsCommand directives and NOT the StrictModes-fragile
// AuthorizedPrincipalsFile.
func TestSSHDropInContentUnix(t *testing.T) {
	got := sshdDropInContentUnix("/etc/ssh/uncluster_ca.pub", "/usr/local/bin/uncluster", "uncluster")
	for _, want := range []string{
		"TrustedUserCAKeys /etc/ssh/uncluster_ca.pub",
		"AuthorizedPrincipalsCommand /usr/local/bin/uncluster agent principals %u",
		"AuthorizedPrincipalsCommandUser uncluster",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing directive %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "AuthorizedPrincipalsFile") {
		t.Errorf("Unix drop-in must NOT use AuthorizedPrincipalsFile (#185):\n%s", got)
	}
}

func TestParseAuthorizedPrincipalsCommandBin(t *testing.T) {
	content := sshdDropInContentUnix("/etc/ssh/ca.pub", "/usr/local/bin/uncluster", "uncluster")
	if got := parseAuthorizedPrincipalsCommandBin(content); got != "/usr/local/bin/uncluster" {
		t.Errorf("parsed bin = %q, want /usr/local/bin/uncluster", got)
	}
	if got := parseAuthorizedPrincipalsCommandBin("TrustedUserCAKeys /x\n"); got != "" {
		t.Errorf("expected empty for absent directive, got %q", got)
	}
}

func TestCheckSSHDropIn_Command(t *testing.T) {
	dir := t.TempDir()
	paths := agent.ExpectedPaths{
		CAPubkey:      filepath.Join(dir, "uncluster_ca.pub"),
		SSHDropIn:     filepath.Join(dir, "uncluster.conf"),
		PrincipalsDir: filepath.Join(dir, "auth_principals"),
	}
	user := serviceAccountName()

	// Missing file → fail.
	if got := checkSSHDropIn(paths); got.Status != CheckFail {
		t.Errorf("missing drop-in should fail, got %v", got.Status)
	}

	// Proper command content → ok.
	good := sshdDropInContentUnix(paths.CAPubkey, "/usr/local/bin/uncluster", user)
	if err := os.WriteFile(paths.SSHDropIn, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := checkSSHDropIn(paths); got.Status != CheckOK {
		t.Errorf("valid command drop-in should be ok, got %v: %s", got.Status, got.Message)
	}

	// Old AuthorizedPrincipalsFile shape (pre-#185) → warn (missing command dirs).
	legacy := "TrustedUserCAKeys " + paths.CAPubkey + "\nAuthorizedPrincipalsFile " + paths.PrincipalsDir + "/%u\n"
	if err := os.WriteFile(paths.SSHDropIn, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := checkSSHDropIn(paths); got.Status != CheckWarn {
		t.Errorf("legacy AuthorizedPrincipalsFile drop-in should warn, got %v: %s", got.Status, got.Message)
	}
}

func TestCheckPrincipalsCommandBinary(t *testing.T) {
	dir := t.TempDir()
	dropIn := filepath.Join(dir, "uncluster.conf")
	paths := agent.ExpectedPaths{SSHDropIn: dropIn, CAPubkey: filepath.Join(dir, "ca.pub")}

	write := func(bin string) {
		content := sshdDropInContentUnix(paths.CAPubkey, bin, "uncluster")
		if err := os.WriteFile(dropIn, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Non-absolute path → fail.
	write("uncluster")
	if got := checkPrincipalsCommandBinary(paths); got.Status != CheckFail {
		t.Errorf("non-absolute command binary should fail, got %v", got.Status)
	}

	// Non-existent absolute path → fail.
	write(filepath.Join(dir, "does-not-exist"))
	if got := checkPrincipalsCommandBinary(paths); got.Status != CheckFail {
		t.Errorf("missing command binary should fail, got %v", got.Status)
	}

	// A file owned by the (non-root) test user → fail (sshd requires root).
	nonroot := filepath.Join(dir, "uncluster")
	if err := os.WriteFile(nonroot, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 { // the CI/dev host runs tests as non-root
		write(nonroot)
		if got := checkPrincipalsCommandBinary(paths); got.Status != CheckFail {
			t.Errorf("non-root-owned command binary should fail, got %v: %s", got.Status, got.Message)
		}
	}

	// A real root-owned, non-writable system binary → ok (matches the installed
	// /usr/local/bin/uncluster shape). Skip if no such binary is present/uid 0.
	rootBin := ""
	for _, cand := range []string{"/bin/ls", "/bin/sh", "/usr/bin/true"} {
		if info, err := os.Stat(cand); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 && info.Mode().Perm()&0o022 == 0 {
				rootBin = cand
				break
			}
		}
	}
	if rootBin == "" {
		t.Skip("no root-owned non-writable system binary available to exercise the OK path")
	}
	write(rootBin)
	if got := checkPrincipalsCommandBinary(paths); got.Status != CheckOK {
		t.Errorf("root-owned non-writable command binary %q should be ok, got %v: %s", rootBin, got.Status, got.Message)
	}
}
