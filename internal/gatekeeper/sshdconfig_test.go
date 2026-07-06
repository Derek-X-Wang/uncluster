package gatekeeper

import (
	"strings"
	"testing"
)

const (
	testCA        = `C:\ProgramData\ssh\uncluster_ca.pub`
	testPrincipal = `C:\ProgramData\ssh\auth_principals/%u`
)

func testBlock() string { return managedDirectiveBlock(testCA, testPrincipal) }

// stockConfig mimics the Win32-OpenSSH default: global directives then a trailing
// `Match Group administrators` block.
const stockConfig = "# stock\n" +
	"PasswordAuthentication yes\n" +
	"AllowGroups administrators \"openssh users\"\n" +
	"Subsystem\tsftp\tsftp-server.exe\n\n" +
	"Match Group administrators\n" +
	"       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"

func TestManagedBlockDirectivesEffective(t *testing.T) {
	got := upsertManagedBlock(stockConfig, testBlock())
	if !hasManagedBlockBeforeMatch(got) {
		t.Fatalf("managed block not effective (before Match):\n%s", got)
	}
	if !strings.Contains(got, "TrustedUserCAKeys "+testCA) {
		t.Errorf("TrustedUserCAKeys directive missing:\n%s", got)
	}
	if !strings.Contains(got, "AuthorizedPrincipalsFile "+testPrincipal) {
		t.Errorf("AuthorizedPrincipalsFile directive missing:\n%s", got)
	}
	// The block must precede the Match line to be global.
	if strings.Index(got, managedBlockBegin) > strings.Index(got, "Match Group administrators") {
		t.Errorf("managed block placed after the Match block:\n%s", got)
	}
	// Original content preserved.
	if !strings.Contains(got, "administrators_authorized_keys") {
		t.Errorf("stock Match content lost:\n%s", got)
	}
}

func TestManagedBlockIdempotent(t *testing.T) {
	once := upsertManagedBlock(stockConfig, testBlock())
	twice := upsertManagedBlock(once, testBlock())
	if once != twice {
		t.Errorf("upsert not idempotent:\nonce:\n%s\ntwice:\n%s", once, twice)
	}
	if n := strings.Count(twice, managedBlockBegin); n != 1 {
		t.Errorf("expected exactly one managed block, got %d:\n%s", n, twice)
	}
}

func TestManagedBlockNoMatchAppends(t *testing.T) {
	const noMatch = "PasswordAuthentication yes\n"
	got := upsertManagedBlock(noMatch, testBlock())
	if !hasManagedBlockBeforeMatch(got) {
		t.Errorf("block not effective when config has no Match:\n%s", got)
	}
	if !strings.Contains(got, "PasswordAuthentication yes") {
		t.Errorf("original content lost:\n%s", got)
	}
}

// Self-heal: a host carrying the pre-#179 drop-in Include (post-Match, the
// #126/#177-pre buggy shape) must end up with the managed block global and the
// stale Include stripped.
func TestSelfHealFromPostMatchInclude(t *testing.T) {
	buggy := "PasswordAuthentication yes\n" +
		"Match Group administrators\n       AuthorizedKeysFile x\n\n" +
		legacyIncludeMarker + "\n" +
		"Include __PROGRAMDATA__/ssh/sshd_config.d/*\n"
	got := upsertManagedBlock(buggy, testBlock())
	if strings.Contains(got, "sshd_config.d") {
		t.Errorf("legacy Include not stripped:\n%s", got)
	}
	if strings.Contains(got, legacyIncludeMarker) {
		t.Errorf("legacy marker not stripped:\n%s", got)
	}
	if !hasManagedBlockBeforeMatch(got) {
		t.Errorf("managed block not effective after self-heal:\n%s", got)
	}
}

// Self-heal: a host carrying the #177 pre-Match Include must likewise migrate to
// the managed block with the Include removed.
func TestSelfHealFromPreMatchInclude(t *testing.T) {
	cfg := "PasswordAuthentication yes\n" +
		legacyIncludeMarker + "\n" +
		"Include __PROGRAMDATA__/ssh/sshd_config.d/*\n" +
		"Match Group administrators\n       AuthorizedKeysFile x\n"
	got := upsertManagedBlock(cfg, testBlock())
	if strings.Contains(got, "sshd_config.d") {
		t.Errorf("pre-Match Include not stripped:\n%s", got)
	}
	if !hasManagedBlockBeforeMatch(got) {
		t.Errorf("managed block not effective after self-heal:\n%s", got)
	}
}

func TestRemoveManagedBlock(t *testing.T) {
	withBlock := upsertManagedBlock(stockConfig, testBlock())
	removed := removeManagedBlock(withBlock)
	if strings.Contains(removed, managedBlockBegin) || strings.Contains(removed, managedBlockEnd) {
		t.Errorf("markers survived removal:\n%s", removed)
	}
	if strings.Contains(removed, "TrustedUserCAKeys") {
		t.Errorf("directive survived removal:\n%s", removed)
	}
	// Deprovision removes EXACTLY our block, leaving the rest intact.
	if !strings.Contains(removed, "administrators_authorized_keys") ||
		!strings.Contains(removed, "PasswordAuthentication yes") {
		t.Errorf("removal deleted unrelated content:\n%s", removed)
	}
	if strings.TrimSpace(removed) != strings.TrimSpace(stripLegacyIncludeLines(stockConfig)) {
		t.Errorf("remove(upsert(x)) did not restore x:\nwant:\n%q\ngot:\n%q", stockConfig, removed)
	}
	// Removing when absent is a no-op.
	if removeManagedBlock(stockConfig) != stockConfig {
		t.Errorf("removeManagedBlock mutated a config without a block")
	}
}

func TestHasManagedBlockBeforeMatchNegatives(t *testing.T) {
	if hasManagedBlockBeforeMatch(stockConfig) {
		t.Errorf("stock config wrongly reported as having the managed block")
	}
	// Block AFTER a Match is not effective.
	afterMatch := "Match Group administrators\n  AuthorizedKeysFile x\n" + testBlock()
	if hasManagedBlockBeforeMatch(afterMatch) {
		t.Errorf("managed block after Match wrongly reported effective:\n%s", afterMatch)
	}
}
