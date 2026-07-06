package gatekeeper

import "strings"

// Windows sshd base-config management (#179).
//
// On Windows the running OpenSSH service does NOT honour `sshd_config.d`
// Includes (empirically: `sshd -T` does not even expand them, and a service
// connection with the drop-in Included still rejects the cert — verified on
// OpenSSH_for_Windows_9.5p2, PR #174). So the CA-trust + principals directives
// must be written DIRECTLY into the base `sshd_config`, before the first `Match`
// block, to take effect. A base-config directive IS honoured (the base config is
// SYSTEM/TrustedInstaller-owned and directly parsed).
//
// The block is delimited by these markers so all three consumers operate on the
// exact same shape from one source of truth (#145 paths pattern): the installer
// upserts it, deprovision removes exactly it, and doctor asserts it. Never
// hand-copy these literals.
const (
	managedBlockBegin = "# >>> uncluster (managed) — do not edit this block >>>"
	managedBlockEnd   = "# <<< uncluster (managed) <<<"
)

// legacyIncludeMarker / the Include line shape are the pre-#179 drop-in+Include
// edits we self-heal away from on re-install (they never worked on Windows).
const legacyIncludeMarker = "# Added by uncluster agent install"

// managedDirectiveBlock renders the marker-delimited block carrying the CA-trust
// + principals directives. The directive lines are identical to the Unix drop-in
// (sshdDropInContent) — one source of truth for the directives themselves.
func managedDirectiveBlock(caPubkeyPath, principalsPattern string) string {
	return managedBlockBegin + "\n" +
		sshdDropInContent(caPubkeyPath, principalsPattern) +
		managedBlockEnd + "\n"
}

// firstMatchOffset returns the byte offset of the start of the first line whose
// first token is `Match` (case-insensitive), or -1 if none. sshd Match blocks
// extend to the next Match or EOF, so global directives must precede the first.
func firstMatchOffset(content string) int {
	off := 0
	for _, line := range strings.SplitAfter(content, "\n") {
		if f := strings.Fields(strings.TrimSpace(line)); len(f) > 0 && strings.EqualFold(f[0], "Match") {
			return off
		}
		off += len(line)
	}
	return -1
}

// insertBeforeFirstMatch inserts block (which ends in a newline) immediately
// before the first `Match` line, else appends at EOF — both global scope.
func insertBeforeFirstMatch(content, block string) string {
	if i := firstMatchOffset(content); i >= 0 {
		return content[:i] + block + content[i:]
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + block
}

// removeManagedBlock deletes the marker-delimited managed block (inclusive of
// both markers and one trailing newline) if present. Safe when absent.
func removeManagedBlock(content string) string {
	b := strings.Index(content, managedBlockBegin)
	if b < 0 {
		return content
	}
	rel := strings.Index(content[b:], managedBlockEnd)
	if rel < 0 {
		// Corrupt block (begin without end): drop from the marker to EOF.
		return content[:b]
	}
	e := b + rel + len(managedBlockEnd)
	if e < len(content) && content[e] == '\n' {
		e++
	}
	return content[:b] + content[e:]
}

// stripLegacyIncludeLines removes any drop-in Include line (and an adjacent
// legacy marker comment) — self-heal from the #126/#177 drop-in+Include shapes,
// which the Windows service ignores anyway.
func stripLegacyIncludeLines(content string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.EqualFold(t, legacyIncludeMarker) {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Include") &&
			strings.Contains(strings.ToLower(strings.ReplaceAll(t, `\`, "/")), "sshd_config.d") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// upsertManagedBlock returns content with the managed block present exactly once
// and global (before the first Match). Any prior managed block AND any legacy
// drop-in Include line are removed first, so re-install self-heals from every
// earlier shape (post-Match Include, pre-Match Include, prior managed block) and
// stays idempotent.
func upsertManagedBlock(content, block string) string {
	content = removeManagedBlock(content)
	content = stripLegacyIncludeLines(content)
	return insertBeforeFirstMatch(content, block)
}

// hasManagedBlockBeforeMatch reports whether the managed block is present AND
// starts before the first Match line, i.e. its directives are effective
// globally. This is the doctor health signal (directives EFFECTIVE), replacing
// the pre-#179 "drop-in file present + Include global" check.
func hasManagedBlockBeforeMatch(content string) bool {
	b := strings.Index(content, managedBlockBegin)
	if b < 0 || !strings.Contains(content, managedBlockEnd) {
		return false
	}
	if m := firstMatchOffset(content); m >= 0 {
		return b < m
	}
	return true
}
