//go:build !windows

package gatekeeper

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPayloadDirResult(t *testing.T) {
	const dir = "/var/lib/uncluster"
	good := payloadDirFacts{
		isDir: true, perm: 0o755,
		uid: 1000, wantUID: 1000, ownerKnown: true,
		noexec: false, noexecKnown: true,
	}

	cases := []struct {
		name    string
		facts   payloadDirFacts
		want    CheckStatus
		wantMsg string
	}{
		{"all good", good, CheckOK, "present"},
		{"missing is warn", payloadDirFacts{statErr: os.ErrNotExist}, CheckWarn, "missing"},
		{"stat error is fail", payloadDirFacts{statErr: errors.New("io boom")}, CheckFail, "cannot stat"},
		{"symlink is fail", func() payloadDirFacts { f := good; f.isSymlink = true; return f }(), CheckFail, "symlink"},
		{"not a dir is fail", func() payloadDirFacts { f := good; f.isDir = false; return f }(), CheckFail, "not a directory"},
		{"world-writable is fail", func() payloadDirFacts { f := good; f.perm = 0o757; return f }(), CheckFail, "world-writable"},
		{"wrong owner is fail", func() payloadDirFacts { f := good; f.uid = 0; return f }(), CheckFail, "owned by uid"},
		{"noexec is fail", func() payloadDirFacts { f := good; f.noexec = true; return f }(), CheckFail, "noexec"},
		{"owner unknown is not graded", func() payloadDirFacts { f := good; f.uid = 0; f.ownerKnown = false; return f }(), CheckOK, "present"},
		{"noexec unknown is not graded", func() payloadDirFacts { f := good; f.noexec = true; f.noexecKnown = false; return f }(), CheckOK, "present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := payloadDirResult(dir, tc.facts)
			if got.Status != tc.want {
				t.Errorf("status = %v, want %v (msg=%q)", got.Status, tc.want, got.Message)
			}
			if tc.wantMsg != "" && !strings.Contains(got.Message, tc.wantMsg) {
				t.Errorf("message %q missing substring %q", got.Message, tc.wantMsg)
			}
			if got.Name != payloadDirCheckName {
				t.Errorf("name = %q, want %q", got.Name, payloadDirCheckName)
			}
		})
	}
}
