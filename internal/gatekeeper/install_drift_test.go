package gatekeeper

import (
	"strings"
	"testing"
)

// TestDetectServiceUnitDrift covers the substring-comparison logic that
// drives the re-install decision in installService (#50). The function
// inspects a service-unit file's content (systemd .service or launchd
// .plist) and reports drift in the executable path, service account, or
// command arguments. Returning "" means no drift; a non-empty string
// triggers Stop → Uninstall → Install in the caller.
func TestDetectServiceUnitDrift(t *testing.T) {
	const (
		intendedExe  = "/usr/local/bin/uncluster"
		intendedUser = "uncluster"
	)
	// Minimal systemd unit shape — enough for the substring checks.
	systemdUnit := `[Unit]
Description=Uncluster Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/uncluster agent run
User=uncluster
Restart=always

[Install]
WantedBy=multi-user.target
`
	// Minimal launchd plist shape — same substrings the function looks for.
	launchdPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC ...>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.uncluster.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/uncluster</string>
    <string>agent</string>
    <string>run</string>
  </array>
  <key>UserName</key>
  <string>uncluster</string>
</dict>
</plist>
`

	cases := []struct {
		name         string
		content      string
		intendedExe  string
		intendedUser string
		wantDrift    string // "" = no drift expected; substring match for non-empty
	}{
		{
			name:         "systemd: no drift",
			content:      systemdUnit,
			intendedExe:  intendedExe,
			intendedUser: intendedUser,
			wantDrift:    "",
		},
		{
			name:         "launchd: no drift",
			content:      launchdPlist,
			intendedExe:  intendedExe,
			intendedUser: intendedUser,
			wantDrift:    "",
		},
		{
			name:         "executable drift — operator moved binary",
			content:      systemdUnit,
			intendedExe:  "/opt/uncluster/bin/uncluster", // unit still references /usr/local/bin
			intendedUser: intendedUser,
			wantDrift:    "executable path drift",
		},
		{
			name:         "user drift — service account changed",
			content:      systemdUnit,
			intendedExe:  intendedExe,
			intendedUser: "uncluster-svc",
			wantDrift:    "user drift",
		},
		{
			name:         "argument drift — old unit missed 'run'",
			content:      strings.Replace(systemdUnit, "agent run", "agent serve", 1),
			intendedExe:  intendedExe,
			intendedUser: intendedUser,
			wantDrift:    "argument drift",
		},
		{
			name:         "blank user is not checked",
			content:      systemdUnit,
			intendedExe:  intendedExe,
			intendedUser: "",
			wantDrift:    "",
		},
		{
			name:         "executable drift on launchd",
			content:      launchdPlist,
			intendedExe:  "/opt/uncluster/bin/uncluster",
			intendedUser: intendedUser,
			wantDrift:    "executable path drift",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectServiceUnitDrift(tc.content, tc.intendedExe, tc.intendedUser)
			if tc.wantDrift == "" {
				if got != "" {
					t.Errorf("expected no drift, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantDrift) {
				t.Errorf("drift = %q, want substring %q", got, tc.wantDrift)
			}
		})
	}
}
