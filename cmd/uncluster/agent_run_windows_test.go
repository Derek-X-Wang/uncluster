//go:build windows

package main

import "testing"

func TestArgvIsAgentRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{
			name: "exact agent run",
			argv: []string{"uncluster.exe", "agent", "run"},
			want: true,
		},
		{
			name: "agent run with extra args",
			argv: []string{"uncluster.exe", "agent", "run", "--foo"},
			want: true,
		},
		{
			name: "agent doctor — should not route through SCM",
			argv: []string{"uncluster.exe", "agent", "doctor"},
			want: false,
		},
		{
			name: "server bootstrap — should not route through SCM",
			argv: []string{"uncluster.exe", "server", "bootstrap"},
			want: false,
		},
		{
			name: "too few args",
			argv: []string{"uncluster.exe"},
			want: false,
		},
		{
			name: "too few args 2",
			argv: []string{"uncluster.exe", "agent"},
			want: false,
		},
		{
			name: "empty",
			argv: nil,
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := argvIsAgentRun(tt.argv); got != tt.want {
				t.Errorf("argvIsAgentRun(%v) = %v, want %v", tt.argv, got, tt.want)
			}
		})
	}
}
