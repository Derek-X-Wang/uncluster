//go:build darwin

package gatekeeper

import (
	"context"
	"errors"
	"testing"
)

// TestBootstrapServiceDarwin_FirstInstall verifies that on a fresh install
// (bootstrap not yet in domain) the bootstrap call is made and its success
// is propagated.
func TestBootstrapServiceDarwin_FirstInstall(t *testing.T) {
	calls := 0
	// Inject a fake that succeeds (service not yet bootstrapped).
	old := darwinLaunchctlBootstrap
	darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
		calls++
		return nil
	}
	defer func() { darwinLaunchctlBootstrap = old }()

	if err := bootstrapServiceDarwin(context.Background()); err != nil {
		t.Fatalf("bootstrapServiceDarwin() unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected bootstrap to be called once, got %d", calls)
	}
}

// TestBootstrapServiceDarwin_AlreadyBootstrapped verifies idempotency: when
// launchctl bootstrap returns an "already bootstrapped" / EEXIST error (the
// real macOS exit-code-17 path), bootstrapServiceDarwin must treat it as
// success so re-running agent install does not error. This is the same
// isAlreadyInstalledErr posture used for plist installation.
func TestBootstrapServiceDarwin_AlreadyBootstrapped(t *testing.T) {
	old := darwinLaunchctlBootstrap
	darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
		// Simulate the "Bootstrap failed: 17" / "service already loaded" error
		// that launchctl emits when the job is already in the domain.
		return errors.New("Bootstrap failed: 17")
	}
	defer func() { darwinLaunchctlBootstrap = old }()

	if err := bootstrapServiceDarwin(context.Background()); err != nil {
		t.Fatalf("bootstrapServiceDarwin() must treat already-bootstrapped as success, got: %v", err)
	}
}

// TestBootstrapServiceDarwin_AlreadyBootstrapped_AltMessage verifies the
// "service already loaded" variant of the idempotency error is also accepted.
func TestBootstrapServiceDarwin_AlreadyBootstrapped_AltMessage(t *testing.T) {
	old := darwinLaunchctlBootstrap
	darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
		return errors.New("service already loaded")
	}
	defer func() { darwinLaunchctlBootstrap = old }()

	if err := bootstrapServiceDarwin(context.Background()); err != nil {
		t.Fatalf("bootstrapServiceDarwin() must treat 'already loaded' as success, got: %v", err)
	}
}

// TestBootstrapServiceDarwin_RealError verifies that genuine bootstrap failures
// (not the already-bootstrapped case) are propagated as errors so operators see
// a useful message rather than a silent no-op.
func TestBootstrapServiceDarwin_RealError(t *testing.T) {
	old := darwinLaunchctlBootstrap
	darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
		return errors.New("Bootstrap failed: 13: Permission denied")
	}
	defer func() { darwinLaunchctlBootstrap = old }()

	if err := bootstrapServiceDarwin(context.Background()); err == nil {
		t.Fatal("bootstrapServiceDarwin() must propagate a real (non-idempotency) bootstrap error")
	}
}

// TestStartServiceDarwin_KickstartVerbUsed verifies that startService on darwin
// uses the kickstart verb (domain-qualified: system/com.uncluster.agent) rather
// than the bare "launchctl start <label>" that requires a pre-loaded job (#99).
func TestStartServiceDarwin_KickstartVerbUsed(t *testing.T) {
	bootstrapCalls := 0
	kickstartCalls := 0

	oldBootstrap := darwinLaunchctlBootstrap
	darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
		bootstrapCalls++
		return nil
	}
	defer func() { darwinLaunchctlBootstrap = oldBootstrap }()

	oldKickstart := darwinLaunchctlKickstart
	darwinLaunchctlKickstart = func(ctx context.Context) error {
		kickstartCalls++
		return nil
	}
	defer func() { darwinLaunchctlKickstart = oldKickstart }()

	if err := startService(context.Background()); err != nil {
		t.Fatalf("startService() unexpected error: %v", err)
	}
	if bootstrapCalls != 1 {
		t.Errorf("expected bootstrapServiceDarwin to be called once, got %d", bootstrapCalls)
	}
	if kickstartCalls != 1 {
		t.Errorf("expected launchctl kickstart to be called once, got %d", kickstartCalls)
	}
}

// TestStopServiceForReinstall_DarwinBootoutFirst verifies the reinstall path
// calls bootout before removing the plist, so the job is fully unregistered
// from the system domain before kardianos/service Uninstall removes the plist.
func TestStopServiceForReinstall_DarwinBootoutFirst(t *testing.T) {
	bootoutCalled := false
	oldBootout := darwinLaunchctlBootout
	darwinLaunchctlBootout = func(ctx context.Context) error {
		bootoutCalled = true
		return nil
	}
	defer func() { darwinLaunchctlBootout = oldBootout }()

	_ = stopServiceForReinstall(context.Background())
	if !bootoutCalled {
		t.Error("stopServiceForReinstall on darwin must call bootout to remove the job from the system domain")
	}
}

// TestIsAlreadyBootstrappedErr covers the error-string predicate used by
// bootstrapServiceDarwin to detect the EEXIST/already-loaded case. The
// predicate must be tight enough not to swallow real errors.
func TestIsAlreadyBootstrappedErr(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"Bootstrap failed: 17", true},
		{"Bootstrap failed: 17: File exists", true},
		{"service already loaded", true},
		{"already bootstrapped", true},
		{"Bootstrap failed: 13: Permission denied", false},
		{"Bootstrap failed: 2: No such file or directory", false},
		{"exit status 3", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isAlreadyBootstrappedErr(errors.New(tc.msg))
		if got != tc.want {
			t.Errorf("isAlreadyBootstrappedErr(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}
