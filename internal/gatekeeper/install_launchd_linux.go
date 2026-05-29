//go:build !darwin && !windows

package gatekeeper

import "context"

// The following stubs satisfy the compiler on non-darwin Unix (Linux). The
// real implementations live in install_launchd_darwin.go (darwin build tag).
// They are referenced only from the darwin switch-arm in install_unix.go, so
// they are never called at runtime on Linux; the stubs exist solely so that
// `GOOS=linux go build ./...` succeeds.

var darwinLaunchctlBootstrap = func(_ context.Context, _ string) error { return nil }
var darwinLaunchctlKickstart = func(_ context.Context) error { return nil }
var darwinLaunchctlBootout = func(_ context.Context) error { return nil }

func bootstrapServiceDarwin(_ context.Context) error { return nil }

func isAlreadyBootstrappedErr(_ error) bool { return false }
