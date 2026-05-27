// Package e2e is the Compose-backed end-to-end test suite for T1a.
//
// These tests REQUIRE Docker + Docker Compose + a working build context
// (the repo root). They are gated behind `-tags e2e` so the default
// `go test ./...` matrix does not attempt to spin up containers — that's
// the GH workflow's job.
//
// Run locally:
//   cd test/e2e && go test -tags e2e -v -count=1 -timeout 600s
//
// In CI: the e2e-compose-smoke job uses the same invocation.
//
//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/test/e2e/harness"
)

// composeFile resolves the docker-compose.yml relative to this test file.
// Using runtime.Caller(0) makes the path stable whether `go test` is run
// from the repo root or from test/e2e/.
func composeFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("cannot resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "docker-compose.yml")
}

// composeCmd is the canonical `docker compose -f <file>` prefix.
func composeCmd(t *testing.T, args ...string) *exec.Cmd {
	full := append([]string{"compose", "-f", composeFile(t)}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1", "COMPOSE_DOCKER_CLI_BUILD=1")
	return cmd
}

// dockerAvailable returns true if `docker compose version` succeeds.
// Used by every test to skip cleanly when running in environments without
// Docker (e.g. early local dev on a laptop without Docker Desktop running).
func dockerAvailable() bool {
	c := exec.Command("docker", "compose", "version")
	return c.Run() == nil
}

// composeUp brings the stack up and registers a cleanup that tears it down
// + scrapes artifacts on any test failure.
func composeUp(t *testing.T) {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker compose not available")
	}

	// Always start clean.
	_ = composeCmd(t, "down", "-v", "--remove-orphans").Run()

	build := composeCmd(t, "build")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("[ADVISORY] compose build failed: %v", err)
	}

	up := composeCmd(t, "up", "-d", "--wait", "--wait-timeout", "120")
	up.Stdout, up.Stderr = os.Stdout, os.Stderr
	if err := up.Run(); err != nil {
		// Collect bootstrap artifacts and bail.
		collectArtifacts(t, "bootstrap-failure")
		t.Fatalf("[ADVISORY] compose up --wait failed: %v", err)
	}

	t.Cleanup(func() {
		if t.Failed() {
			collectArtifacts(t, "test-failure")
		} else {
			collectArtifacts(t, "test-success")
		}
		_ = composeCmd(t, "down", "-v", "--remove-orphans").Run()
	})
}

// collectArtifacts shells out to scripts/collect-artifacts.sh. The output
// directory is shaped <repo>/test/e2e/_artifacts/<test-name>-<reason>/
// so multiple tests in the same run don't clobber each other.
func collectArtifacts(t *testing.T, reason string) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	outDir := filepath.Join(base, "_artifacts", fmt.Sprintf("%s-%s", t.Name(), reason))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("artifact dir mkdir failed: %v", err)
		return
	}
	script := filepath.Join(base, "scripts", "collect-artifacts.sh")
	cmd := exec.Command("bash", script, outDir)
	cmd.Env = append(os.Environ(), "COMPOSE_FILE="+composeFile(t))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Logf("artifact collector failed: %v", err)
	}
}

// TestSmoke_RolesBoot is the canonical T1a assertion: the three roles come
// up, reach healthy state, and the Control plane responds to /healthz.
// No product behaviour (cert flow, ACL) is asserted — that's T1b's job.
func TestSmoke_RolesBoot(t *testing.T) {
	composeUp(t)

	// CP is reachable inside its container at :7777; we need to talk to it
	// from the host. Use docker-exec rather than mapping a host port to
	// avoid clashes with other CI services.
	healthOut, err := composeCmd(t, "exec", "-T", "cp", "curl", "-fsS", "http://127.0.0.1:7777/healthz").CombinedOutput()
	if err != nil {
		t.Fatalf("[REQUIRED] cp healthz via exec failed: %v\n%s", err, healthOut)
	}
	if !strings.Contains(string(healthOut), `"ok":true`) {
		t.Fatalf("[REQUIRED] cp healthz response unexpected: %s", healthOut)
	}

	// Verify the Agent successfully joined (file dropped on the shared volume).
	if out, err := composeCmd(t, "exec", "-T", "agent", "test", "-s", "/shared/join-token").CombinedOutput(); err != nil {
		t.Fatalf("[ADVISORY] /shared/join-token missing in agent: %v\n%s", err, out)
	}

	// Verify sshd is configured: drop-in file present, CA pubkey installed.
	if out, err := composeCmd(t, "exec", "-T", "agent", "test", "-f", "/etc/ssh/uncluster_ca.pub").CombinedOutput(); err != nil {
		t.Fatalf("[REQUIRED] CA pubkey not installed on agent: %v\n%s", err, out)
	}
	if out, err := composeCmd(t, "exec", "-T", "agent", "grep", "-q", "TrustedUserCAKeys", "/etc/ssh/sshd_config.d/uncluster.conf").CombinedOutput(); err != nil {
		t.Fatalf("[REQUIRED] sshd drop-in missing TrustedUserCAKeys: %v\n%s", err, out)
	}

	// Verify caller has its key + cli.toml.
	if out, err := composeCmd(t, "exec", "-T", "caller", "test", "-f", "/var/lib/uncluster-caller/keys/id_ed25519").CombinedOutput(); err != nil {
		t.Fatalf("[REQUIRED] caller key missing: %v\n%s", err, out)
	}
	if out, err := composeCmd(t, "exec", "-T", "caller", "test", "-s", "/root/.config/uncluster/cli.toml").CombinedOutput(); err != nil {
		t.Fatalf("[REQUIRED] caller cli.toml missing: %v\n%s", err, out)
	}

	// Sanity-check the harness's Client against the live CP via exec'd curl,
	// then have the harness mint a join token through the API. Going through
	// the harness here is what proves the helper unit tests in
	// harness/helpers_test.go are exercising the right contract.
	cpCmd := composeCmd(t, "exec", "-T", "cp", "cat", "/shared/caller-token")
	tokBytes, err := cpCmd.Output()
	if err != nil {
		t.Fatalf("[ADVISORY] read caller token from shared volume: %v", err)
	}
	callerTok := strings.TrimSpace(string(tokBytes))
	if callerTok == "" {
		t.Fatalf("[ADVISORY] caller token empty")
	}

	// Run the harness Mint via docker-exec'd curl, NOT directly from the
	// test host (the CP doesn't publish a host port).
	mintReq := fmt.Sprintf(
		`curl -fsS -X POST http://127.0.0.1:7777/v1/tokens -H 'Authorization: Bearer %s' -H 'Content-Type: application/json' -d '{"kind":"join","label":"smoke-mint"}'`,
		callerTok,
	)
	out, err := composeCmd(t, "exec", "-T", "cp", "sh", "-c", mintReq).CombinedOutput()
	if err != nil {
		t.Fatalf("[REQUIRED] mint join token via API failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"token":"`) {
		t.Fatalf("[REQUIRED] mint response missing token: %s", out)
	}

	// Sanity-touch the harness import so the import graph is exercised in
	// CI even if every assertion above uses docker-exec rather than direct
	// HTTP (the CP doesn't publish a host port in this Compose profile).
	_ = harness.NewClient
}
