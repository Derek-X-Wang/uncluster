package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newSSHCmd() *cobra.Command {
	var asUser, subnet string

	cmd := &cobra.Command{
		Use:   "ssh <agent> [-- <ssh args>...]",
		Short: "SSH to an agent via a short-lived certificate",
		Long: `Resolves the agent, picks the best endpoint, requests a short-lived
SSH certificate from the control plane, and execs ssh. Exit code is propagated.

The caller token and SSH key path are read from the CLI config
(~/.config/uncluster/cli.toml). Set them with:
  uncluster config set server=URL
  uncluster config set token --stdin
  uncluster config set ssh_key_path=~/.ssh/id_ed25519
`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			agentArg := args[0]
			var extraSSHArgs []string
			// Remaining args after "--" are passed to ssh.
			for i, a := range args[1:] {
				if a == "--" {
					extraSSHArgs = args[i+2:]
					break
				}
				// No "--" found; pass them all to ssh.
				if i == len(args)-2 {
					extraSSHArgs = args[1:]
				}
			}

			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}

			sshKeyPath := cfg.SSHKeyPath
			if sshKeyPath == "" {
				home, _ := os.UserHomeDir()
				sshKeyPath = filepath.Join(home, ".ssh", "id_ed25519")
			}
			sshKeyPath = expandHome(sshKeyPath)

			principal := cfg.SSHPrincipal
			if asUser != "" {
				principal = asUser
			}
			if principal == "" {
				principal = os.Getenv("USER")
				if principal == "" {
					return fmt.Errorf("no username; set --as <user> or ssh_principal_default in config")
				}
			}

			client := NewClient(cfg.Server, cfg.Token)

			// 1. Resolve agent.
			var agent api.AgentDetail
			if err := client.Do(cmd.Context(), "GET", "/v1/agents/"+agentArg, nil, &agent); err != nil {
				return fmt.Errorf("resolve agent: %w", err)
			}

			// 2. Pick endpoint.
			address, err := pickEndpoint(agent.Endpoints, subnet, cfg.Subnets)
			if err != nil {
				return err
			}

			// 3. Read user public key.
			pubkeyPath := sshKeyPath + ".pub"
			pubkeyBytes, err := os.ReadFile(pubkeyPath)
			if err != nil {
				return fmt.Errorf("read public key %s: %w", pubkeyPath, err)
			}

			// 4. Request cert from control plane.
			var certResp api.CertResponse
			if err := client.Do(cmd.Context(), "POST", "/v1/certs", api.CertRequest{
				Agent:    agent.ID,
				Username: principal,
				Pubkey:   strings.TrimSpace(string(pubkeyBytes)),
			}, &certResp); err != nil {
				return fmt.Errorf("cert request: %w", err)
			}

			// 5. Write cert to temp file.
			certDir := certTempDir()
			if err := os.MkdirAll(certDir, 0o700); err != nil {
				return fmt.Errorf("cert dir: %w", err)
			}
			certPath := filepath.Join(certDir, "cert-"+randomHex(8)+"-cert.pub")
			if err := os.WriteFile(certPath, []byte(certResp.Certificate), 0o600); err != nil {
				return fmt.Errorf("write cert: %w", err)
			}
			defer os.Remove(certPath) //nolint:errcheck

			// 6. Exec ssh.
			sshArgs := []string{
				"-i", sshKeyPath,
				"-o", "CertificateFile=" + certPath,
				"-o", "IdentitiesOnly=yes",
				principal + "@" + address,
			}
			sshArgs = append(sshArgs, extraSSHArgs...)

			sshBin, err := exec.LookPath("ssh")
			if err != nil {
				return fmt.Errorf("ssh not found in PATH: %w", err)
			}
			sshCmd := exec.Command(sshBin, sshArgs...)
			sshCmd.Stdin = os.Stdin
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&asUser, "as", "", "SSH username (overrides config ssh_principal_default)")
	cmd.Flags().StringVar(&subnet, "subnet", "", "subnet name to use for endpoint selection")
	return cmd
}

// pickEndpoint selects the best endpoint address from a list.
//
// Priority: explicit --subnet flag > first endpoint whose subnet appears in
// callerSubnets > first endpoint overall. Returns an error with a listing
// if no endpoints are found.
func pickEndpoint(endpoints []api.AgentEndpointSummary, explicit string, callerSubnets []string) (string, error) {
	if len(endpoints) == 0 {
		return "", fmt.Errorf("agent has no endpoints registered; check that the agent is running and has reported its address")
	}
	if explicit != "" {
		for _, e := range endpoints {
			if e.Subnet == explicit {
				return e.Address, nil
			}
		}
		names := endpointNames(endpoints)
		return "", fmt.Errorf("no endpoint for subnet %q; available: %s", explicit, strings.Join(names, ", "))
	}
	// First overlap with caller's declared subnets.
	if len(callerSubnets) > 0 {
		subnetSet := map[string]struct{}{}
		for _, s := range callerSubnets {
			subnetSet[s] = struct{}{}
		}
		for _, e := range endpoints {
			if _, ok := subnetSet[e.Subnet]; ok {
				return e.Address, nil
			}
		}
	}
	// Fall back to first endpoint.
	return endpoints[0].Address, nil
}

func endpointNames(endpoints []api.AgentEndpointSummary) []string {
	names := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		names = append(names, e.Subnet)
	}
	return names
}

func certTempDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "uncluster")
	}
	return filepath.Join(os.TempDir(), "uncluster-certs")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}
