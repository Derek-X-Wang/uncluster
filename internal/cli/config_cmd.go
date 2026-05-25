package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
)

// promptLine prints prompt and reads a single line from stdin. If defaultVal
// is non-empty, shows it and returns it when user presses Enter.
func promptLine(prompt, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

type CLIConfig struct {
	Server string `toml:"server"`
	Token  string `toml:"token"`

	// V2 SSH config fields (S4).
	SSHKeyPath      string   `toml:"ssh_key_path,omitempty"`
	SSHPrincipal    string   `toml:"ssh_principal_default,omitempty"`
	Subnets         []string `toml:"subnets,omitempty"`
}

func cliConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "uncluster", "cli.toml"), nil
}

func LoadCLIConfig() (CLIConfig, error) {
	var cfg CLIConfig
	p, err := cliConfigPath()
	if err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	_, err = toml.Decode(string(b), &cfg)
	return cfg, err
}

func SaveCLIConfig(cfg CLIConfig) error {
	p, err := cliConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Read / write ~/.config/uncluster/cli.toml"}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the CLI config (token is masked)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "server            = %q\n", cfg.Server)
			if cfg.Token != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "token             = %q\n", "uct_***_"+truncID(cfg.Token))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "token             = (unset)")
			}
			if cfg.SSHKeyPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "ssh_key_path      = %q\n", cfg.SSHKeyPath)
			}
			if cfg.SSHPrincipal != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "ssh_principal     = %q\n", cfg.SSHPrincipal)
			}
			if len(cfg.Subnets) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "subnets           = %v\n", cfg.Subnets)
			}
			return nil
		},
	})
	cmd.AddCommand(newConfigInitCmd())

	var setStdin bool
	set := &cobra.Command{
		Use:   "set [key=value]",
		Short: "Set a config value. Use --stdin for secrets (token).",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			if setStdin {
				rd := bufio.NewReader(os.Stdin)
				line, err := rd.ReadString('\n')
				if err != nil && err != io.EOF {
					return err
				}
				cfg.Token = strings.TrimSpace(line)
			}
			for _, kv := range args {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("bad argument %q; want key=value", kv)
				}
				switch parts[0] {
				case "server":
					cfg.Server = parts[1]
				case "token":
					return fmt.Errorf("refusing to read 'token' from argv; use `config set token --stdin`")
				case "ssh_key_path":
					cfg.SSHKeyPath = parts[1]
				case "ssh_principal_default":
					cfg.SSHPrincipal = parts[1]
				case "subnets":
					if parts[1] == "" {
						cfg.Subnets = nil
					} else {
						cfg.Subnets = strings.Split(parts[1], ",")
					}
				default:
					return fmt.Errorf("unknown key %q", parts[0])
				}
			}
			return SaveCLIConfig(cfg)
		},
	}
	set.Flags().BoolVar(&setStdin, "stdin", false, "read the token from stdin (first line)")
	cmd.AddCommand(set)
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive setup wizard for ~/.config/uncluster/cli.toml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load existing config as defaults.
			cfg, _ := LoadCLIConfig()

			fmt.Fprintln(cmd.OutOrStdout(), "Uncluster CLI setup — press Enter to keep the default.")
			fmt.Fprintln(cmd.OutOrStdout())

			// Server URL.
			serverURL, err := promptLine("Control plane URL (e.g. https://uncluster.example.com:7777)", cfg.Server)
			if err != nil {
				return err
			}
			if serverURL == "" {
				return fmt.Errorf("server URL is required")
			}
			cfg.Server = serverURL

			// Caller token — never from argv.
			fmt.Print("Caller token (paste, then Enter): ")
			rd := bufio.NewReader(os.Stdin)
			line, err := rd.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			tok := strings.TrimSpace(line)
			if tok == "" {
				return fmt.Errorf("token is required")
			}
			cfg.Token = tok

			// SSH key path.
			home, _ := os.UserHomeDir()
			defaultKey := filepath.Join(home, ".ssh", "id_ed25519")
			if cfg.SSHKeyPath != "" {
				defaultKey = cfg.SSHKeyPath
			}
			keyPath, err := promptLine("SSH private key path", defaultKey)
			if err != nil {
				return err
			}
			expanded := expandHome(keyPath)
			if _, statErr := os.Stat(expanded); os.IsNotExist(statErr) {
				fmt.Fprintf(cmd.OutOrStdout(), "Warning: key %q does not exist. Create it with: ssh-keygen -t ed25519 -f %q\n", expanded, expanded)
			}
			cfg.SSHKeyPath = keyPath

			// Default SSH principal.
			defaultPrincipal := os.Getenv("USER")
			if cfg.SSHPrincipal != "" {
				defaultPrincipal = cfg.SSHPrincipal
			}
			principal, err := promptLine("Default SSH username (principal)", defaultPrincipal)
			if err != nil {
				return err
			}
			cfg.SSHPrincipal = principal

			// Subnets.
			defaultSubnets := strings.Join(cfg.Subnets, ",")
			subnetsStr, err := promptLine("Advertised subnets (comma-separated, or leave empty)", defaultSubnets)
			if err != nil {
				return err
			}
			if subnetsStr == "" {
				cfg.Subnets = nil
			} else {
				cfg.Subnets = strings.Split(subnetsStr, ",")
				for i := range cfg.Subnets {
					cfg.Subnets[i] = strings.TrimSpace(cfg.Subnets[i])
				}
			}

			if err := SaveCLIConfig(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			p, _ := cliConfigPath()
			fmt.Fprintf(cmd.OutOrStdout(), "\nConfig saved to %s\n", p)
			fmt.Fprintln(cmd.OutOrStdout(), "Run `uncluster agents ls` to see registered agents.")
			return nil
		},
	}
}

func truncID(full string) string {
	// uct_<kind>_<id>_<secret>: keep only id tail chars.
	parts := strings.Split(full, "_")
	if len(parts) >= 3 && len(parts[2]) >= 4 {
		return parts[2][len(parts[2])-4:]
	}
	return "****"
}
