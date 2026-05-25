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
			fmt.Fprintf(cmd.OutOrStdout(), "server = %q\n", cfg.Server)
			if cfg.Token != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "token  = %q\n", "uct_***_"+truncID(cfg.Token))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "token  = (unset)")
			}
			return nil
		},
	})

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

func truncID(full string) string {
	// uct_<kind>_<id>_<secret>: keep only id tail chars.
	parts := strings.Split(full, "_")
	if len(parts) >= 3 && len(parts[2]) >= 4 {
		return parts[2][len(parts[2])-4:]
	}
	return "****"
}
