package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadSecretToken returns a token read from one of:
//   - --token-stdin flag: reads the first line of os.Stdin
//   - UNCLUSTER_TOKEN env var (only if --token-stdin was not set)
// Returns an error if both are absent or if a bare --token=... flag is passed.
func ReadSecretToken(tokenStdin bool) (string, error) {
	if tokenStdin {
		rd := bufio.NewReader(os.Stdin)
		line, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return "", fmt.Errorf("empty token on stdin")
		}
		return line, nil
	}
	if v, ok := os.LookupEnv("UNCLUSTER_TOKEN"); ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no token provided; use --token-stdin or set UNCLUSTER_TOKEN (never --token=<value>)")
}
