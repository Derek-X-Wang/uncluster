package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newRunCmd() *cobra.Command {
	var async bool

	cmd := &cobra.Command{
		Use:   "run <node> -- <cmd>...",
		Short: "Run a command on a node and stream its output",
		Long: `Run a shell command on a registered agent node.
The node name or ID comes before '--'; everything after '--' is the command.

Example:
  uncluster run my-mac -- ls -la /tmp`,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			// args[0] is the node; args[1:] is the command (cobra consumes '--').
			node := args[0]
			rest := args[1:]
			if len(rest) == 0 {
				return fmt.Errorf("command is required after '--'")
			}
			command := strings.Join(rest, " ")

			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}

			client := NewClient(cfg.Server, cfg.Token)

			var out api.CreateTaskResponse
			if err := client.Do(cmd.Context(), "POST", "/v1/tasks",
				api.CreateTaskRequest{Node: node, Command: command}, &out); err != nil {
				return fmt.Errorf("create task: %w", err)
			}

			taskID := out.TaskID
			fmt.Fprintf(os.Stderr, "[%s on %s]\n", taskID, node)

			if async {
				fmt.Fprintln(cmd.OutOrStdout(), taskID)
				return nil
			}

			runCtx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			go func() {
				<-runCtx.Done()
				// Best-effort: cancel the remote task with a short timeout so the CLI doesn't hang.
				ctxCancel, cancelCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancelCancel()
				_ = client.Do(ctxCancel, "POST", "/v1/tasks/"+taskID+"/cancel", nil, nil)
			}()

			return tailTask(runCtx, client, taskID)

		},
	}

	cmd.Flags().BoolVar(&async, "async", false, "print task ID and return without streaming output")
	return cmd
}

// tailTask streams the output of taskID to stdout/stderr and propagates the
// command's exit code via os.Exit when non-zero.
func tailTask(ctx context.Context, client *Client, taskID string) error {
	var finalExit *int

	type chunkPayload struct {
		Stream string `json:"stream"`
		Data   []byte `json:"data"`
	}
	type donePayload struct {
		ExitCode *int   `json:"exit_code"`
		Status   string `json:"status"`
	}

	err := client.StreamSSE(ctx, "/v1/tasks/"+taskID+"/stream", func(ev SSEEvent) error {
		switch ev.Kind {
		case "chunk":
			var p chunkPayload
			if jsonErr := json.Unmarshal(ev.Data, &p); jsonErr != nil {
				return nil // skip malformed chunk
			}
			switch p.Stream {
			case "stderr":
				os.Stderr.Write(p.Data)
			default: // stdout or unspecified
				os.Stdout.Write(p.Data)
			}

		case "done":
			var p donePayload
			if jsonErr := json.Unmarshal(ev.Data, &p); jsonErr == nil {
				finalExit = p.ExitCode
			}
			return io.EOF // signal the SSE loop to exit cleanly
		}
		return nil
	})

	if err != nil {
		return err
	}

	if finalExit != nil && *finalExit != 0 {
		os.Exit(*finalExit)
	}
	return nil
}
