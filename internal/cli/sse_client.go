package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SSEEvent is a single parsed Server-Sent Event frame.
type SSEEvent struct {
	Kind string
	Data []byte
}

// StreamSSE opens an SSE stream at path and calls onEvent for each complete
// event frame. It returns when the stream is closed by the server, the context
// is cancelled, or onEvent returns io.EOF (used by callers to exit early after
// receiving a terminal event).
//
// A dedicated http.Client with Timeout=0 is used so the connection is never
// killed by a read deadline during long-running streams.
func (c *Client) StreamSSE(ctx context.Context, path string, onEvent func(SSEEvent) error) error {
	streamClient := &http.Client{Timeout: 0}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("sse request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := streamClient.Do(req)
	if err != nil {
		return fmt.Errorf("sse connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// Parse SSE frames: each frame is a sequence of "field: value\n" lines
	// terminated by a blank line "\n".
	rd := bufio.NewReader(resp.Body)
	var kind, data string

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("sse read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case line == "":
			// Blank line = end of frame. Dispatch if we have a data field.
			if data != "" {
				ev := SSEEvent{Kind: kind, Data: []byte(data)}
				if callErr := onEvent(ev); callErr != nil {
					if callErr == io.EOF {
						return nil
					}
					return callErr
				}
			}
			// Reset for next frame.
			kind = ""
			data = ""

		case strings.HasPrefix(line, "event:"):
			kind = strings.TrimSpace(strings.TrimPrefix(line, "event:"))

		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
}
