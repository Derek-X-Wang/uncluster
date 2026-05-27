// Package harness drives the Uncluster Compose-based E2E stack. It exposes
// a small set of helpers that the test suites in test/e2e/ use to bootstrap
// the stack, mint tokens, request certs, and collect artifacts on failure.
//
// The helpers are deliberately HTTP-shaped (Endpoint, Caller token) rather
// than Compose-shaped: each helper can be unit-tested against an
// httptest.Server before being wired to a live stack. See helpers_test.go.
package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the slim HTTP client the helpers use against the Control plane.
// It is independent of internal/cli to keep test/e2e isolated from the
// production CLI wiring (so a CLI refactor cannot silently break E2E).
type Client struct {
	BaseURL string
	Token   string // bearer; empty when calling endpoints that don't require auth (/healthz, /v1/agents/register)
	HTTP    *http.Client
}

// NewClient returns a Client with a 10s default timeout. Tests can override
// HTTP to swap in an httptest-bound transport.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Do issues an HTTP request and unmarshals the JSON response body into `out`.
// `path` must not contain a `?` (use doRaw for paths that carry a query
// string — Do percent-encodes any `?` via url.JoinPath which breaks query
// dispatch). Returns a typed HTTPError on non-2xx for assertion ergonomics.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	u, err := url.JoinPath(c.BaseURL, path)
	if err != nil {
		return fmt.Errorf("join url: %w", err)
	}
	return c.execute(ctx, method, u, body, out)
}

// doRaw is the query-string-aware variant of Do: it concatenates the path
// directly so the query separator `?` is not percent-encoded. Used by
// helpers that pass through a built query string.
func (c *Client) doRaw(ctx context.Context, method, pathWithQuery string, body any, out any) error {
	return c.execute(ctx, method, c.BaseURL+pathWithQuery, body, out)
}

func (c *Client) execute(ctx context.Context, method, fullURL string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Status: resp.StatusCode, Body: string(respBody)}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("unmarshal response (status=%d, body=%s): %w", resp.StatusCode, respBody, err)
	}
	return nil
}

// HTTPError is returned by Client.Do on non-2xx so tests can assert on the
// wire status without parsing prose.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("http %d: %s", e.Status, e.Body)
}

// WaitForHealthz polls GET /healthz until 200 or deadline expires.
// Returns the wall-clock elapsed time so the caller can log boot duration.
func WaitForHealthz(ctx context.Context, baseURL string, deadline time.Duration) (time.Duration, error) {
	c := NewClient(baseURL, "")
	c.HTTP.Timeout = 2 * time.Second
	start := time.Now()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	to := time.NewTimer(deadline)
	defer to.Stop()
	for {
		var resp struct {
			OK      bool   `json:"ok"`
			Version string `json:"version"`
		}
		err := c.Do(ctx, "GET", "/healthz", nil, &resp)
		if err == nil && resp.OK {
			return time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-to.C:
			return time.Since(start), fmt.Errorf("healthz never returned ok after %s: last err=%v", deadline, err)
		case <-tick.C:
		}
	}
}
