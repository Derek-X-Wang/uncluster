package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

type ServerClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewServerClient(baseURL, tok string) *ServerClient {
	return &ServerClient{
		BaseURL: baseURL,
		Token:   tok,
		// Long enough for the 30s long-poll + headroom.
		HTTP: &http.Client{Timeout: 45 * time.Second},
	}
}

var (
	ErrUnauthorized = errors.New("agent: unauthorized")
	ErrRevoked      = errors.New("agent: revoked by control plane")
)

func (c *ServerClient) do(ctx context.Context, method, path string, in any, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		return nil, ErrUnauthorized
	}
	if resp.StatusCode == http.StatusGone {
		_ = resp.Body.Close()
		return nil, ErrRevoked
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return nil, err
		}
	}
	return resp, nil
}

func (c *ServerClient) Register(ctx context.Context, req api.AgentRegisterRequest) (api.AgentRegisterResponse, error) {
	var out api.AgentRegisterResponse
	_, err := c.do(ctx, "POST", "/v1/agent/register", req, &out)
	return out, err
}

func (c *ServerClient) HeartbeatV2(ctx context.Context, req api.V2HeartbeatRequest) (api.V2HeartbeatResponse, error) {
	var out api.V2HeartbeatResponse
	_, err := c.do(ctx, "POST", "/v1/agent/heartbeat", req, &out)
	return out, err
}

func (c *ServerClient) GetUpdatePlan(ctx context.Context) (api.UpdatePlanResponse, error) {
	var out api.UpdatePlanResponse
	_, err := c.do(ctx, "GET", "/v1/agent/update-plan", nil, &out)
	return out, err
}
