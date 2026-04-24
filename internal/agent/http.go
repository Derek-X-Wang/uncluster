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

var ErrUnauthorized = errors.New("agent: unauthorized")

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
	if resp.StatusCode == 401 {
		_ = resp.Body.Close()
		return nil, ErrUnauthorized
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

func (c *ServerClient) Heartbeat(ctx context.Context, metadata map[string]any) (api.HeartbeatResponse, error) {
	var out api.HeartbeatResponse
	_, err := c.do(ctx, "POST", "/v1/agent/heartbeat", api.HeartbeatRequest{Metadata: metadata}, &out)
	return out, err
}

func (c *ServerClient) NextTask(ctx context.Context) (*api.NextTaskResponse, error) {
	// Uses a separate HTTP client with longer timeout for long-poll.
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/v1/agent/next-task", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	lpClient := &http.Client{Timeout: 45 * time.Second}
	resp, err := lpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode == 204 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("next-task: %d: %s", resp.StatusCode, string(b))
	}
	var out api.NextTaskResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *ServerClient) UploadChunk(ctx context.Context, taskID, stream string, data []byte) (api.ChunkUploadResponse, error) {
	var out api.ChunkUploadResponse
	_, err := c.do(ctx, "POST", "/v1/agent/tasks/"+taskID+"/chunks",
		api.ChunkUploadRequest{Stream: stream, Data: data}, &out)
	return out, err
}

func (c *ServerClient) Complete(ctx context.Context, taskID string, exitCode int) error {
	_, err := c.do(ctx, "POST", "/v1/agent/tasks/"+taskID+"/complete",
		api.CompleteRequest{ExitCode: exitCode}, nil)
	return err
}
