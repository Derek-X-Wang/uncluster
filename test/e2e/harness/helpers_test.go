package harness

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer wires a handler with token-aware routing for the helpers.
// We don't model the full CP — just enough to validate the wire shape the
// harness produces. Each handler asserts headers + body + returns canned JSON.
func newTestServer(t *testing.T, mux map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	h := http.NewServeMux()
	for k, v := range mux {
		h.HandleFunc(k, v)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_Do_AuthHeaderAndBody(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/echo": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer t0k3n" {
				t.Errorf("missing or wrong auth header: %q", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("missing content-type")
			}
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"hello":"world"`) {
				t.Errorf("body missing: %s", b)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
	})

	c := NewClient(srv.URL, "t0k3n")
	var out struct{ OK bool `json:"ok"` }
	if err := c.Do(context.Background(), "POST", "/v1/echo", map[string]string{"hello": "world"}, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Errorf("expected ok=true")
	}
}

func TestClient_Do_NonJSONError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/forbidden": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		},
	})
	c := NewClient(srv.URL, "")
	err := c.Do(context.Background(), "GET", "/v1/forbidden", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if he.Status != http.StatusForbidden {
		t.Errorf("status=%d, want 403", he.Status)
	}
}

func TestMintJoinToken(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/tokens": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("method=%s, want POST", r.Method)
			}
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["kind"] != "join" {
				t.Errorf("kind=%q, want join", req["kind"])
			}
			if req["label"] != "e2e-label" {
				t.Errorf("label=%q, want e2e-label", req["label"])
			}
			_, _ = w.Write([]byte(`{"id":"tk_123","token":"join_t.0k3n"}`))
		},
	})
	c := NewClient(srv.URL, "admin-token")
	tok, err := c.MintJoinToken(context.Background(), "e2e-label")
	if err != nil {
		t.Fatalf("MintJoinToken: %v", err)
	}
	if tok != "join_t.0k3n" {
		t.Errorf("token=%q, want join_t.0k3n", tok)
	}
}

func TestMintCallerToken(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/tokens": func(w http.ResponseWriter, r *http.Request) {
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["kind"] != "caller" {
				t.Errorf("kind=%q, want caller", req["kind"])
			}
			_, _ = w.Write([]byte(`{"id":"tk_caller","token":"cal_t.0k3n"}`))
		},
	})
	c := NewClient(srv.URL, "admin")
	tok, err := c.MintCallerToken(context.Background(), "harness")
	if err != nil {
		t.Fatalf("MintCallerToken: %v", err)
	}
	if tok != "cal_t.0k3n" {
		t.Errorf("token=%q, want cal_t.0k3n", tok)
	}
}

func TestEnrollAgent_NoAuthRequired(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/agents/register": func(w http.ResponseWriter, r *http.Request) {
			// Registration is open — no Authorization required.
			// Asserting that the harness does NOT leak its admin token here
			// is important: a real-world misuse would expose the admin token
			// in registration audit logs.
			if r.Header.Get("Authorization") != "" {
				t.Errorf("EnrollAgent must not send Authorization header, got %q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["join_token"] != "join.tok" {
				t.Errorf("join_token=%v", req["join_token"])
			}
			if req["name"] != "agent-1" {
				t.Errorf("name=%v", req["name"])
			}
			_, _ = w.Write([]byte(`{"agent_id":"a_001","agent_token":"agt.tok","ca_pubkey":"ssh-ed25519 AAA...","expected_paths":{"ca_pubkey":"/x","sshd_drop_in":"/y","principals_dir":"/z"}}`))
		},
	})
	c := NewClient(srv.URL, "") // crucial: no token
	id, err := c.EnrollAgent(context.Background(), "join.tok", "agent-1")
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if id != "a_001" {
		t.Errorf("agent_id=%q, want a_001", id)
	}
}

func TestGrantACL(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/acl": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("method=%s, want POST", r.Method)
			}
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["caller_token_id"] != "ct_1" {
				t.Errorf("caller_token_id=%v", req["caller_token_id"])
			}
			if req["agent"] != "agent-1" {
				t.Errorf("agent=%v", req["agent"])
			}
			users, _ := req["usernames"].([]any)
			if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
				t.Errorf("usernames=%v", users)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	c := NewClient(srv.URL, "admin")
	if err := c.GrantACL(context.Background(), "ct_1", "agent-1", []string{"alice", "bob"}); err != nil {
		t.Fatalf("GrantACL: %v", err)
	}
}

func TestRequestCert(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/certs": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("method=%s, want POST", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer caller.tok" {
				t.Errorf("missing caller auth")
			}
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["agent"] != "agent-1" {
				t.Errorf("agent=%v", req["agent"])
			}
			if req["username"] != "tester" {
				t.Errorf("username=%v", req["username"])
			}
			if int(req["ttl_seconds"].(float64)) != 300 {
				t.Errorf("ttl_seconds=%v", req["ttl_seconds"])
			}
			_, _ = w.Write([]byte(`{"certificate":"ssh-ed25519-cert-v01@openssh.com AAA...","key_id":"k1","principal":"tester","serial":42}`))
		},
	})
	c := NewClient(srv.URL, "caller.tok")
	cert, err := c.RequestCert(context.Background(), "agent-1", "tester", "ssh-ed25519 AAA...", 300)
	if err != nil {
		t.Fatalf("RequestCert: %v", err)
	}
	if !strings.HasPrefix(cert, "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("cert prefix wrong: %q", cert)
	}
}

func TestRevokeToken(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/tokens/tk_xyz": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "DELETE" {
				t.Errorf("method=%s, want DELETE", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	c := NewClient(srv.URL, "admin")
	if err := c.RevokeToken(context.Background(), "tk_xyz"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

func TestDeprovisionAgent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/v1/agents/agent-1": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "DELETE" {
				t.Errorf("method=%s, want DELETE", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	c := NewClient(srv.URL, "admin")
	if err := c.DeprovisionAgent(context.Background(), "agent-1"); err != nil {
		t.Fatalf("DeprovisionAgent: %v", err)
	}
}

func TestWaitForHealthz_Success(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/healthz": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true,"version":"test"}`))
		},
	})
	d, err := WaitForHealthz(context.Background(), srv.URL, 3*time.Second)
	if err != nil {
		t.Fatalf("WaitForHealthz: %v", err)
	}
	if d > 3*time.Second {
		t.Errorf("elapsed=%s exceeded budget", d)
	}
}

func TestWaitForHealthz_Timeout(t *testing.T) {
	// Server that always returns 503.
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/healthz": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	})
	_, err := WaitForHealthz(context.Background(), srv.URL, 1500*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
