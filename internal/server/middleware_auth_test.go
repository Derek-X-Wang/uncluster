package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func newAuthTestSetup(t *testing.T) (*httptest.Server, store.Store, token.Token) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	tok, _ := token.Generate(token.KindCaller)
	hash, _ := token.HashSecret(tok.Secret)
	// Poke the token directly into the store with our desired ID.
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		tok.ID, store.TokenCaller, nil, hash, "test"); err != nil {
		t.Fatal(err)
	}

	srv := server.New(server.Config{Store: st})
	// Mount a protected probe route for testing.
	probe := server.MountProbeRoute(srv)
	ts := httptest.NewServer(probe)
	t.Cleanup(ts.Close)
	return ts, st, tok
}

func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsMissing(t *testing.T) {
	ts, _, _ := newAuthTestSetup(t)
	resp, _ := http.Get(ts.URL + "/__probe")
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsWrongSecret(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	bad := "uct_caller_" + tok.ID + "_" + strings("A", 52) // wrong secret
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func strings(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}
