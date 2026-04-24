package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	srv := server.New(server.Config{Store: s})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var body api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.OK {
		t.Fatal("ok=false")
	}
}
