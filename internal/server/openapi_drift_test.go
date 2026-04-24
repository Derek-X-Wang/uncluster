package server_test

import (
	"net/http"
	"os"
	"path/filepath"
	strs "strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestOpenAPIDrift enforces that every route mounted by the server is present
// in api/openapi.yaml. Satisfies acceptance §11 #13.
func TestOpenAPIDrift(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "d.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})

	// Find api/openapi.yaml by walking up from test's working directory.
	yamlPath := ""
	for _, rel := range []string{"api/openapi.yaml", "../api/openapi.yaml", "../../api/openapi.yaml"} {
		if _, err := os.Stat(rel); err == nil {
			yamlPath = rel
			break
		}
	}
	if yamlPath == "" {
		t.Skip("openapi.yaml not found relative to test")
	}
	y, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(y)

	_ = chi.Walk(srv.Handler().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Skip middleware-only paths / healthz (which IS documented; adjust if needed).
		if route == "" {
			return nil
		}
		if !strs.Contains(yaml, route) {
			t.Errorf("route %s %s not documented in openapi.yaml", method, route)
		}
		return nil
	})
}
