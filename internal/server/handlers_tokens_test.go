package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func seedCLIToken(t *testing.T, st store.Store) string {
	t.Helper()
	tok, _ := token.Generate(token.KindCLI)
	hash, _ := token.HashSecret(tok.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		tok.ID, store.TokenCLI, nil, hash, "seed")
	return tok.String()
}

func TestCreateAndListTokens(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cli := seedCLIToken(t, st)

	body, _ := json.Marshal(api.CreateTokenRequest{Kind: "join", Label: "new-node"})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cli)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("create: %v status=%d", err, resp.StatusCode)
	}
	var got api.CreateTokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ID == "" || got.Token == "" {
		t.Fatalf("empty response: %+v", got)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+cli)
	resp, _ = http.DefaultClient.Do(req)
	var list []api.TokenSummary
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list) < 2 { // seeded + the one we just made
		t.Fatalf("want >=2 tokens, got %d", len(list))
	}
}

func httpTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}
