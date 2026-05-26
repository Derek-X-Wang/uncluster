package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

// TestAgentRegister_HashSecretFailure proves the fix for #42: when
// token.HashSecret returns an error during agent registration the handler
// must return 500 and must NOT persist any token row. Pre-fix the handler
// discarded the error (`hash, _ := token.HashSecret(...)`), wrote an empty
// hash into tokens, returned 200 with the plaintext token, and every future
// heartbeat then 401'd forever because VerifySecret compared against "".
//
// Lives in `package server` so we can swap the package-level hashSecret var.
func TestAgentRegister_HashSecretFailure(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "hashfail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Mint a join token via the store directly (the handler will verify it).
	jt, err := token.Generate(token.KindJoin)
	if err != nil {
		t.Fatal(err)
	}
	jtHash, _ := token.HashSecret(jt.Secret)
	expiry := time.Now().Add(time.Hour)
	if _, err := st.CreateToken(context.Background(), store.NewTokenParams{
		ID:         jt.ID,
		Kind:       store.TokenJoin,
		SecretHash: jtHash,
		Label:      "test-join",
		ExpiresAt:  &expiry,
	}); err != nil {
		t.Fatal(err)
	}

	// Swap hashSecret to simulate argon2id failure. Restore after the test
	// regardless of outcome — other tests rely on the real impl.
	orig := hashSecret
	t.Cleanup(func() { hashSecret = orig })
	hashSecret = func(secret string) (string, error) {
		return "", errors.New("simulated argon2id failure")
	}

	srv := New(Config{Store: st})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: jt.String(), Name: "hashfail-box",
	})
	resp, err := http.Post(ts.URL+"/v1/agent/register",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}

	// Critical: no agent-token row was persisted. Pre-fix this would have an
	// agent token with secret_hash = "" — authenticate-anything-but-broken.
	tokens, err := st.ListTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range tokens {
		if tok.Kind == store.TokenAgent {
			t.Errorf("agent token persisted despite HashSecret failure: %+v", tok)
		}
	}

	// The join token must remain usable (not marked-used) so a retry can
	// re-register. The handler completes CreateAgent before HashSecret runs,
	// so the agent row will exist — but the join token itself is only marked
	// used AFTER the token persist succeeds, so a retry path is sane.
	jtRow, err := st.GetTokenByID(context.Background(), jt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if jtRow.UsedAt != nil {
		t.Errorf("join token marked used despite HashSecret failure; retry impossible")
	}
}
