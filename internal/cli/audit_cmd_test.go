package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestRunAuditCerts_FiltersAndRenders exercises the non-tail audit path through
// the in-memory client: filtering, denial-reason rendering, key truncation, and
// JSON output.
func TestRunAuditCerts_FiltersAndRenders(t *testing.T) {
	f := newFakeControlPlaneClient()
	f.certEvents = []api.CertEventSummary{
		{TS: 100, CallerTokenID: "caller_x", TargetAgentID: "ag_1", Username: "derek", Outcome: "signed", KeyID: "abcdef0123456789ZZ"},
		{TS: 90, CallerTokenID: "caller_y", TargetAgentID: "ag_1", Username: "root", Outcome: "denied", DenialReason: "no_acl"},
	}

	// No filters: both rows, denial reason + truncated key rendered.
	var out bytes.Buffer
	if err := runAuditCerts(context.Background(), f, &out, CertAuditQuery{}, "", false, false); err != nil {
		t.Fatalf("runAuditCerts: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "signed") || !strings.Contains(s, "denied") {
		t.Errorf("expected both events:\n%s", s)
	}
	if !strings.Contains(s, "[no_acl]") {
		t.Errorf("expected denial reason:\n%s", s)
	}
	if !strings.Contains(s, "key=abcdef0123456789") { // truncated to 16 chars
		t.Errorf("expected truncated key:\n%s", s)
	}

	// Caller filter narrows to caller_x.
	out.Reset()
	if err := runAuditCerts(context.Background(), f, &out, CertAuditQuery{Caller: "caller_x"}, "", false, false); err != nil {
		t.Fatalf("runAuditCerts(caller): %v", err)
	}
	s = out.String()
	if !strings.Contains(s, "caller_x") || strings.Contains(s, "caller_y") {
		t.Errorf("caller filter wrong:\n%s", s)
	}

	// JSON output.
	out.Reset()
	if err := runAuditCerts(context.Background(), f, &out, CertAuditQuery{}, "", false, true); err != nil {
		t.Fatalf("runAuditCerts(json): %v", err)
	}
	if !strings.Contains(out.String(), `"outcome": "signed"`) {
		t.Errorf("json output missing outcome:\n%s", out.String())
	}
}

// TestHTTPListCertEvents_EncodesQuery proves the HTTP adapter builds the audit
// query with proper URL value encoding (acceptance: "Audit query building uses
// URL value encoding") — values with spaces are percent/`+`-encoded rather than
// concatenated raw.
func TestHTTPListCertEvents_EncodesQuery(t *testing.T) {
	var gotRawQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode([]api.CertEventSummary{})
	}))
	t.Cleanup(ts.Close)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	if _, err := client.ListCertEvents(context.Background(), CertAuditQuery{
		Caller:  "caller x", // contains a space to prove encoding
		Agent:   "ag_1",
		User:    "de rek",
		Outcome: "signed",
		Since:   1234,
		Limit:   50,
	}); err != nil {
		t.Fatalf("ListCertEvents: %v", err)
	}

	// Raw query must be parseable and correctly decoded.
	vals, err := url.ParseQuery(gotRawQuery)
	if err != nil {
		t.Fatalf("raw query %q not URL-encoded: %v", gotRawQuery, err)
	}
	if vals.Get("caller") != "caller x" || vals.Get("user") != "de rek" {
		t.Errorf("decoded values wrong: caller=%q user=%q", vals.Get("caller"), vals.Get("user"))
	}
	if vals.Get("since") != "1234" || vals.Get("limit") != "50" {
		t.Errorf("since/limit wrong: since=%q limit=%q", vals.Get("since"), vals.Get("limit"))
	}
	// The space must be encoded on the wire, not sent raw.
	if !strings.Contains(gotRawQuery, "caller=caller+x") {
		t.Errorf("space not URL-encoded in raw query: %q", gotRawQuery)
	}
}

// TestHTTPListCertEvents_NoFilters_NoQuery confirms an empty query produces a
// bare path (no trailing "?").
func TestHTTPListCertEvents_NoFilters_NoQuery(t *testing.T) {
	var gotPath, gotRawQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode([]api.CertEventSummary{})
	}))
	t.Cleanup(ts.Close)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	if _, err := client.ListCertEvents(context.Background(), CertAuditQuery{}); err != nil {
		t.Fatalf("ListCertEvents: %v", err)
	}
	if gotPath != "/v1/audit/certs" || gotRawQuery != "" {
		t.Errorf("path/query = %q?%q, want /v1/audit/certs with empty query", gotPath, gotRawQuery)
	}
}
