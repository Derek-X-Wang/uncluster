package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestRunServerUpdateSet confirms the update policy routes through the client
// and the expected version is echoed back.
func TestRunServerUpdateSet(t *testing.T) {
	f := newFakeControlPlaneClient()
	var out bytes.Buffer
	req := api.SetUpdatePolicyRequest{
		ExpectedVersion:   "v2.1.0",
		AssetURLTemplate:  "https://example/{version}/uncluster_{os}_{arch}",
		SHA256URLTemplate: "https://example/{version}/uncluster_{os}_{arch}.sha256",
	}
	if err := runServerUpdateSet(context.Background(), f, &out, req); err != nil {
		t.Fatalf("runServerUpdateSet: %v", err)
	}
	if len(f.updatePolicies) != 1 || f.updatePolicies[0].ExpectedVersion != "v2.1.0" {
		t.Fatalf("updatePolicies = %+v, want one v2.1.0", f.updatePolicies)
	}
	if f.updatePolicies[0].AssetURLTemplate != req.AssetURLTemplate {
		t.Errorf("asset template not forwarded: %q", f.updatePolicies[0].AssetURLTemplate)
	}
	if !strings.Contains(out.String(), "expected_version=v2.1.0") {
		t.Errorf("output = %q, want expected_version confirmation", out.String())
	}
}
