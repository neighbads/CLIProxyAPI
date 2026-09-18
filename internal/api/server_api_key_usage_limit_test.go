package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/usagelimit"
)

// Usage accounting must follow the compiled policies: a key restricted only by model, or a
// key with no policy at all, keeps no counter.
func TestUsageLimitedFingerprintsTracksOnlyLimitedKeys(t *testing.T) {
	t.Parallel()

	cfg := &config.SDKConfig{
		APIKeys: []string{"sk-limited", "sk-models", "sk-plain"},
		APIKeyPolicies: config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
			{APIKey: "sk-limited", UsageLimits: config.APIKeyUsageLimits{DailyTokensMB: 200}},
			{APIKey: "sk-models", ExcludedModels: []string{"gpt-5"}},
		}),
	}

	tracked := usageLimitedFingerprints(buildAPIKeyPolicyIndex(cfg))
	if len(tracked) != 1 {
		t.Fatalf("tracked = %d keys, want 1: %#v", len(tracked), tracked)
	}
	if _, ok := tracked[misc.APIKeyFingerprint("sk-limited")]; !ok {
		t.Fatal("key with a usage limit is not tracked")
	}

	// A configuration without any usage limit tracks nothing.
	if tracked = usageLimitedFingerprints(buildAPIKeyPolicyIndex(&config.SDKConfig{})); len(tracked) != 0 {
		t.Fatalf("empty config tracked %d keys", len(tracked))
	}
}

func TestCodexAlphaSearchRejectsOverLimitAPIKey(t *testing.T) {
	server := newTestServer(t)

	server.UpdateClients(policyConfig(
		[]string{"test-key"},
		config.APIKeyPolicy{
			APIKey:      "test-key",
			UsageLimits: config.APIKeyUsageLimits{DailyTokensMB: 1},
		},
	))

	fp := misc.APIKeyFingerprint("test-key")
	tracker := usagelimit.Default()
	tracker.SetTrackedKeys(map[string]struct{}{fp: {}})
	tracker.Add(fp, 1_000_000, time.Now())

	body := `{"model":"gpt-4","query":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusTooManyRequests, rr.Body.String())
	}
}
