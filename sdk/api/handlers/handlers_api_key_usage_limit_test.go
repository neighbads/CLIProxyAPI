package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usagelimit"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// useTestUsageTracker points enforcement at an in-memory tracker so tests never read or
// write the process-wide state file.
func useTestUsageTracker(t *testing.T) *usagelimit.Tracker {
	t.Helper()

	previous := apiKeyUsageTracker
	tracker := usagelimit.New("")
	apiKeyUsageTracker = tracker
	t.Cleanup(func() { apiKeyUsageTracker = previous })
	return tracker
}

func TestEnforceAPIKeyUsageLimitDaily(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tracker := useTestUsageTracker(t)
	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{
		UsageLimits: internalconfig.APIKeyUsageLimits{DailyTokensMB: 1},
	})
	tracker.SetTrackedKeys(map[string]struct{}{policy.Fingerprint(): {}})
	ctx := policyContext(policy)

	if errMsg := handler.EnforceAPIKeyUsageLimit(ctx); errMsg != nil {
		t.Fatalf("fresh key was rejected: %v", errMsg.Error)
	}

	// Below the allowance the key keeps passing.
	tracker.Add(policy.Fingerprint(), 999_999, time.Now())
	if errMsg := handler.EnforceAPIKeyUsageLimit(ctx); errMsg != nil {
		t.Fatalf("key below limit was rejected: %v", errMsg.Error)
	}

	tracker.Add(policy.Fingerprint(), 1, time.Now())
	errMsg := handler.EnforceAPIKeyUsageLimit(ctx)
	if errMsg == nil {
		t.Fatal("key at the daily limit was allowed")
	}
	if errMsg.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", errMsg.StatusCode, http.StatusTooManyRequests)
	}
}

func TestEnforceAPIKeyUsageLimitMonthly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tracker := useTestUsageTracker(t)
	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{
		UsageLimits: internalconfig.APIKeyUsageLimits{MonthlyTokensMB: 2},
	})
	tracker.SetTrackedKeys(map[string]struct{}{policy.Fingerprint(): {}})
	ctx := policyContext(policy)

	// The daily window is unlimited here, so only the monthly allowance can reject.
	now := time.Now()
	tracker.Add(policy.Fingerprint(), 1_500_000, now)
	if errMsg := handler.EnforceAPIKeyUsageLimit(ctx); errMsg != nil {
		t.Fatalf("key below monthly limit was rejected: %v", errMsg.Error)
	}

	tracker.Add(policy.Fingerprint(), 600_000, now)
	errMsg := handler.EnforceAPIKeyUsageLimit(ctx)
	if errMsg == nil {
		t.Fatal("key over the monthly limit was allowed")
	}
	if errMsg.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", errMsg.StatusCode, http.StatusTooManyRequests)
	}
}

func TestEnforceAPIKeyUsageLimitIgnoresUnlimitedKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tracker := useTestUsageTracker(t)
	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}

	// A key with no policy at all is never limited.
	if errMsg := handler.EnforceAPIKeyUsageLimit(policyContext(nil)); errMsg != nil {
		t.Fatalf("unrestricted key was rejected: %v", errMsg.Error)
	}

	// A key restricted only by model keeps its unlimited allowance.
	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{ExcludedModels: []string{"gpt-5"}})
	tracker.Add("", 5_000_000_000, time.Now())
	if errMsg := handler.EnforceAPIKeyUsageLimit(policyContext(policy)); errMsg != nil {
		t.Fatalf("model-only policy was rejected: %v", errMsg.Error)
	}
}
