package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usagelimit"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/net/context"
)

// EnforceAPIKeyModelPolicy rejects a request whose outward model is forbidden by the
// authenticated client key's policy. It runs before provider resolution and auth selection,
// so a denied model never reaches an upstream request.
func (h *BaseAPIHandler) EnforceAPIKeyModelPolicy(ctx context.Context, modelName string) *interfaces.ErrorMessage {
	policy := h.apiKeyPolicyFromContext(ctx)
	if policy.Empty() {
		return nil
	}
	requested := strings.TrimSpace(modelName)
	if requested == "" || !policy.DeniesModel(requested) {
		return nil
	}
	return &interfaces.ErrorMessage{
		StatusCode: http.StatusForbidden,
		Error:      fmt.Errorf("model %s is not allowed for this API key", requested),
	}
}

// apiKeyUsageTracker accounts the tokens each client key consumes. It is a package variable
// so tests can account against a temporary tracker instead of the process-wide state file.
var apiKeyUsageTracker = usagelimit.Default()

// EnforceAPIKeyUsageLimit rejects a request once the authenticated client key has consumed
// its token allowance for the current calendar day or month. Accounting is fed by completed
// requests, so a limit stops the next request instead of truncating the one in flight.
func (h *BaseAPIHandler) EnforceAPIKeyUsageLimit(ctx context.Context) *interfaces.ErrorMessage {
	policy := h.apiKeyPolicyFromContext(ctx)
	if !policy.LimitsUsage() {
		return nil
	}
	dayTokens, monthTokens := apiKeyUsageTracker.Snapshot(policy.Fingerprint(), time.Now())
	if limit := policy.DailyTokenLimit(); limit > 0 && dayTokens >= limit {
		return usageLimitError("daily", dayTokens, limit)
	}
	if limit := policy.MonthlyTokenLimit(); limit > 0 && monthTokens >= limit {
		return usageLimitError("monthly", monthTokens, limit)
	}
	return nil
}

func usageLimitError(window string, used, limit int64) *interfaces.ErrorMessage {
	return &interfaces.ErrorMessage{
		StatusCode: http.StatusTooManyRequests,
		Error:      fmt.Errorf("%s token limit reached for this API key: %d of %d tokens used", window, used, limit),
	}
}

// apiKeyPolicyFromContext reads the compiled policy published by the authentication
// middleware. It returns nil when the request carries no policy.
func (h *BaseAPIHandler) apiKeyPolicyFromContext(ctx context.Context) *config.APIKeyPolicySet {
	if ctx == nil {
		return nil
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil {
		return nil
	}
	return requestAPIKeyPolicy(ginCtx)
}

// FilterModelsForAPIKeyPolicy removes models the client key can never use from a model-list
// payload. A model is hidden when the policy denies it directly, or when every credential
// that serves it is excluded by the provider-instance or account restrictions.
func (h *BaseAPIHandler) FilterModelsForAPIKeyPolicy(c *gin.Context, models []map[string]any) []map[string]any {
	if len(models) == 0 {
		return models
	}
	keep := h.APIKeyPolicyModelFilter(c)
	if keep == nil {
		return models
	}
	filtered := make([]map[string]any, 0, len(models))
	for _, model := range models {
		if keep(modelListEntryID(model)) {
			filtered = append(filtered, model)
		}
	}
	return filtered
}

// ModelAllowedByAPIKeyPolicy reports whether the outward model identifier is usable by the
// authenticated client key. A model is usable when the policy does not deny it directly and
// at least one credential the policy allows can serve it.
func (h *BaseAPIHandler) ModelAllowedByAPIKeyPolicy(c *gin.Context, modelID string) bool {
	filter := h.APIKeyPolicyModelFilter(c)
	if filter == nil {
		return true
	}
	return filter(modelID)
}

// AttachAPIKeyPolicyMetadata copies the authenticated client key's compiled policy into an
// execution metadata map. Entry points that build their own coreexecutor.Options, instead of
// going through the shared execution chain, call this so provider-instance and account
// exclusions reach auth selection. A key without a policy leaves the map untouched.
func (h *BaseAPIHandler) AttachAPIKeyPolicyMetadata(c *gin.Context, metadata map[string]any) {
	attachAPIKeyPolicyMetadata(metadata, requestAPIKeyPolicy(c))
}

// AttachAPIKeyPolicyMetadataFromContext is the context-scoped counterpart for entry points
// that carry the Gin context inside the request context rather than passing it directly.
// As with the Gin-scoped variant, the policy comes from the authentication middleware and
// never from client input.
func AttachAPIKeyPolicyMetadataFromContext(ctx context.Context, metadata map[string]any) {
	if ctx == nil {
		return
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil {
		return
	}
	attachAPIKeyPolicyMetadata(metadata, requestAPIKeyPolicy(ginCtx))
}

// attachAPIKeyPolicyMetadata publishes the compiled policy into an execution metadata map.
// Only a nil map is skipped: a freshly created but still empty map is a valid target.
func attachAPIKeyPolicyMetadata(metadata map[string]any, policy *config.APIKeyPolicySet) {
	if metadata == nil || policy.Empty() {
		return
	}
	metadata[coreexecutor.APIKeyPolicyMetadataKey] = policy
}

// APIKeyPolicyModelFilter returns a predicate over outward model identifiers for the current
// request, or nil when no per-client policy applies and every model stays usable. Callers that
// build their own catalog payloads (Home and Grok branches) use it to apply the same filtering
// as the SDK model-list endpoints.
func (h *BaseAPIHandler) APIKeyPolicyModelFilter(c *gin.Context) func(string) bool {
	policy := requestAPIKeyPolicy(c)
	if policy.Empty() {
		return nil
	}
	allowedAuthIDs := h.allowedAuthIDsForPolicy(policy)
	return func(modelID string) bool {
		modelID = strings.TrimSpace(modelID)
		if modelID == "" {
			return true
		}
		if policy.DeniesModel(modelID) {
			return false
		}
		if allowedAuthIDs == nil {
			return true
		}
		return modelServedByAllowedAuth(modelID, allowedAuthIDs)
	}
}

// allowedAuthIDsForPolicy returns the auth record IDs the policy still allows, or nil when the
// policy carries no provider/account restriction or excludes nothing. A nil result disables
// the availability filter, so the catalog is never hidden by an empty or stale auth set.
func (h *BaseAPIHandler) allowedAuthIDsForPolicy(policy *config.APIKeyPolicySet) map[string]struct{} {
	if h == nil || h.AuthManager == nil || policy.Empty() || !policy.RestrictsAuth() {
		return nil
	}
	auths := h.AuthManager.List()
	if len(auths) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if policy.DeniesAuth(auth.ID, authProviderInstanceKey(auth), authAccountEmail(auth)) {
			continue
		}
		allowed[auth.ID] = struct{}{}
	}
	if len(allowed) == len(auths) {
		return nil
	}
	return allowed
}

// modelServedByAllowedAuth reports whether at least one allowed credential serves the model.
func modelServedByAllowedAuth(modelID string, allowedAuthIDs map[string]struct{}) bool {
	globalRegistry := registry.GetGlobalRegistry()
	for authID := range allowedAuthIDs {
		if globalRegistry.ClientSupportsModel(authID, modelID) {
			return true
		}
	}
	return false
}

// modelListEntryID extracts the outward model identifier from a model-list entry. Gemini
// entries carry the identifier in "name" as "models/<id>"; other shapes use "id".
func modelListEntryID(model map[string]any) string {
	if len(model) == 0 {
		return ""
	}
	if id, ok := model["id"].(string); ok {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			return trimmed
		}
	}
	if name, ok := model["name"].(string); ok {
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "models/"))
	}
	return ""
}

// authProviderInstanceKey returns the provider configuration api-key behind an auth record.
func authProviderInstanceKey(auth *coreauth.Auth) string {
	if auth == nil || len(auth.Attributes) == 0 {
		return ""
	}
	return strings.TrimSpace(auth.Attributes["api_key"])
}

// authAccountEmail resolves the account email with the same precedence used during selection.
func authAccountEmail(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if value, ok := auth.Metadata["email"].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	if len(auth.Attributes) > 0 {
		if trimmed := strings.TrimSpace(auth.Attributes["email"]); trimmed != "" {
			return trimmed
		}
		if trimmed := strings.TrimSpace(auth.Attributes["account_email"]); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
