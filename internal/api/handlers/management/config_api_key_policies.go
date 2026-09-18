package management

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// api-key-policies: []config.APIKeyPolicy
//
// The section restricts the models, provider configuration instances, upstream accounts, and
// token allowance each client API key may use. Writes go through the shared persist/reload
// path, so policy changes take effect on the next request without a restart.

func (h *Handler) GetAPIKeyPolicies(c *gin.Context) {
	c.JSON(200, gin.H{"api-key-policies": config.NormalizeAPIKeyPolicies(h.cfg.APIKeyPolicies)})
}

func (h *Handler) PutAPIKeyPolicies(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.APIKeyPolicy
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.APIKeyPolicy `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies(arr)
	h.persistLocked(c)
}

// PatchAPIKeyPolicies upserts a single policy identified by "api-key" (or by "index").
// Omitted restriction lists keep their current value; an explicitly supplied empty list
// clears that dimension. Supplying "usage-limits" replaces both token allowances, so a
// zero value in it lifts the limit for that window.
func (h *Handler) PatchAPIKeyPolicies(c *gin.Context) {
	type apiKeyPolicyPatch struct {
		APIKey              *string                   `json:"api-key"`
		ExcludedModels      *[]string                 `json:"excluded-models"`
		ExcludedAIProviders *[]string                 `json:"excluded-ai-providers"`
		ExcludedAIAccounts  *[]string                 `json:"excluded-ai-accounts"`
		UsageLimits         *config.APIKeyUsageLimits `json:"usage-limits"`
	}
	var body struct {
		APIKey              *string                   `json:"api-key"`
		Index               *int                      `json:"index"`
		ExcludedModels      *[]string                 `json:"excluded-models"`
		ExcludedAIProviders *[]string                 `json:"excluded-ai-providers"`
		ExcludedAIAccounts  *[]string                 `json:"excluded-ai-accounts"`
		UsageLimits         *config.APIKeyUsageLimits `json:"usage-limits"`
		Value               *apiKeyPolicyPatch        `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if body.Value != nil {
		// Accept the {"value": {...}} envelope used by the other patch endpoints.
		if body.Value.APIKey != nil {
			body.APIKey = body.Value.APIKey
		}
		if body.Value.ExcludedModels != nil {
			body.ExcludedModels = body.Value.ExcludedModels
		}
		if body.Value.ExcludedAIProviders != nil {
			body.ExcludedAIProviders = body.Value.ExcludedAIProviders
		}
		if body.Value.ExcludedAIAccounts != nil {
			body.ExcludedAIAccounts = body.Value.ExcludedAIAccounts
		}
		if body.Value.UsageLimits != nil {
			body.UsageLimits = body.Value.UsageLimits
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := -1
	if body.Index != nil {
		// An explicitly supplied index must address an existing entry. Falling back to an
		// upsert here would silently append a duplicate instead of updating the target.
		if *body.Index < 0 || *body.Index >= len(h.cfg.APIKeyPolicies) {
			c.JSON(400, gin.H{"error": "index out of range"})
			return
		}
		idx = *body.Index
	} else if body.APIKey != nil {
		key := strings.TrimSpace(*body.APIKey)
		if key == "" {
			c.JSON(400, gin.H{"error": "invalid api-key"})
			return
		}
		for i := range h.cfg.APIKeyPolicies {
			if h.cfg.APIKeyPolicies[i].APIKey == key {
				idx = i
				break
			}
		}
	} else {
		c.JSON(400, gin.H{"error": "missing api-key"})
		return
	}

	entry := config.APIKeyPolicy{}
	if idx >= 0 {
		entry = h.cfg.APIKeyPolicies[idx]
	}
	if body.APIKey != nil {
		entry.APIKey = strings.TrimSpace(*body.APIKey)
	}
	if body.ExcludedModels != nil {
		entry.ExcludedModels = config.NormalizeExcludedModels(*body.ExcludedModels)
	}
	if body.ExcludedAIProviders != nil {
		entry.ExcludedAIProviders = append([]string(nil), (*body.ExcludedAIProviders)...)
	}
	if body.ExcludedAIAccounts != nil {
		entry.ExcludedAIAccounts = append([]string(nil), (*body.ExcludedAIAccounts)...)
	}
	if body.UsageLimits != nil {
		entry.UsageLimits = body.UsageLimits.Normalized()
	}
	if entry.APIKey == "" {
		c.JSON(400, gin.H{"error": "missing api-key"})
		return
	}

	out := make([]config.APIKeyPolicy, 0, len(h.cfg.APIKeyPolicies)+1)
	if idx >= 0 {
		out = append(out, h.cfg.APIKeyPolicies[:idx]...)
		out = append(out, h.cfg.APIKeyPolicies[idx+1:]...)
	} else {
		out = append(out, h.cfg.APIKeyPolicies...)
	}
	if !entry.Empty() {
		out = append(out, entry)
	}
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies(out)
	h.persistLocked(c)
}

func (h *Handler) DeleteAPIKeyPolicies(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		if _, errScan := fmt.Sscanf(idxStr, "%d", &idx); errScan == nil && idx >= 0 && idx < len(h.cfg.APIKeyPolicies) {
			out := append([]config.APIKeyPolicy(nil), h.cfg.APIKeyPolicies[:idx]...)
			out = append(out, h.cfg.APIKeyPolicies[idx+1:]...)
			h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies(out)
			h.persistLocked(c)
			return
		}
	}
	if key := strings.TrimSpace(c.Query("api-key")); key != "" {
		found := false
		out := make([]config.APIKeyPolicy, 0, len(h.cfg.APIKeyPolicies))
		for _, entry := range h.cfg.APIKeyPolicies {
			if entry.APIKey == key {
				found = true
				continue
			}
			out = append(out, entry)
		}
		if !found {
			c.JSON(404, gin.H{"error": "policy not found"})
			return
		}
		h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies(out)
		h.persistLocked(c)
		return
	}
	c.JSON(400, gin.H{"error": "missing index or api-key"})
}
