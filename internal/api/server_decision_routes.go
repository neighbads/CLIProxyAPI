package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const maxDecisionBodyBytes = 16 << 20

// Standard Decision JSON schemas for normalization
type normalizedDecisionRequest struct {
	Model     string                       `json:"model"`
	Input     any                          `json:"input"`
	Questions []normalizedDecisionQuestion `json:"questions"`
}

type normalizedDecisionQuestion struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Instruction string   `json:"instructions,omitempty"`
	Options     []string `json:"options"`
}

type normalizedDecisionResponse struct {
	ID      string                    `json:"id"`
	Model   string                    `json:"model"`
	Results map[string]questionResult `json:"results"`
	Answers []decisionAnswer          `json:"answers,omitempty"`
	Usage   map[string]any            `json:"usage,omitempty"`
}

type questionResult struct {
	Selected      string             `json:"selected"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

type decisionAnswer struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Choice     string  `json:"choice"`
	Confidence float64 `json:"confidence"`
}

// handleSystemOne handles POST /v1/systemone (TypeSafe / Cloudflare / Jev protocol)
func (s *Server) handleSystemOne(c *gin.Context) {
	s.handleDecisionRequest(c, "systemone")
}

// handleDecisions handles POST /v1/decisions (OpenAI Decisions protocol)
func (s *Server) handleDecisions(c *gin.Context) {
	s.handleDecisionRequest(c, "decisions")
}

func (s *Server) handleDecisionRequest(c *gin.Context, entryProtocol string) {
	if s == nil || s.handlers == nil || s.handlers.AuthManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Decision handler unavailable"})
		return
	}

	body, errRead := readWithLimit(c.Request.Body, maxDecisionBodyBytes)
	if errRead != nil {
		if errors.Is(errRead, errBodyTooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.JSON(clienterror.HTTPStatusFromErrorOr(errRead, http.StatusBadRequest), gin.H{"error": "Failed to read request body"})
		return
	}

	normReq, rawModel, errParse := parseNormalizedDecisionRequest(body, entryProtocol)
	if errParse != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid decision request: %v", errParse)})
		return
	}

	reqHeaders := c.Request.Header.Clone()
	ctx := context.WithValue(c.Request.Context(), "gin", c)
	ctx = handlers.EnrichContextWithSessionHierarchy(ctx, reqHeaders, body, nil)

	if rawModel != "" {
		if errPolicy := s.handlers.EnforceAPIKeyModelPolicy(ctx, rawModel); errPolicy != nil {
			c.JSON(errPolicy.StatusCode, gin.H{"error": errPolicy.Error.Error()})
			return
		}
	}
	if errLimit := s.handlers.EnforceAPIKeyUsageLimit(ctx); errLimit != nil {
		c.JSON(errLimit.StatusCode, gin.H{"error": errLimit.Error.Error()})
		return
	}

	targetModel := rawModel
	selectionOpts := coreexecutor.Options{Headers: reqHeaders, OriginalRequest: body}
	selectionOpts.EnsureMetadata()
	defer auth.CleanupAcquiredSlot(selectionOpts.Metadata)
	s.handlers.AttachAPIKeyPolicyMetadata(c, selectionOpts.Metadata)

	selected, selection, errSelect := s.selectDecisionAuth(ctx, targetModel, selectionOpts)
	if errSelect != nil {
		status := clienterror.HTTPStatusFromErrorOr(errSelect, http.StatusServiceUnavailable)
		c.JSON(status, gin.H{"error": errSelect.Error()})
		return
	}
	if selected == nil {
		if selection != nil {
			selection.End("missing_auth")
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No available provider for decision model"})
		return
	}
	if selection != nil {
		defer selection.End("completed")
	}

	logging.SetGinCPATraceID(c, selected.EnsureIndex())

	// Resolve actual upstream execution model removing aliases / routing prefixes
	upstreamModel := s.handlers.AuthManager.ResolveExecutionModel(selected, targetModel)
	if upstreamModel == "" {
		upstreamModel = targetModel
	}

	respBytes, respHeader, statusCode, errExec := s.executeDecision(ctx, selected, normReq, upstreamModel, entryProtocol, selectionOpts)
	if errExec != nil {
		helps.RecordAPIResponseError(ctx, s.cfg, errExec)
		c.JSON(clienterror.HTTPStatusFromErrorOr(errExec, http.StatusBadGateway), gin.H{"error": errExec.Error()})
		return
	}

	if contentType := respHeader.Get("Content-Type"); contentType != "" {
		c.Header("Content-Type", contentType)
	} else {
		c.Header("Content-Type", "application/json")
	}
	c.Status(statusCode)
	_, _ = c.Writer.Write(respBytes)
}

func parseNormalizedDecisionRequest(body []byte, protocol string) (*normalizedDecisionRequest, string, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", err
	}

	model, _ := raw["model"].(string)
	model = strings.TrimSpace(model)

	req := &normalizedDecisionRequest{
		Model: model,
		Input: raw["input"],
	}

	if rawQuestions, ok := raw["questions"].([]any); ok {
		for _, qItem := range rawQuestions {
			qMap, ok := qItem.(map[string]any)
			if !ok {
				continue
			}
			q := normalizedDecisionQuestion{
				Type:        getString(qMap, "type"),
				Name:        getString(qMap, "name"),
				Instruction: getString(qMap, "instructions"),
			}
			if opts, ok := qMap["options"].([]any); ok {
				for _, opt := range opts {
					if s, ok := opt.(string); ok {
						q.Options = append(q.Options, s)
					}
				}
			} else if choices, ok := qMap["choices"].([]any); ok {
				for _, ch := range choices {
					if chMap, ok := ch.(map[string]any); ok {
						if val := getString(chMap, "value"); val != "" {
							q.Options = append(q.Options, val)
						}
					}
				}
			}
			req.Questions = append(req.Questions, q)
		}
	}

	return req, model, nil
}

func (s *Server) selectDecisionAuth(ctx context.Context, model string, opts coreexecutor.Options) (*auth.Auth, *auth.HomeDispatchSelection, error) {
	if s.handlers == nil || s.handlers.AuthManager == nil {
		return nil, nil, errors.New("auth manager unavailable")
	}

	providers := append([]string{"", "openai-compatibility", "codex"}, s.handlers.AuthManager.AvailableProviders()...)

	for _, p := range providers {
		if s.handlers.AuthManager.HomeEnabled() {
			selection, err := s.handlers.AuthManager.SelectHomeAuthWithCredentialPolicy(ctx, p, model, "", opts)
			if err == nil && selection != nil {
				return selection.CloneAuth(), selection, nil
			}
		} else {
			selected, err := s.handlers.AuthManager.SelectAuth(ctx, p, model, opts)
			if err == nil && selected != nil {
				return selected, nil, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no provider available for model %q", model)
}

func (s *Server) executeDecision(ctx context.Context, selected *auth.Auth, normReq *normalizedDecisionRequest, upstreamModel, entryProtocol string, opts coreexecutor.Options) ([]byte, http.Header, int, error) {
	upstreamURL := ""
	if selected.Attributes != nil {
		upstreamURL = strings.TrimSpace(selected.Attributes["base_url"])
	}
	if upstreamURL == "" {
		return nil, nil, 0, errors.New("upstream provider base_url not configured")
	}

	// Determine upstream protocol: default to preserving client entry protocol unless explicit upstream capability requires conversion
	upstreamProtocol := entryProtocol
	if strings.EqualFold(selected.Provider, "codex") {
		upstreamProtocol = "decisions"
	}

	var outboundBody []byte
	var errMarshal error
	if upstreamProtocol == "decisions" {
		upstreamReq := map[string]any{
			"model": upstreamModel,
			"input": normReq.Input,
		}
		var qList []map[string]any
		for _, q := range normReq.Questions {
			var choices []map[string]string
			for _, opt := range q.Options {
				choices = append(choices, map[string]string{"value": opt})
			}
			qList = append(qList, map[string]any{
				"type":         q.Type,
				"name":         q.Name,
				"instructions": q.Instruction,
				"choices":      choices,
			})
		}
		upstreamReq["questions"] = qList
		outboundBody, errMarshal = json.Marshal(upstreamReq)
	} else {
		upstreamReq := map[string]any{
			"model":     upstreamModel,
			"input":     normReq.Input,
			"questions": normReq.Questions,
		}
		outboundBody, errMarshal = json.Marshal(upstreamReq)
	}
	if errMarshal != nil {
		return nil, nil, 0, errMarshal
	}

	// Apply final user payload configuration rules before dispatching HTTP request
	if s.cfg != nil {
		outboundBody = helps.ApplyPayloadConfigWithRequest(
			s.cfg,
			upstreamModel,
			selected.Provider,
			entryProtocol,
			"",
			outboundBody,
			opts.OriginalRequest,
			normReq.Model,
			"/v1/"+entryProtocol,
			opts.Headers,
		)
	}

	fullURL := buildDecisionUpstreamURL(upstreamURL, upstreamProtocol)

	httpReq, errReq := s.handlers.AuthManager.NewHttpRequest(ctx, selected, http.MethodPost, fullURL, outboundBody, http.Header{"Content-Type": []string{"application/json"}})
	if errReq != nil {
		return nil, nil, 0, errReq
	}

	resp, errDo := s.handlers.AuthManager.HttpRequestWithMetadata(ctx, selected, httpReq, opts.Metadata)
	if errDo != nil {
		return nil, nil, 0, errDo
	}
	defer resp.Body.Close()

	respBytes, errRead := readWithLimit(resp.Body, maxDecisionBodyBytes)
	if errRead != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("read upstream response: %w", errRead)
	}

	if resp.StatusCode != http.StatusOK {
		return respBytes, resp.Header, resp.StatusCode, nil
	}

	finalBytes, errConvert := convertDecisionResponse(respBytes, upstreamProtocol, entryProtocol)
	if errConvert != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("decision protocol conversion error: %w", errConvert)
	}

	return finalBytes, resp.Header, resp.StatusCode, nil
}

func buildDecisionUpstreamURL(baseURL, protocol string) string {
	clean := strings.TrimRight(baseURL, "/")
	cleanLower := strings.ToLower(clean)

	endpoint := "/systemone"
	if protocol == "decisions" {
		endpoint = "/decisions"
	}

	if strings.HasSuffix(cleanLower, "/v1") {
		return clean + endpoint
	}
	return clean + "/v1" + endpoint
}

func convertDecisionResponse(raw []byte, fromProtocol, toProtocol string) ([]byte, error) {
	if fromProtocol == toProtocol {
		return raw, nil
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}

	model, _ := data["model"].(string)
	origID, _ := data["id"].(string)

	if toProtocol == "decisions" && fromProtocol == "systemone" {
		var answers []map[string]any
		if results, ok := data["results"].(map[string]any); ok {
			for name, rItem := range results {
				if rMap, ok := rItem.(map[string]any); ok {
					sel, _ := rMap["selected"].(string)
					prob := 1.0
					if probs, ok := rMap["probabilities"].(map[string]any); ok {
						if p, ok := probs[sel].(float64); ok {
							prob = p
						}
					}
					answers = append(answers, map[string]any{
						"name":       name,
						"type":       "choice",
						"choice":     sel,
						"confidence": prob,
					})
				}
			}
		}
		targetID := origID
		if targetID == "" {
			targetID = "dec_" + generateRandomHex(8)
		}
		out := map[string]any{
			"id":      targetID,
			"object":  "decision",
			"model":   model,
			"answers": answers,
			"usage":   data["usage"],
		}
		return json.Marshal(out)
	}

	if toProtocol == "systemone" && fromProtocol == "decisions" {
		results := make(map[string]any)
		if answers, ok := data["answers"].([]any); ok {
			for _, aItem := range answers {
				if aMap, ok := aItem.(map[string]any); ok {
					name, _ := aMap["name"].(string)
					choice, _ := aMap["choice"].(string)
					conf := 1.0
					if val, ok := aMap["confidence"]; ok {
						if cFloat, okFloat := val.(float64); okFloat {
							conf = cFloat
						}
					}
					results[name] = map[string]any{
						"selected":      choice,
						"probabilities": map[string]float64{choice: conf},
					}
				}
			}
		}
		targetID := origID
		if targetID == "" {
			targetID = "sys1_" + generateRandomHex(8)
		}
		out := map[string]any{
			"id":      targetID,
			"model":   model,
			"results": results,
			"usage":   data["usage"],
		}
		return json.Marshal(out)
	}

	return raw, nil
}

var errBodyTooLarge = errors.New("body exceeds limit")

func readWithLimit(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := io.LimitReader(r, maxBytes+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, errBodyTooLarge
	}
	return b, nil
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
