package api

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBuildDecisionUpstreamURL(t *testing.T) {
	tests := []struct {
		base     string
		protocol string
		want     string
	}{
		{"https://api.typesafe.ai", "systemone", "https://api.typesafe.ai/v1/systemone"},
		{"https://api.typesafe.ai/v1", "systemone", "https://api.typesafe.ai/v1/systemone"},
		{"https://api.openai.com", "decisions", "https://api.openai.com/v1/decisions"},
		{"https://api.openai.com/v1", "decisions", "https://api.openai.com/v1/decisions"},
	}

	for _, tc := range tests {
		got := buildDecisionUpstreamURL(tc.base, tc.protocol)
		if got != tc.want {
			t.Errorf("buildDecisionUpstreamURL(%q, %q) = %q, want %q", tc.base, tc.protocol, got, tc.want)
		}
	}
}

func TestConvertDecisionResponse_PreservesZeroConfidence(t *testing.T) {
	decResp := []byte(`{
		"id": "dec_12345",
		"model": "gpt-6-luna",
		"answers": [
			{
				"name": "routing",
				"type": "choice",
				"choice": "opt_a",
				"confidence": 0.0
			}
		]
	}`)

	converted, err := convertDecisionResponse(decResp, "decisions", "systemone")
	if err != nil {
		t.Fatalf("convertDecisionResponse failed: %v", err)
	}

	var sys1 map[string]any
	if err := json.Unmarshal(converted, &sys1); err != nil {
		t.Fatalf("unmarshal converted failed: %v", err)
	}

	results := sys1["results"].(map[string]any)
	routing := results["routing"].(map[string]any)
	probs := routing["probabilities"].(map[string]any)
	if probs["opt_a"] != 0.0 {
		t.Errorf("expected probability 0.0 preserved, got %v", probs["opt_a"])
	}
	if sys1["id"] != "dec_12345" {
		t.Errorf("expected ID dec_12345 preserved, got %v", sys1["id"])
	}
}

func TestConvertDecisionResponse_SystemOneToDecisions(t *testing.T) {
	sys1Resp := []byte(`{
		"id": "sys1_999",
		"model": "jev",
		"results": {
			"intent": {
				"selected": "coding",
				"probabilities": {
					"coding": 0.88,
					"chat": 0.12
				}
			}
		}
	}`)

	converted, err := convertDecisionResponse(sys1Resp, "systemone", "decisions")
	if err != nil {
		t.Fatalf("convertDecisionResponse failed: %v", err)
	}

	var dec map[string]any
	if err := json.Unmarshal(converted, &dec); err != nil {
		t.Fatalf("unmarshal converted failed: %v", err)
	}

	if dec["id"] != "sys1_999" {
		t.Errorf("expected preserved ID sys1_999, got %v", dec["id"])
	}
	answers := dec["answers"].([]any)
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	ans := answers[0].(map[string]any)
	if ans["name"] != "intent" || ans["choice"] != "coding" || ans["confidence"] != 0.88 {
		t.Errorf("unexpected answer contents: %+v", ans)
	}
}

func TestReadWithLimit(t *testing.T) {
	data := []byte("hello world")
	buf := bytes.NewReader(data)
	_, err := readWithLimit(buf, 5)
	if err != errBodyTooLarge {
		t.Errorf("expected errBodyTooLarge, got %v", err)
	}

	buf2 := bytes.NewReader(data)
	readBytes, err2 := readWithLimit(buf2, 20)
	if err2 != nil || string(readBytes) != "hello world" {
		t.Errorf("expected successful read, got %v, data=%q", err2, string(readBytes))
	}
}
