package executor

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

var benchmarkCodexPayloadOverrideOutput []byte

func BenchmarkClaudeToCodexPayloadOverrides(b *testing.B) {
	for _, turns := range []int{64, 256} {
		request := benchmarkClaudePayloadOverrideRequest(turns, 32, 8*1024)
		if !gjson.ValidBytes(request) {
			b.Fatal("benchmark generated invalid Claude JSON")
		}
		for _, test := range []struct {
			name          string
			cfg           *config.Config
			wantOverrides bool
		}{
			{name: "no_rules", cfg: &config.Config{}},
			{name: "summary_verbosity", cfg: benchmarkCodexPayloadOverrideConfig(), wantOverrides: true},
		} {
			b.Run(strconv.Itoa(turns)+"_turns/"+test.name, func(b *testing.B) {
				output, err := benchmarkClaudeToCodexPayload(request, test.cfg)
				if err != nil {
					b.Fatal(err)
				}
				if !gjson.ValidBytes(output) {
					b.Fatal("pipeline generated invalid Codex JSON")
				}
				if test.wantOverrides {
					if got := gjson.GetBytes(output, "reasoning.summary").String(); got != "concise" {
						b.Fatalf("reasoning.summary = %q, want concise", got)
					}
					if got := gjson.GetBytes(output, "text.verbosity").String(); got != "medium" {
						b.Fatalf("text.verbosity = %q, want medium", got)
					}
				}

				b.ReportAllocs()
				b.SetBytes(int64(len(request)))
				b.ResetTimer()
				for b.Loop() {
					benchmarkCodexPayloadOverrideOutput, err = benchmarkClaudeToCodexPayload(request, test.cfg)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkClaudeToCodexPayloadOverridesParallel(b *testing.B) {
	for _, turns := range []int{64, 256} {
		request := benchmarkClaudePayloadOverrideRequest(turns, 32, 8*1024)
		if !gjson.ValidBytes(request) {
			b.Fatal("benchmark generated invalid Claude JSON")
		}
		for _, rules := range []struct {
			name string
			cfg  *config.Config
		}{
			{name: "no_rules", cfg: &config.Config{}},
			{name: "summary_verbosity", cfg: benchmarkCodexPayloadOverrideConfig()},
		} {
			for _, parallelism := range []int{1, 8, 32} {
				name := strconv.Itoa(turns) + "_turns/" + rules.name + "/parallel_" + strconv.Itoa(parallelism)
				b.Run(name, func(b *testing.B) {
					b.SetParallelism(parallelism)
					b.ReportAllocs()
					b.SetBytes(int64(len(request)))
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						var output []byte
						ran := false
						for pb.Next() {
							ran = true
							var err error
							output, err = benchmarkClaudeToCodexPayload(request, rules.cfg)
							if err != nil {
								b.Error(err)
								return
							}
						}
						if ran && len(output) == 0 {
							b.Error("pipeline returned an empty payload")
						}
					})
					workers := runtime.GOMAXPROCS(0) * parallelism
					if b.N > 0 {
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())*float64(workers)/float64(b.N), "estimated-wall-ns/op")
					}
				})
			}
		}
	}
}

func benchmarkClaudeToCodexPayload(request []byte, cfg *config.Config) ([]byte, error) {
	from := sdktranslator.FormatClaude
	to := sdktranslator.FormatCodex
	req := cliproxyexecutor.Request{Model: "gpt-5.6-sol", Payload: request}
	opts := cliproxyexecutor.Options{Stream: true, OriginalRequest: request, SourceFormat: from}
	originalTranslated, body := translateCodexRequestPair(from, to, req.Model, request, request, true)
	var err error
	body, err = helps.ApplyRequestThinking(body, req, opts, from.String(), to.String(), "codex")
	if err != nil {
		return nil, err
	}
	return helps.ApplyPayloadConfigWithRequest(cfg, req.Model, to.String(), from.String(), "", body, originalTranslated, req.Model, "/v1/messages", nil), nil
}

func benchmarkCodexPayloadOverrideConfig() *config.Config {
	return &config.Config{Payload: config.PayloadConfig{
		Override: []config.PayloadRule{{
			Models: []config.PayloadModelRule{{
				Name:         "gpt-5.6-sol",
				Protocol:     "codex",
				FromProtocol: "claude",
			}},
			Params: map[string]any{
				"reasoning.summary": "concise",
				"text.verbosity":    "medium",
			},
		}},
	}}
}

func benchmarkClaudePayloadOverrideRequest(turns, toolCount, payloadSize int) []byte {
	payload := strings.Repeat("x", payloadSize)
	var request strings.Builder
	request.Grow((turns + toolCount) * payloadSize)
	request.WriteString(`{"model":"gpt-5.6-sol","system":[{"type":"text","text":"`)
	request.WriteString(payload)
	request.WriteString(`"}],"messages":[`)
	for i := 0; i < turns; i++ {
		if i > 0 {
			request.WriteByte(',')
		}
		request.WriteString(`{"role":"assistant","content":[{"type":"text","text":"`)
		request.WriteString(payload)
		request.WriteString(`"},{"type":"tool_use","id":"toolu_`)
		request.WriteString(strconv.Itoa(i))
		request.WriteString(`","name":"tool_`)
		request.WriteString(strconv.Itoa(i % toolCount))
		request.WriteString(`","input":{"value":"`)
		request.WriteString(payload)
		request.WriteString(`"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_`)
		request.WriteString(strconv.Itoa(i))
		request.WriteString(`","content":[{"type":"text","text":"`)
		request.WriteString(payload)
		request.WriteString(`"}]}]}`)
	}
	request.WriteString(`],"tools":[`)
	for i := 0; i < toolCount; i++ {
		if i > 0 {
			request.WriteByte(',')
		}
		request.WriteString(`{"name":"tool_`)
		request.WriteString(strconv.Itoa(i))
		request.WriteString(`","description":"`)
		request.WriteString(payload)
		request.WriteString(`","input_schema":{"type":"object","properties":{"value":{"type":"string"}}}}`)
	}
	request.WriteString(`]}`)
	return []byte(request.String())
}
