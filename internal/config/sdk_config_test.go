package config

import "testing"

func TestClaudeCodexResponsesBridgeConfigDefaults(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("{}"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if !cfg.ClaudeCodexResponsesBridge.IsEnabled() {
		t.Fatal("Claude Codex Responses bridge defaulted to disabled")
	}
	if got := cfg.ClaudeCodexResponsesBridge.ContextWindow; got != 0 {
		t.Fatalf("context window = %d, want 0", got)
	}
}

func TestParseConfigBytesClaudeCodexResponsesBridge(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
claude-codex-responses-bridge:
  enabled: false
  context-window: 300000
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if cfg.ClaudeCodexResponsesBridge.IsEnabled() {
		t.Fatal("Claude Codex Responses bridge ignored enabled: false")
	}
	if got := cfg.ClaudeCodexResponsesBridge.ContextWindow; got != 300_000 {
		t.Fatalf("context window = %d, want 300000", got)
	}

	cfg, errParse = ParseConfigBytes([]byte(`
claude-codex-responses-bridge:
  enabled: true
  context-window: 0
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if !cfg.ClaudeCodexResponsesBridge.IsEnabled() {
		t.Fatal("Claude Codex Responses bridge ignored enabled: true")
	}
	if got := cfg.ClaudeCodexResponsesBridge.ContextWindow; got != 0 {
		t.Fatalf("context window = %d, want 0", got)
	}
}
