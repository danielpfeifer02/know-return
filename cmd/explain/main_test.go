package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseServeArgsDefaults(t *testing.T) {
	cfg, err := parseServeArgs(nil)
	if err != nil {
		t.Fatalf("parseServeArgs returned error: %v", err)
	}
	if cfg.socketPath != defaultSocket {
		t.Fatalf("socketPath = %q, want %q", cfg.socketPath, defaultSocket)
	}
	if cfg.idleMinutes != 30 {
		t.Fatalf("idleMinutes = %d, want 30", cfg.idleMinutes)
	}
}

func TestParseServeArgsWithFlags(t *testing.T) {
	cfg, err := parseServeArgs([]string{"-socket", "/tmp/custom.sock", "-idle-minutes", "5"})
	if err != nil {
		t.Fatalf("parseServeArgs returned error: %v", err)
	}
	if cfg.socketPath != "/tmp/custom.sock" {
		t.Fatalf("socketPath = %q, want /tmp/custom.sock", cfg.socketPath)
	}
	if cfg.idleMinutes != 5 {
		t.Fatalf("idleMinutes = %d, want 5", cfg.idleMinutes)
	}
}

func TestParseServeArgsRejectsInvalidIdleMinutes(t *testing.T) {
	if _, err := parseServeArgs([]string{"-idle-minutes", "0"}); err == nil {
		t.Fatal("expected error for idle-minutes=0")
	}
}

func TestExtractResponseTextPrefersOutputText(t *testing.T) {
	resp := responsesResponse{OutputText: "  concise answer  "}
	got := extractResponseText(resp)
	if got != "concise answer" {
		t.Fatalf("extractResponseText = %q, want %q", got, "concise answer")
	}
}

func TestExtractResponseTextFromOutputItems(t *testing.T) {
	var resp responsesResponse
	payload := []byte(`{
		"output": [
			{"content": [{"type": "output_text", "text": " first "}, {"type": "reasoning", "text": "skip"}]},
			{"content": [{"type": "output_text", "text": "second"}]}
		]
	}`)
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	got := extractResponseText(resp)
	if got != "first second" {
		t.Fatalf("extractResponseText = %q, want %q", got, "first second")
	}
}

func TestHeuristicFalseCommand(t *testing.T) {
	got := heuristic(Request{Command: "false", ExitCode: 1})
	if got.Confidence < 0.9 {
		t.Fatalf("heuristic confidence = %v, want >= 0.9", got.Confidence)
	}
	if got.Message == "" || got.Message == "Command failed (exit 1)." {
		t.Fatalf("heuristic message too generic: %q", got.Message)
	}
}

func TestIsLowValueLLMMessage(t *testing.T) {
	if !isLowValueLLMMessage("The command failed because it returned a non-zero exit code.") {
		t.Fatal("expected generic response to be marked low-value")
	}
	if isLowValueLLMMessage("`grep -l` was run without a pattern; provide a pattern like `grep -l foo file.txt`.") {
		t.Fatal("expected concrete response to be accepted")
	}
}

func TestShouldUseLLMForNonZeroWithNoOutput(t *testing.T) {
	req := Request{
		Command:  `grep --color=auto -rl "THIS SHALL NOT BE FOUND"`,
		ExitCode: 1,
		StdErr:   "",
	}
	if !shouldUseLLM(req, false) {
		t.Fatal("expected non-zero/no-output case to use LLM")
	}
}

func TestShouldUseLLMFalseForUsageOutput(t *testing.T) {
	req := Request{
		Command:  `grep -l`,
		ExitCode: 2,
		StdErr:   "usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.",
	}
	if shouldUseLLM(req, false) {
		t.Fatal("expected usage output case to skip LLM")
	}
}

func TestShouldUseLLMFalseForHelpCommand(t *testing.T) {
	req := Request{
		Command:  `grep --help`,
		ExitCode: 2,
	}
	if shouldUseLLM(req, false) {
		t.Fatal("expected --help command to skip LLM")
	}
}

func TestShouldUseLLMTrueForShortHFlag(t *testing.T) {
	req := Request{
		Command:  `grep -h "foo" some-file.txt`,
		ExitCode: 1,
	}
	if !shouldUseLLM(req, false) {
		t.Fatal("expected -h command without usage output to use LLM")
	}
}

func TestShouldUseLLMForceOverride(t *testing.T) {
	req := Request{
		Command:  `grep --help`,
		ExitCode: 2,
		StdErr:   "usage: grep ...",
	}
	if !shouldUseLLM(req, true) {
		t.Fatal("expected force mode to use LLM")
	}
}

func TestRedactSensitiveText(t *testing.T) {
	input := `OPENAI_API_KEY=sk-secret-value Authorization: Bearer very-secret-token https://user:pass@example.com/path`
	got := redactSensitiveText(input)
	if got == input {
		t.Fatal("expected sensitive content to be redacted")
	}
	if contains := "sk-secret-value"; strings.Contains(got, contains) {
		t.Fatalf("expected %q to be redacted", contains)
	}
	if contains := "very-secret-token"; strings.Contains(got, contains) {
		t.Fatalf("expected %q to be redacted", contains)
	}
	if strings.Contains(got, "user:pass@") {
		t.Fatal("expected URL credentials to be redacted")
	}
}

func TestRuntimeConfigHashChangesWithModel(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("EXPLAIN_MODEL", "gpt-4o-mini")
	base := runtimeConfigHash()

	t.Setenv("EXPLAIN_MODEL", "gpt-4.1-mini")
	changed := runtimeConfigHash()
	if base == changed {
		t.Fatal("expected runtime config hash to change when model changes")
	}
}
