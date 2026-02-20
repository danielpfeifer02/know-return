package main

import (
	"encoding/json"
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
