package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestExplainReturnsHeuristicWhenLLMCallFails(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("EXPLAIN_FORCE_LLM", "1")

	origLLMCaller := llmCaller
	llmCaller = func(string, Request, heuristicResult) (string, error) {
		return "", errors.New("simulated LLM outage")
	}
	t.Cleanup(func() {
		llmCaller = origLLMCaller
	})

	llmState.mu.Lock()
	llmState.lastCall = time.Time{}
	llmState.cache = make(map[string]cachedLLMResult)
	llmState.mu.Unlock()

	req := Request{Command: "definitely-not-a-real-command", ExitCode: 127}
	want := heuristic(req).Message

	msg, usedLLM, err := explain(req)
	if err != nil {
		t.Fatalf("explain returned unexpected error: %v", err)
	}
	if usedLLM {
		t.Fatal("expected usedLLM=false when LLM call fails")
	}
	if msg != want {
		t.Fatalf("message = %q, want heuristic fallback %q", msg, want)
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

func TestRuntimeConfigPartsChangeWithInstructions(t *testing.T) {
	partsA := runtimeConfigParts("instruction-set-a")
	partsB := runtimeConfigParts("instruction-set-b")
	if strings.Join(partsA, "\n") == strings.Join(partsB, "\n") {
		t.Fatal("expected runtime config parts to change when instructions change")
	}

	foundSchema := false
	for _, part := range partsA {
		if strings.HasPrefix(part, "prompt_schema_version=") {
			foundSchema = true
			break
		}
	}
	if !foundSchema {
		t.Fatal("expected prompt schema version to be part of runtime config")
	}
}

func TestServerConnDeadlineFollowsLLMTimeout(t *testing.T) {
	t.Setenv("EXPLAIN_SEND_TIMEOUT_MS", "6000")
	t.Setenv("EXPLAIN_LLM_TIMEOUT_MS", "9000")

	got := serverConnDeadline()
	want := 10 * time.Second
	if got != want {
		t.Fatalf("serverConnDeadline = %v, want %v", got, want)
	}
}

func TestServerConnDeadlineUsesSendTimeoutWhenLonger(t *testing.T) {
	t.Setenv("EXPLAIN_SEND_TIMEOUT_MS", "9000")
	t.Setenv("EXPLAIN_LLM_TIMEOUT_MS", "4000")

	got := serverConnDeadline()
	want := 9 * time.Second
	if got != want {
		t.Fatalf("serverConnDeadline = %v, want %v", got, want)
	}
}

func TestBuildPromptStructuredJSON(t *testing.T) {
	req := Request{
		Command:       "  cleaqr  ",
		ExitCode:      127,
		Cwd:           "/home/dev/workspace/know-return",
		StdErr:        "bash: cleaqr: command not found",
		OS:            "linux/amd64",
		Distro:        "Ubuntu 24.04 LTS",
		Shell:         "/bin/bash",
		InRepo:        true,
		InVenv:        false,
		InContainer:   false,
		PathEntries:   8,
		PathHasUsrBin: true,
	}
	heur := heuristicResult{Message: "Command not found: check PATH or install the binary."}

	prompt := buildPrompt(req, heur)
	const prefix = "INPUT_JSON:\n"
	if !strings.HasPrefix(prompt, prefix) {
		t.Fatalf("prompt missing INPUT_JSON prefix: %q", prompt)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(prompt, prefix)), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if got := payload["command"]; got != "cleaqr" {
		t.Fatalf("command = %#v, want %q", got, "cleaqr")
	}
	if got := payload["cwd"]; got != "workspace/know-return" {
		t.Fatalf("cwd = %#v, want %q", got, "workspace/know-return")
	}
	if got := payload["output_error"]; got != "bash: cleaqr: command not found" {
		t.Fatalf("output_error = %#v, want exact stderr", got)
	}
	if got := payload["heuristic_hint"]; got != heur.Message {
		t.Fatalf("heuristic_hint = %#v, want %q", got, heur.Message)
	}

	env, ok := payload["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment has wrong type: %T", payload["environment"])
	}
	if got := env["shell"]; got != "/bin/bash" {
		t.Fatalf("environment.shell = %#v, want %q", got, "/bin/bash")
	}
	if got := env["in_repo"]; got != true {
		t.Fatalf("environment.in_repo = %#v, want true", got)
	}
	if got := env["path_has_usr_bin"]; got != true {
		t.Fatalf("environment.path_has_usr_bin = %#v, want true", got)
	}
}

func TestBuildPromptEmptyOutputError(t *testing.T) {
	prompt := buildPrompt(Request{Command: "false", ExitCode: 1}, heuristicResult{})

	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(prompt, "INPUT_JSON:\n")), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got := payload["output_error"]; got != "<empty>" {
		t.Fatalf("output_error = %#v, want %q", got, "<empty>")
	}
}

func TestCwdTail(t *testing.T) {
	if got := cwdTail("/home/dev/workspace/know-return", 2); got != "workspace/know-return" {
		t.Fatalf("cwdTail = %q, want %q", got, "workspace/know-return")
	}
	if got := cwdTail("know-return", 2); got != "know-return" {
		t.Fatalf("cwdTail short path = %q, want %q", got, "know-return")
	}
	if got := cwdTail("", 2); got != "" {
		t.Fatalf("cwdTail empty = %q, want empty", got)
	}
}

func TestPathSummary(t *testing.T) {
	entries, hasUsrBin := pathSummary("/usr/local/bin:/usr/bin::/bin")
	if entries != 3 {
		t.Fatalf("entries = %d, want 3", entries)
	}
	if !hasUsrBin {
		t.Fatal("expected /usr/bin to be detected")
	}
}

func TestResponsesInstructionsHasNoInventConstraint(t *testing.T) {
	if !strings.Contains(responsesInstructions, "Do not invent package names") {
		t.Fatal("expected instructions to include do-not-invent constraint")
	}
	if !strings.Contains(responsesInstructions, "Output format") {
		t.Fatal("expected instructions to include output format section")
	}
}
