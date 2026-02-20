package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Request is sent from shell hook to daemon.
type Request struct {
	Command          string `json:"cmd"`
	ExitCode         int    `json:"exit_code"`
	StdErr           string `json:"stderr"`
	Cwd              string `json:"cwd"`
	OS               string `json:"os"`
	Distro           string `json:"distro"`
	Shell            string `json:"shell"`
	InRepo           bool   `json:"in_repo"`
	InVenv           bool   `json:"in_venv"`
	InContainer      bool   `json:"in_container"`
	PathEntries      int    `json:"path_entries"`
	PathHasUsrBin    bool   `json:"path_has_usr_bin"`
	Duration         int64  `json:"duration_ms"`
	Timestamp        int64  `json:"ts"`
	ClientConfigHash string `json:"cfg_hash,omitempty"`
}

// Response is returned by daemon to shell hook.
type Response struct {
	Message string `json:"message"`
	UsedLLM bool   `json:"used_llm"`
	Error   string `json:"error,omitempty"`
}

const defaultSocket = "/tmp/explainerr.sock"
const defaultModel = "gpt-4o-mini"
const defaultSendDeadline = 6 * time.Second
const defaultLLMTimeout = 4 * time.Second
const defaultLLMMinInterval = 800 * time.Millisecond
const defaultLLMCacheTTL = 45 * time.Second
const defaultLLMFailureBackoff = 5 * time.Second
const maxLLMCacheEntries = 256
const runtimeConfigVersion = "3"
const promptSchemaVersion = "1"
const responsesInstructions = `You are a terminal error explainer.

Task:
Given a command invocation and its stderr/output, produce ONE single-line suggestion.

Rules (follow in order):
1) Use only evidence from the provided output/error and metadata. Do not invent package names, flags, paths, or tools.
2) Understand the command itself and combine command intent with exit code/output signals (e.g., typo, host not found) to infer the most likely issue.
3) Be concise when you suggest a solution. Isolate e.g. wrong words or misused flags directly instead of only mentioning them as a cause.
4) Choose the single most likely cause and the single best next action.
5) If the output names a package manager or package that provides the command, prefer that exact install command/name.
6) Otherwise keep the advice OS-agnostic (e.g., "install the package that provides <binary>" / "check PATH").

Output format (exactly one line, nothing else):
'<command>' - <brief cause> - <brief explanation/hint>

Constraints:
- Keep the entire line concise: target 15-20 words total, if needed can be more but never exceed 30 words.
- No backticks, no extra punctuation beyond what the format implies.`

type cachedLLMResult struct {
	message   string
	expiresAt time.Time
}

var llmState = struct {
	mu           sync.Mutex
	lastCall     time.Time
	failureUntil time.Time
	cache        map[string]cachedLLMResult
}{
	cache: make(map[string]cachedLLMResult),
}

var llmCaller = callLLM

var sensitivePatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	{
		pattern: regexp.MustCompile(`(?i)\b(authorization\s*:\s*bearer)\s+[^\s"']+`),
		replace: `$1 [REDACTED]`,
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(bearer)\s+[a-z0-9._-]{10,}`),
		replace: `$1 [REDACTED]`,
	},
	{
		pattern: regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*(?:api[_-]?key|token|secret|password|passwd)[a-z0-9_]*)\s*=\s*([^\s"']+)`),
		replace: `$1=[REDACTED]`,
	},
	{
		pattern: regexp.MustCompile(`sk-[a-zA-Z0-9_-]{10,}`),
		replace: `[REDACTED_KEY]`,
	},
	{
		pattern: regexp.MustCompile(`([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@`),
		replace: `$1[REDACTED]:[REDACTED]@`,
	},
}

func main() {
	if len(os.Args) < 2 {
		runServe(nil)
		return
	}

	args := os.Args[1:]
	switch args[0] {
	case "serve":
		runServe(args[1:])
	case "send":
		runSend(args[1:])
	default:
		// Keep backward compatibility with historical `explain -socket ...`.
		if strings.HasPrefix(args[0], "-") {
			runServe(args)
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: explain [serve|send] [flags]")
		os.Exit(1)
	}
}

type serveConfig struct {
	socketPath  string
	idleMinutes int
}

type runtimeContext struct {
	OS            string
	Distro        string
	Shell         string
	InRepo        bool
	InVenv        bool
	InContainer   bool
	PathEntries   int
	PathHasUsrBin bool
}

type responsesRequest struct {
	Model           string  `json:"model"`
	Instructions    string  `json:"instructions,omitempty"`
	Input           string  `json:"input"`
	MaxOutputTokens int     `json:"max_output_tokens"`
	Temperature     float64 `json:"temperature"`
}

type responsesResponse struct {
	OutputText string `json:"output_text"`
	Output     []struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
}

func parseServeArgs(args []string) (serveConfig, error) {
	cfg := serveConfig{
		socketPath:  defaultSocket,
		idleMinutes: 30,
	}

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.socketPath, "socket", cfg.socketPath, "unix socket path")
	fs.IntVar(&cfg.idleMinutes, "idle-minutes", cfg.idleMinutes, "shutdown after idle minutes")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if cfg.socketPath == "" {
		return serveConfig{}, errors.New("socket path must not be empty")
	}
	if cfg.idleMinutes < 1 {
		return serveConfig{}, errors.New("idle-minutes must be >= 1")
	}
	return cfg, nil
}

func runServe(args []string) {
	cfg, err := parseServeArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid serve flags: %v\n", err)
		os.Exit(2)
	}

	l, err := listenUnixSocket(cfg.socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", cfg.socketPath, err)
		os.Exit(1)
	}
	defer l.Close()
	defer os.Remove(cfg.socketPath)

	idleTimer := time.NewTimer(time.Duration(cfg.idleMinutes) * time.Minute)
	defer idleTimer.Stop()

	fmt.Fprintf(os.Stderr, "explainerr daemon listening on %s\n", cfg.socketPath)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	for {
		l.SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-idleTimer.C:
					fmt.Fprintln(os.Stderr, "idle timeout reached, exiting")
					return
				default:
				}
				select {
				case <-sigc:
					fmt.Fprintln(os.Stderr, "signal received, exiting")
					return
				default:
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}
		resetTimer(idleTimer, time.Duration(cfg.idleMinutes)*time.Minute)
		go handleConn(conn)
	}
}

func listenUnixSocket(socketPath string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}

	if fi, err := os.Lstat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("path exists and is not a socket: %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	unixListener, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		return nil, errors.New("listener is not a unix listener")
	}
	_ = os.Chmod(socketPath, 0o600)
	return unixListener, nil
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "unix socket path")
	exitCode := fs.Int("exit", 1, "exit code")
	stderr := fs.String("stderr", "", "stderr snippet")
	cmdLine := fs.String("cmd", "", "command line")
	cwd := fs.String("cwd", "", "working directory")
	duration := fs.Int64("duration", 0, "duration ms")
	fs.Parse(args)

	ctx := detectRuntimeContext(*cwd)

	req := Request{
		Command:          *cmdLine,
		ExitCode:         *exitCode,
		StdErr:           *stderr,
		Cwd:              *cwd,
		OS:               ctx.OS,
		Distro:           ctx.Distro,
		Shell:            ctx.Shell,
		InRepo:           ctx.InRepo,
		InVenv:           ctx.InVenv,
		InContainer:      ctx.InContainer,
		PathEntries:      ctx.PathEntries,
		PathHasUsrBin:    ctx.PathHasUsrBin,
		Duration:         *duration,
		Timestamp:        time.Now().Unix(),
		ClientConfigHash: runtimeConfigHash(),
	}

	resp, err := sendRequest(*socket, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "explainerr send failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(maybeColor(resp.Message))
}

func detectRuntimeContext(cwd string) runtimeContext {
	resolvedCwd := strings.TrimSpace(cwd)
	if resolvedCwd == "" {
		if wd, err := os.Getwd(); err == nil {
			resolvedCwd = wd
		}
	}

	pathEntries, pathHasUsrBin := pathSummary(os.Getenv("PATH"))
	return runtimeContext{
		OS:            runtime.GOOS + "/" + runtime.GOARCH,
		Distro:        detectDistro(),
		Shell:         strings.TrimSpace(os.Getenv("SHELL")),
		InRepo:        isInsideRepo(resolvedCwd),
		InVenv:        inVirtualEnv(),
		InContainer:   inContainer(),
		PathEntries:   pathEntries,
		PathHasUsrBin: pathHasUsrBin,
	}
}

func detectDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		value := strings.TrimPrefix(line, "PRETTY_NAME=")
		value = strings.Trim(value, `"'`)
		return value
	}
	return ""
}

func inVirtualEnv() bool {
	return strings.TrimSpace(os.Getenv("VIRTUAL_ENV")) != "" || strings.TrimSpace(os.Getenv("CONDA_PREFIX")) != ""
}

func inContainer() bool {
	if strings.TrimSpace(os.Getenv("container")) != "" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	text := strings.ToLower(string(data))
	return strings.Contains(text, "docker") || strings.Contains(text, "kubepods") || strings.Contains(text, "containerd")
}

func isInsideRepo(cwd string) bool {
	dir := strings.TrimSpace(cwd)
	if dir == "" {
		return false
	}
	dir = filepath.Clean(dir)

	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

func pathSummary(pathEnv string) (entries int, hasUsrBin bool) {
	for _, item := range filepath.SplitList(pathEnv) {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		entries++
		if part == "/usr/bin" {
			hasUsrBin = true
		}
	}
	return entries, hasUsrBin
}

func sendRequest(socket string, req Request) (*Response, error) {
	c, err := net.DialTimeout("unix", socket, 300*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(clientConnDeadline())); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Error != "" {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(serverConnDeadline()))

	dec := json.NewDecoder(bufio.NewReader(conn))
	var req Request
	if err := dec.Decode(&req); err != nil {
		writeErr(conn, fmt.Sprintf("decode error: %v", err))
		return
	}

	if req.ClientConfigHash != "" && req.ClientConfigHash != runtimeConfigHash() {
		writeErr(conn, "daemon config mismatch")
		return
	}

	redactedReq := sanitizeRequestForLLM(req)

	if isTruthy(os.Getenv("EXPLAIN_DEBUG")) {
		fmt.Fprintf(os.Stderr, "[explainerr] request: %+v\n", redactedReq)
	}

	msg, usedLLM, err := explain(req)
	resp := Response{Message: msg, UsedLLM: usedLLM}
	if err != nil {
		resp.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func writeErr(w io.Writer, msg string) {
	_ = json.NewEncoder(w).Encode(Response{Error: msg})
}

func clientConnDeadline() time.Duration {
	sendTimeout := durationFromEnvMillis("EXPLAIN_SEND_TIMEOUT_MS", defaultSendDeadline)
	llmTimeout := durationFromEnvMillis("EXPLAIN_LLM_TIMEOUT_MS", defaultLLMTimeout)
	minRequired := llmTimeout + 1500*time.Millisecond
	if sendTimeout > minRequired {
		return sendTimeout
	}
	return minRequired
}

func serverConnDeadline() time.Duration {
	sendTimeout := durationFromEnvMillis("EXPLAIN_SEND_TIMEOUT_MS", defaultSendDeadline)
	llmTimeout := durationFromEnvMillis("EXPLAIN_LLM_TIMEOUT_MS", defaultLLMTimeout)
	minRequired := llmTimeout + time.Second
	if sendTimeout > minRequired {
		return sendTimeout
	}
	return minRequired
}

// explain runs heuristics and optionally an LLM call.
func explain(req Request) (string, bool, error) {
	heur := heuristic(req)

	key := os.Getenv("OPENAI_API_KEY")
	forceLLM := isTruthy(os.Getenv("EXPLAIN_FORCE_LLM"))

	if !shouldUseLLM(req, forceLLM) {
		return heur.Message, false, nil
	}

	// If no API key, return heuristic result but annotate absence.
	if key == "" {
		return heur.Message + " (LLM disabled: set OPENAI_API_KEY)", false, nil
	}

	cacheKey := llmCacheKey(req)
	if cached, ok := loadCachedLLM(cacheKey); ok {
		return cached, true, nil
	}
	if llmInFailureBackoff() {
		return heur.Message, false, nil
	}
	if !allowLLMCallNow() {
		return heur.Message, false, nil
	}

	llmMsg, err := llmCaller(key, req, heur)
	if err != nil {
		noteLLMFailure()
		if isTruthy(os.Getenv("EXPLAIN_DEBUG")) {
			fmt.Fprintf(os.Stderr, "[explainerr] LLM call failed: %v\n", err)
		}
		return heur.Message, false, nil
	}
	clearLLMFailureBackoff()
	if isLowValueLLMMessage(llmMsg) {
		return heur.Message, false, nil
	}
	storeCachedLLM(cacheKey, llmMsg)
	return llmMsg, true, nil
}

func shouldUseLLM(req Request, forceLLM bool) bool {
	if forceLLM {
		return true
	}
	if req.ExitCode == 0 {
		return false
	}
	return !isSelfExplainedByOutput(req)
}

func isSelfExplainedByOutput(req Request) bool {
	if hasCommandToken(req.Command, "--help") {
		return true
	}

	stderr := strings.ToLower(strings.TrimSpace(req.StdErr))
	if stderr == "" {
		return false
	}
	if strings.Contains(stderr, "usage:") {
		return true
	}
	if strings.Contains(stderr, "--help") || strings.Contains(stderr, "for help") {
		return true
	}
	if strings.Contains(stderr, "try '") || strings.Contains(stderr, "try \"") {
		return true
	}
	return false
}

func hasCommandToken(command, token string) bool {
	parts := strings.Fields(command)
	for _, part := range parts {
		if part == token || strings.HasPrefix(part, token+"=") {
			return true
		}
	}
	return false
}

func runtimeConfigHash() string {
	h := sha256.New()
	parts := runtimeConfigParts(responsesInstructions)
	for _, part := range parts {
		_, _ = io.WriteString(h, part)
		_, _ = io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func runtimeConfigParts(instructions string) []string {
	return []string{
		"version=" + runtimeConfigVersion,
		"prompt_schema_version=" + promptSchemaVersion,
		"instructions_sha256=" + textHash(instructions),
		"openai_api_key=" + os.Getenv("OPENAI_API_KEY"),
		"force_llm=" + os.Getenv("EXPLAIN_FORCE_LLM"),
		"mock_llm=" + os.Getenv("EXPLAIN_MOCK_LLM"),
		"model=" + effectiveModel(),
		"llm_timeout_ms=" + strconv.FormatInt(durationFromEnvMillis("EXPLAIN_LLM_TIMEOUT_MS", defaultLLMTimeout).Milliseconds(), 10),
		"llm_min_interval_ms=" + strconv.FormatInt(durationFromEnvMillis("EXPLAIN_LLM_MIN_INTERVAL_MS", defaultLLMMinInterval).Milliseconds(), 10),
		"llm_cache_ttl_ms=" + strconv.FormatInt(durationFromEnvMillis("EXPLAIN_LLM_CACHE_TTL_MS", defaultLLMCacheTTL).Milliseconds(), 10),
		"llm_failure_backoff_ms=" + strconv.FormatInt(durationFromEnvMillis("EXPLAIN_LLM_FAILURE_BACKOFF_MS", defaultLLMFailureBackoff).Milliseconds(), 10),
	}
}

func textHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func effectiveModel() string {
	model := strings.TrimSpace(os.Getenv("EXPLAIN_MODEL"))
	if model == "" {
		return defaultModel
	}
	return model
}

func llmCacheKey(req Request) string {
	h := sha256.New()
	_, _ = io.WriteString(h, strconv.Itoa(req.ExitCode))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strings.TrimSpace(req.Command))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, truncate(strings.TrimSpace(req.StdErr), 4096))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strings.TrimSpace(req.OS))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strings.TrimSpace(req.Distro))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strconv.FormatBool(req.InRepo))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strconv.FormatBool(req.InVenv))
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, strconv.FormatBool(req.InContainer))
	return hex.EncodeToString(h.Sum(nil))
}

func loadCachedLLM(key string) (string, bool) {
	now := time.Now()
	llmState.mu.Lock()
	defer llmState.mu.Unlock()

	for k, entry := range llmState.cache {
		if now.After(entry.expiresAt) {
			delete(llmState.cache, k)
		}
	}

	entry, ok := llmState.cache[key]
	if !ok || now.After(entry.expiresAt) {
		return "", false
	}
	return entry.message, true
}

func storeCachedLLM(key, message string) {
	now := time.Now()
	ttl := durationFromEnvMillis("EXPLAIN_LLM_CACHE_TTL_MS", defaultLLMCacheTTL)
	llmState.mu.Lock()
	defer llmState.mu.Unlock()

	for k, entry := range llmState.cache {
		if now.After(entry.expiresAt) {
			delete(llmState.cache, k)
		}
	}
	if len(llmState.cache) >= maxLLMCacheEntries {
		for k := range llmState.cache {
			delete(llmState.cache, k)
			break
		}
	}

	llmState.cache[key] = cachedLLMResult{
		message:   message,
		expiresAt: now.Add(ttl),
	}
}

func allowLLMCallNow() bool {
	now := time.Now()
	minInterval := durationFromEnvMillis("EXPLAIN_LLM_MIN_INTERVAL_MS", defaultLLMMinInterval)

	llmState.mu.Lock()
	defer llmState.mu.Unlock()
	if now.Sub(llmState.lastCall) < minInterval {
		return false
	}
	llmState.lastCall = now
	return true
}

func llmInFailureBackoff() bool {
	now := time.Now()
	llmState.mu.Lock()
	defer llmState.mu.Unlock()
	return now.Before(llmState.failureUntil)
}

func noteLLMFailure() {
	backoff := durationFromEnvMillis("EXPLAIN_LLM_FAILURE_BACKOFF_MS", defaultLLMFailureBackoff)
	until := time.Now().Add(backoff)

	llmState.mu.Lock()
	defer llmState.mu.Unlock()
	if until.After(llmState.failureUntil) {
		llmState.failureUntil = until
	}
}

func clearLLMFailureBackoff() {
	llmState.mu.Lock()
	defer llmState.mu.Unlock()
	llmState.failureUntil = time.Time{}
}

type heuristicResult struct {
	Message    string
	Confidence float64
}

func heuristic(req Request) heuristicResult {
	// Base message fallback
	msg := fmt.Sprintf("Command failed (exit %d).", req.ExitCode)
	conf := 0.2

	cmdLine := strings.TrimSpace(req.Command)
	cmdLower := strings.ToLower(cmdLine)
	stderr := strings.ToLower(req.StdErr)

	if cmdLower == "false" {
		return heuristicResult{Message: "The `false` command always exits with status 1; replace it with the real command you intended or `true` if this was a test.", Confidence: 0.95}
	}
	if req.ExitCode == 127 || strings.Contains(stderr, "command not found") {
		return heuristicResult{Message: "Command not found: check PATH or install the binary.", Confidence: 0.9}
	}
	if req.ExitCode == 126 || strings.Contains(stderr, "permission denied") {
		return heuristicResult{Message: "Permission denied: file exists but is not executable or lacks permissions.", Confidence: 0.85}
	}
	if strings.Contains(stderr, "no such file") || strings.Contains(stderr, "cannot stat") {
		return heuristicResult{Message: "Missing file or directory referenced by the command.", Confidence: 0.75}
	}
	if strings.Contains(stderr, "address already in use") {
		return heuristicResult{Message: "Port already in use: stop the other process or pick a new port.", Confidence: 0.9}
	}
	if strings.Contains(stderr, "connection refused") {
		return heuristicResult{Message: "Connection refused: target service not listening or blocked.", Confidence: 0.7}
	}
	if strings.Contains(stderr, "module not found") || strings.Contains(stderr, "cannot find module") {
		return heuristicResult{Message: "Module not found: install dependencies or fix import path.", Confidence: 0.8}
	}
	if strings.Contains(stderr, "syntax error") {
		return heuristicResult{Message: "Syntax error reported by the tool; check the referenced file and line.", Confidence: 0.7}
	}
	if strings.Contains(stderr, "killed") {
		return heuristicResult{Message: "Process killed (possibly OOM or signal). Check memory usage or limits.", Confidence: 0.6}
	}
	if req.ExitCode == 2 && (strings.Contains(stderr, "usage:") || strings.Contains(stderr, "try '") || strings.Contains(stderr, "try \"")) {
		return heuristicResult{Message: "Usage error: the command arguments are invalid or incomplete. Re-run with required args or --help.", Confidence: 0.85}
	}
	if req.ExitCode == 1 && strings.TrimSpace(req.StdErr) == "" && cmdLine != "" {
		return heuristicResult{
			Message:    fmt.Sprintf("`%s` exited with status 1 and no stderr; rerun with verbose/debug flags or inspect command-specific logs.", truncate(cmdLine, 80)),
			Confidence: 0.72,
		}
	}

	// Generic exit code hints
	switch req.ExitCode {
	case 130:
		return heuristicResult{Message: "Interrupted by user (SIGINT).", Confidence: 0.9}
	case 137, 139:
		return heuristicResult{Message: "Process terminated (likely OOM or segfault).", Confidence: 0.6}
	case 143:
		return heuristicResult{Message: "Process terminated by SIGTERM (maybe stop/restart).", Confidence: 0.6}
	}

	// Quick path existence check for simplest missing file messages.
	pathRe := regexp.MustCompile(`['\"]([^'\"]+)['\"]`)
	if matches := pathRe.FindStringSubmatch(req.StdErr); len(matches) == 2 {
		p := matches[1]
		if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "./") {
			if _, err := os.Stat(p); err != nil {
				return heuristicResult{Message: fmt.Sprintf("Path appears missing: %s", p), Confidence: 0.55}
			}
		}
	}

	return heuristicResult{Message: msg, Confidence: conf}
}

// callLLM sends a short prompt to OpenAI if available.
func callLLM(apiKey string, req Request, heur heuristicResult) (string, error) {
	safeReq := sanitizeRequestForLLM(req)

	// Optional mock path for offline/testing environments.
	if isTruthy(os.Getenv("EXPLAIN_MOCK_LLM")) {
		return mockLLM(safeReq, heur), nil
	}

	prompt := buildPrompt(safeReq, heur)

	if isTruthy(os.Getenv("EXPLAIN_DEBUG")) {
		fmt.Fprintf(os.Stderr, "[explainerr] LLM instructions sha256: %s\n", textHash(responsesInstructions))
		fmt.Fprintf(os.Stderr, "[explainerr] LLM prompt:\n%s\n", prompt)
	}

	payload := responsesRequest{
		Model:           effectiveModel(),
		Instructions:    responsesInstructions,
		Input:           prompt,
		MaxOutputTokens: 90,
		Temperature:     0.0,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), durationFromEnvMillis("EXPLAIN_LLM_TIMEOUT_MS", defaultLLMTimeout))
	defer cancel()

	reqHTTP, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/responses", strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("openai error: %s", strings.TrimSpace(string(data)))
	}

	var out responsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}

	msg := extractResponseText(out)
	if msg == "" {
		return "", errors.New("empty response output")
	}
	return msg, nil
}

func durationFromEnvMillis(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 200 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

func sanitizeRequestForLLM(req Request) Request {
	req.Command = redactSensitiveText(req.Command)
	req.StdErr = redactSensitiveText(req.StdErr)
	req.Cwd = cwdTail(req.Cwd, 2)
	if shell := strings.TrimSpace(req.Shell); shell != "" {
		req.Shell = filepath.Base(shell)
	}
	return req
}

func redactSensitiveText(input string) string {
	redacted := input
	for _, entry := range sensitivePatterns {
		redacted = entry.pattern.ReplaceAllString(redacted, entry.replace)
	}
	return redacted
}

func extractResponseText(resp responsesResponse) string {
	if msg := strings.TrimSpace(resp.OutputText); msg != "" {
		return msg
	}

	var parts []string
	for _, item := range resp.Output {
		for _, content := range item.Content {
			if content.Type != "output_text" {
				continue
			}
			if text := strings.TrimSpace(content.Text); text != "" {
				parts = append(parts, text)
			}
		}
	}

	return strings.TrimSpace(strings.Join(parts, " "))
}

func buildPrompt(req Request, heur heuristicResult) string {
	outputErr := strings.TrimSpace(truncate(req.StdErr, 1200))
	if outputErr == "" {
		outputErr = "<empty>"
	}

	payload := map[string]any{
		"command":      strings.TrimSpace(req.Command),
		"exit_code":    req.ExitCode,
		"cwd":          cwdTail(req.Cwd, 2),
		"output_error": outputErr,
		"environment": map[string]any{
			"os":               strings.TrimSpace(req.OS),
			"distro":           strings.TrimSpace(req.Distro),
			"shell":            strings.TrimSpace(req.Shell),
			"in_repo":          req.InRepo,
			"in_venv":          req.InVenv,
			"in_container":     req.InContainer,
			"path_entries":     req.PathEntries,
			"path_has_usr_bin": req.PathHasUsrBin,
		},
	}
	if heur.Message != "" {
		payload["heuristic_hint"] = strings.TrimSpace(heur.Message)
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("INPUT_JSON:\n{\"command\":%q,\"exit_code\":%d}", strings.TrimSpace(req.Command), req.ExitCode)
	}
	return "INPUT_JSON:\n" + string(b)
}

func cwdTail(path string, elems int) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if elems < 1 {
		elems = 1
	}

	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) <= elems {
		return clean
	}
	return strings.Join(parts[len(parts)-elems:], string(filepath.Separator))
}

func isLowValueLLMMessage(msg string) bool {
	m := strings.ToLower(strings.TrimSpace(msg))
	if m == "" {
		return true
	}
	if strings.Contains(m, "non-zero exit code") || strings.Contains(m, "returned a non-zero") {
		return true
	}
	if strings.HasPrefix(m, "the command failed because") {
		return true
	}
	if strings.Contains(m, "ensure the command") && strings.Contains(m, "does not fail") {
		return true
	}
	if strings.Contains(m, "make sure") && strings.Contains(m, "does not fail") {
		return true
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// isTruthy treats common true-ish values as true.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// maybeColor wraps message in green if EXPLAIN_COLOR is not disabled.
func maybeColor(msg string) string {
	if msg == "" {
		return msg
	}
	disable := strings.ToLower(strings.TrimSpace(os.Getenv("EXPLAIN_COLOR")))
	if disable == "0" || disable == "off" || disable == "false" || disable == "no" {
		return msg
	}
	const green = "\033[32m"
	const reset = "\033[0m"
	return green + msg + reset
}

// mockLLM returns a concise synthetic message for offline testing.
func mockLLM(req Request, heur heuristicResult) string {
	stderr := strings.TrimSpace(req.StdErr)
	if stderr != "" {
		if idx := strings.Index(stderr, "\n"); idx > 0 {
			stderr = stderr[:idx]
		}
	}
	var parts []string
	if heur.Message != "" {
		parts = append(parts, heur.Message)
	}
	if stderr != "" {
		parts = append(parts, stderr)
	}
	if len(parts) == 0 {
		return "Command failed; no stderr captured."
	}
	return strings.Join(parts, " — ")
}
