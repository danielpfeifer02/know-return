# explainerr (MVP)

Tiny background helper that watches failed shell commands and prints a quick explanation using heuristics plus an optional OpenAI call.

## Build

```bash
GOCACHE=/tmp/go-cache go build -o explain ./cmd/explain
```

## Quick start

For bash or zsh (preferred):

```bash
source scripts/start_explain.sh
```

For fish:

```fish
source scripts/start_explain.fish
```

This builds the binary, starts the daemon, and installs hooks in your current shell.

## Shell hook setup (per shell session)

```bash
source scripts/explain_init.sh
```

For fish:

```fish
source scripts/explain_init.fish
```

`scripts/explain_init.sh` detects bash vs zsh and loads the correct hook automatically.

What it does:
- Captures command context and exit code, then sends JSON to a local daemon over `/tmp/explainerr.sock`.
- Bash and zsh also capture stderr tail from the failed command and include it in the request.
- Auto-starts the daemon if the socket is missing, and retries once if a stale socket is detected.
- Preserves original command exit status (`$?`) after explanation output.

Environment knobs (override before sourcing):
- `EXPLAIN_BIN` path to the built binary (defaults to `explain` in PATH or `./explain`).
- `EXPLAIN_SOCK` unix socket path (default `/tmp/explainerr.sock`).
- `EXPLAIN_LOG` stderr log file (default `/tmp/explainerr-stderr-$PPID.log`).
- `EXPLAIN_MAX_BYTES` stderr bytes to send (default 4096).
- `EXPLAIN_IDLE_MINUTES` daemon idle shutdown (default 30).
- `EXPLAIN_FORCE_LLM` set to `1/true/on/yes` to always use the LLM (requires `OPENAI_API_KEY`).
- `EXPLAIN_COLOR` disable color by setting `0/false/off/no` (default is green output).
- `EXPLAIN_DEBUG` set to `1/true/on/yes` to log daemon requests/prompts; daemon logs to `${EXPLAIN_DAEMON_LOG:-/tmp/explainerr-daemon.log}`.
- `EXPLAIN_MOCK_LLM` set to `1/true/on/yes` to bypass real API calls and return a concise synthetic explanation (handy when offline).
- `EXPLAIN_MODEL` OpenAI model for LLM fallback (default `gpt-4o-mini`).
- `EXPLAIN_SHELL` override shell detection in `scripts/explain_init.sh` (`bash` or `zsh`).

## OpenAI

Set `OPENAI_API_KEY` in your env to let the daemon use the LLM fallback. Without it, heuristics-only messages are shown.

LLM requests use the OpenAI Responses API (`POST /v1/responses`).

## CLI usage

```bash
# start daemon (defaults shown)
./explain serve -socket /tmp/explainerr.sock -idle-minutes 30

# send one request
./explain send -socket /tmp/explainerr.sock -exit 2 -cmd "grep -l" -stderr "usage: grep ..."
```

## Notes / Caveats
- Bash, zsh, and fish are supported; fish currently sends command/exit metadata but not stderr tail snippets.
- Bash/zsh stderr redirection is session-wide; avoid sourcing in shells where that is undesirable.
- The daemon is intentionally minimal and runs entirely locally except the optional OpenAI call.
- Hooks only run in interactive shells. If you sourced successfully but see no output, check `echo "$-"` contains `i`.
