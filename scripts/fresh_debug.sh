#!/usr/bin/env bash
# Convenience helper to start a clean explainerr session with debug logging.
# Usage: source scripts/fresh_debug.sh

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "Please source this script: source ${BASH_SOURCE[0]}" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export EXPLAIN_BIN="$repo_root/explain"
export EXPLAIN_SOCK="${EXPLAIN_SOCK:-/tmp/explainerr.sock}"
export EXPLAIN_DAEMON_LOG="${EXPLAIN_DAEMON_LOG:-/tmp/explainerr-daemon.log}"
export EXPLAIN_DEBUG=1
export EXPLAIN_FORCE_LLM="${EXPLAIN_FORCE_LLM:-}"

echo "[fresh_debug] Building binary at $EXPLAIN_BIN"
GOCACHE=/tmp/go-cache go build -o "$EXPLAIN_BIN" ./cmd/explain || { echo "[fresh_debug] build failed"; return 1; }

echo "[fresh_debug] Removing old socket $EXPLAIN_SOCK"
rm -f "$EXPLAIN_SOCK"

echo "[fresh_debug] Daemon log: $EXPLAIN_DAEMON_LOG"

echo "[fresh_debug] Sourcing hook"
source "$repo_root/scripts/explain_init.sh"

echo "[fresh_debug] Ready. Run a failing command (e.g., 'grep -l'); prompts and requests will log to $EXPLAIN_DAEMON_LOG."
