#!/usr/bin/env bash
# Build explainerr and initialize shell hooks.
# Preferred usage (installs hooks in current shell):
#   source scripts/start_explain.sh
# If executed directly, it only starts the daemon and prints next steps.

__explain_sourced=0
if [[ -n "${BASH_VERSION:-}" && "${BASH_SOURCE[0]}" != "$0" ]]; then
  __explain_sourced=1
elif [[ -n "${ZSH_VERSION:-}" && "${(%):-%N}" != "$0" ]]; then
  __explain_sourced=1
fi

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  __explain_script_path="${BASH_SOURCE[0]}"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
  __explain_script_path="${(%):-%N}"
else
  __explain_script_path="$0"
fi

__explain_repo_root="$(cd "$(dirname "$__explain_script_path")/.." && pwd)"
__explain_bin="$__explain_repo_root/explain"
__explain_sock="${EXPLAIN_SOCK:-/tmp/explainerr.sock}"
__explain_idle="${EXPLAIN_IDLE_MINUTES:-30}"

if ! GOCACHE=/tmp/go-cache go build -o "$__explain_bin" "$__explain_repo_root/cmd/explain"; then
  echo "[start_explain] build failed" >&2
  [[ "$__explain_sourced" -eq 1 ]] && return 1 || exit 1
fi

if [[ -e "$__explain_sock" && ! -S "$__explain_sock" ]]; then
  rm -f "$__explain_sock"
fi

if [[ ! -S "$__explain_sock" ]]; then
  if [[ "${EXPLAIN_DEBUG:-}" =~ ^([Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]|1)$ ]]; then
    __explain_log="${EXPLAIN_DAEMON_LOG:-/tmp/explainerr-daemon.log}"
    EXPLAIN_DEBUG=1 "$__explain_bin" serve -socket "$__explain_sock" -idle-minutes "$__explain_idle" >"$__explain_log" 2>&1 &
  else
    "$__explain_bin" serve -socket "$__explain_sock" -idle-minutes "$__explain_idle" >/dev/null 2>&1 &
  fi
  for _i in {1..20}; do
    [[ -S "$__explain_sock" ]] && break
    sleep 0.05
  done
fi

if [[ ! -S "$__explain_sock" ]]; then
  echo "[start_explain] warning: daemon socket was not created at $__explain_sock" >&2
fi

if [[ "$__explain_sourced" -eq 0 ]]; then
  if [[ -S "$__explain_sock" ]]; then
    echo "[start_explain] daemon is up (socket: $__explain_sock)."
  else
    echo "[start_explain] daemon may not be running (no socket at $__explain_sock)." >&2
  fi
  echo "[start_explain] to enable command-failure hooks in your current shell, run:"
  echo "  source $__explain_repo_root/scripts/start_explain.sh"
  exit 0
fi

export EXPLAIN_BIN="$__explain_bin"
export EXPLAIN_SOCK="$__explain_sock"
source "$__explain_repo_root/scripts/explain_init.sh"

echo "[start_explain] ready in current shell. Try: definitely-not-a-real-command"

echo '[start_explain] if no output appears, confirm this is an interactive shell with: echo "$-"'

unset __explain_sourced __explain_script_path __explain_repo_root __explain_bin __explain_sock __explain_idle __explain_log
