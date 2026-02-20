#!/usr/bin/env bash
# Bash hook for explainerr.
# Captures stderr for each command and, on non-zero exit, sends context to the daemon.

EXPLAIN_SOCK="${EXPLAIN_SOCK:-/tmp/explainerr.sock}"
EXPLAIN_BIN="${EXPLAIN_BIN:-$(command -v explain 2>/dev/null || command -v ./explain 2>/dev/null)}"
EXPLAIN_LOG="${EXPLAIN_LOG:-/tmp/explainerr-stderr-$PPID.log}"
EXPLAIN_MAX_BYTES="${EXPLAIN_MAX_BYTES:-4096}"
EXPLAIN_IDLE_MINUTES="${EXPLAIN_IDLE_MINUTES:-30}"

# DEBUG traps are only inherited into sourced scripts when functrace is enabled.
# Bootstrap one re-source with functrace so we can preserve an existing DEBUG trap.
if [[ -n "${BASH_VERSION:-}" && "${EXPLAIN_FTRACE_BOOTSTRAP:-0}" != "1" && "$-" != *T* ]]; then
  set -o functrace
  EXPLAIN_FTRACE_BOOTSTRAP=1 source "${BASH_SOURCE[0]}"
  explain_bootstrap_rc=$?
  set +o functrace
  unset EXPLAIN_FTRACE_BOOTSTRAP
  return "$explain_bootstrap_rc"
fi

if [[ -n "${EXPLAIN_HOOK_INSTALLED_BASH:-}" ]]; then
  return 0
fi

if [[ -z "$EXPLAIN_BIN" ]]; then
  echo "explain binary not found. Build with: go build -o explain ./cmd/explain" >&2
  return 0
fi

explain_is_truthy() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if ! touch "$EXPLAIN_LOG" 2>/dev/null; then
  echo "explain log is not writable: $EXPLAIN_LOG" >&2
  return 0
fi

# Keep compatibility with historical typo EXPLAIN_STERR_REDIRECTED.
if [[ -z "${EXPLAIN_STDERR_REDIRECTED:-${EXPLAIN_STERR_REDIRECTED:-}}" ]]; then
  export EXPLAIN_STDERR_REDIRECTED=1
  export EXPLAIN_STERR_REDIRECTED=1
  exec 3>&2 2> >(tee -a "$EXPLAIN_LOG" >&3)
fi

explain_maybe_start_daemon() {
  if [[ -S "$EXPLAIN_SOCK" ]]; then
    return 0
  fi

  local daemon_pid
  if explain_is_truthy "${EXPLAIN_DEBUG:-}"; then
    local log_file="${EXPLAIN_DAEMON_LOG:-/tmp/explainerr-daemon.log}"
    echo "[explainerr] starting daemon with debug; logs at $log_file" >&2
    EXPLAIN_DEBUG=1 "$EXPLAIN_BIN" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >"$log_file" 2>&1 &
    daemon_pid=$!
  else
    "$EXPLAIN_BIN" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >/dev/null 2>&1 &
    daemon_pid=$!
  fi
  disown "$daemon_pid" 2>/dev/null || true

  explain_wait_for_socket
}

explain_wait_for_socket() {
  local i
  for i in {1..20}; do
    [[ -S "$EXPLAIN_SOCK" ]] && return 0
    sleep 0.05
  done
  return 1
}

explain_send_with_retry() {
  "$EXPLAIN_BIN" send \
    -socket "$EXPLAIN_SOCK" \
    -exit "$1" \
    -stderr "$2" \
    -cmd "$3" \
    -cwd "$4" \
    -duration "$5" && return 0

  rm -f "$EXPLAIN_SOCK"
  explain_maybe_start_daemon

  explain_wait_for_socket || return 1

  "$EXPLAIN_BIN" send \
    -socket "$EXPLAIN_SOCK" \
    -exit "$1" \
    -stderr "$2" \
    -cmd "$3" \
    -cwd "$4" \
    -duration "$5"
}

explain_preexec() {
  if [[ "${EXPLAIN_IN_PROMPT:-0}" == "1" ]]; then
    return
  fi

  case "$BASH_COMMAND" in
    explain_precmd*|explain_preexec*|explain_maybe_start_daemon*|explain_send_with_retry*) return ;;
  esac

  EXPLAIN_ERR_START=$(wc -c <"$EXPLAIN_LOG" 2>/dev/null || echo 0)
  EXPLAIN_CMD_LINE=${BASH_COMMAND}
  EXPLAIN_CMD_START_MS=$(date +%s%3N 2>/dev/null || date +%s000)
}

explain_debug_trap_wrapper() {
  if [[ "${EXPLAIN_IN_DEBUG_TRAP:-0}" == "1" ]]; then
    return
  fi
  EXPLAIN_IN_DEBUG_TRAP=1

  explain_preexec
  if [[ -n "${EXPLAIN_PREV_DEBUG_TRAP:-}" ]]; then
    builtin eval -- "$EXPLAIN_PREV_DEBUG_TRAP"
  fi

  EXPLAIN_IN_DEBUG_TRAP=0
}

explain_precmd() {
  local exit_code=$?
  EXPLAIN_IN_PROMPT=1
  if [[ $exit_code -eq 0 ]]; then
    EXPLAIN_IN_PROMPT=0
    return "$exit_code"
  fi

  local start_bytes="${EXPLAIN_ERR_START:-0}"
  local slice_start=$((start_bytes + 1))
  if (( slice_start < 1 )); then
    slice_start=1
  fi

  local stderr_snip
  stderr_snip=$(tail -c +"$slice_start" "$EXPLAIN_LOG" 2>/dev/null | tail -c "$EXPLAIN_MAX_BYTES")

  local now_ms
  now_ms=$(date +%s%3N 2>/dev/null || date +%s000)
  local cmd_start_ms="${EXPLAIN_CMD_START_MS:-$now_ms}"
  local dur_ms=$((now_ms - cmd_start_ms))

  explain_maybe_start_daemon
  if ! explain_send_with_retry "$exit_code" "$stderr_snip" "${EXPLAIN_CMD_LINE:-}" "$PWD" "$dur_ms"; then
    if explain_is_truthy "${EXPLAIN_DEBUG:-}"; then
      echo "[explainerr] failed to send request" >&2
    elif [[ -z "${EXPLAIN_WARNED_SEND_FAIL:-}" ]]; then
      EXPLAIN_WARNED_SEND_FAIL=1
      echo "[explainerr] unable to reach daemon; re-source scripts/start_explain.sh or set EXPLAIN_DEBUG=1" >&2
    fi
  fi

  EXPLAIN_IN_PROMPT=0
  return "$exit_code"
}

if [[ -n "${BASH_VERSION:-}" ]]; then
  EXPLAIN_HOOK_INSTALLED_BASH=1
  explain_maybe_start_daemon

  EXPLAIN_PREV_DEBUG_TRAP=""
  explain_prev_trap_line=""
  explain_prev_trap_file="/tmp/explainerr-prev-debug-trap-$$.txt"
  trap -p DEBUG >"$explain_prev_trap_file" 2>/dev/null || true
  if [[ -s "$explain_prev_trap_file" ]]; then
    IFS= read -r explain_prev_trap_line <"$explain_prev_trap_file"
  fi
  if [[ -n "$explain_prev_trap_line" ]]; then
    explain_prev_debug_candidate="${explain_prev_trap_line#trap -- \'}"
    explain_prev_debug_candidate="${explain_prev_debug_candidate%\' DEBUG}"
    if [[ "$explain_prev_debug_candidate" != "$explain_prev_trap_line" ]]; then
      EXPLAIN_PREV_DEBUG_TRAP="$explain_prev_debug_candidate"
    fi
  fi
  if [[ -n "$EXPLAIN_PREV_DEBUG_TRAP" ]]; then
    if [[ "$EXPLAIN_PREV_DEBUG_TRAP" == "explain_debug_trap_wrapper" ]] || [[ "$EXPLAIN_PREV_DEBUG_TRAP" == "explain_preexec" ]]; then
      EXPLAIN_PREV_DEBUG_TRAP=""
    fi
  fi
  rm -f "$explain_prev_trap_file"
  unset explain_prev_trap_line explain_prev_debug_candidate explain_prev_trap_file

  trap 'explain_debug_trap_wrapper' DEBUG
  if declare -p PROMPT_COMMAND >/dev/null 2>&1 && [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == declare\ -a* ]]; then
    explain_has_precmd=0
    for explain_cmd in "${PROMPT_COMMAND[@]}"; do
      if [[ "$explain_cmd" == "explain_precmd" ]]; then
        explain_has_precmd=1
        break
      fi
    done
    if [[ "$explain_has_precmd" -eq 0 ]]; then
      PROMPT_COMMAND=("explain_precmd" "${PROMPT_COMMAND[@]}")
    fi
    unset explain_has_precmd explain_cmd
  else
    case "${PROMPT_COMMAND:-}" in
      *explain_precmd*) ;;
      *) PROMPT_COMMAND="explain_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
  fi
fi
