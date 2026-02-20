#!/usr/bin/env bash
# Full reset + activation for explainerr.
# Preferred usage: source scripts/activate_explain.sh

if [[ -n "${BASH_VERSION:-}" && "${BASH_SOURCE[0]}" != "$0" ]]; then
  __explain_sourced=1
elif [[ -n "${ZSH_VERSION:-}" && "${(%):-%N}" != "$0" ]]; then
  __explain_sourced=1
else
  __explain_sourced=0
fi

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  __explain_script_path="${BASH_SOURCE[0]}"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
  __explain_script_path="${(%):-%N}"
else
  __explain_script_path="$0"
fi

__explain_repo_root="$(cd "$(dirname "$__explain_script_path")/.." && pwd)"
__explain_sock="${EXPLAIN_SOCK:-/tmp/explainerr.sock}"
__explain_daemon_log="${EXPLAIN_DAEMON_LOG:-/tmp/explainerr-daemon.log}"
__explain_bin="$__explain_repo_root/explain"

__explain_reset_shell_state() {
  if [[ "$__explain_sourced" -ne 1 ]]; then
    return 0
  fi

  if [[ -n "${BASH_VERSION:-}" ]]; then
    if [[ -n "${EXPLAIN_STDERR_REDIRECTED:-${EXPLAIN_STERR_REDIRECTED:-}}" ]]; then
      exec 2>&3 3>&- 2>/dev/null || true
    fi

    if trap -p DEBUG 2>/dev/null | grep -q "explain_debug_trap_wrapper"; then
      if [[ -n "${EXPLAIN_PREV_DEBUG_TRAP:-}" ]]; then
        trap -- "$EXPLAIN_PREV_DEBUG_TRAP" DEBUG
      else
        trap - DEBUG
      fi
    fi

    if declare -p PROMPT_COMMAND >/dev/null 2>&1 && [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == declare\ -a* ]]; then
      __explain_new_prompt_cmd=()
      for __explain_cmd in "${PROMPT_COMMAND[@]}"; do
        [[ "$__explain_cmd" == "explain_precmd" ]] && continue
        __explain_new_prompt_cmd+=("$__explain_cmd")
      done
      PROMPT_COMMAND=("${__explain_new_prompt_cmd[@]}")
      unset __explain_new_prompt_cmd __explain_cmd
    else
      __explain_prompt_cmd="${PROMPT_COMMAND:-}"
      __explain_prompt_cmd="${__explain_prompt_cmd//explain_precmd;}"
      __explain_prompt_cmd="${__explain_prompt_cmd//;explain_precmd/}"
      __explain_prompt_cmd="${__explain_prompt_cmd//explain_precmd/}"
      PROMPT_COMMAND="$__explain_prompt_cmd"
      unset __explain_prompt_cmd
    fi

    unset EXPLAIN_HOOK_INSTALLED_BASH EXPLAIN_IN_PROMPT EXPLAIN_IN_DEBUG_TRAP EXPLAIN_PREV_DEBUG_TRAP
    unset EXPLAIN_WARNED_SEND_FAIL EXPLAIN_STDERR_REDIRECTED EXPLAIN_STERR_REDIRECTED
  elif [[ -n "${ZSH_VERSION:-}" ]]; then
    if [[ -n "${EXPLAIN_STDERR_REDIRECTED:-}" ]]; then
      exec 2>&3 3>&- 2>/dev/null || true
    fi
    if typeset -f add-zsh-hook >/dev/null 2>&1; then
      add-zsh-hook -D preexec explain_preexec 2>/dev/null || true
      add-zsh-hook -D precmd explain_precmd 2>/dev/null || true
    fi

    unset EXPLAIN_HOOK_INSTALLED_ZSH EXPLAIN_STDERR_REDIRECTED EXPLAIN_WARNED_SEND_FAIL
    unset EXPLAIN_CMD_LINE EXPLAIN_CMD_START_MS EXPLAIN_ERR_START
  fi
}

__explain_stop_daemons() {
  if command -v pkill >/dev/null 2>&1; then
    pkill -f -- "$__explain_bin serve" 2>/dev/null || true
  elif command -v pgrep >/dev/null 2>&1; then
    while read -r __explain_pid; do
      [[ -n "$__explain_pid" ]] || continue
      kill "$__explain_pid" 2>/dev/null || true
    done < <(pgrep -f "$__explain_bin serve" 2>/dev/null || true)
  fi
}

__explain_cleanup_files() {
  rm -f "$__explain_sock"

  if [[ -z "${EXPLAIN_KEEP_LOGS:-}" ]]; then
    rm -f "$__explain_daemon_log"
    if [[ -n "${EXPLAIN_LOG:-}" ]]; then
      rm -f "$EXPLAIN_LOG"
    fi
  fi
}

__explain_reset_shell_state
__explain_stop_daemons
__explain_cleanup_files

if [[ "$__explain_sourced" -eq 1 ]]; then
  source "$__explain_repo_root/scripts/start_explain.sh"
  return $?
fi

"$__explain_repo_root/scripts/start_explain.sh"
exit $?
