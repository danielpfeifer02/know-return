#!/usr/bin/env bash
# Source this file from bash or zsh to install the correct explainerr hook.

if [[ -n "${BASH_VERSION:-}" ]]; then
  __explain_script_path="${BASH_SOURCE[0]}"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
  __explain_script_path="${(%):-%N}"
else
  __explain_script_path="$0"
fi

__explain_repo_root="$(cd "$(dirname "$__explain_script_path")/.." && pwd)"

if [[ -z "${EXPLAIN_BIN:-}" && -x "$__explain_repo_root/explain" ]]; then
  export EXPLAIN_BIN="$__explain_repo_root/explain"
fi

__explain_detect_shell() {
  if [[ -n "${BASH_VERSION:-}" ]]; then
    echo "bash"
    return
  fi
  if [[ -n "${ZSH_VERSION:-}" ]]; then
    echo "zsh"
    return
  fi

  local parent_shell
  parent_shell="$(ps -p "$PPID" -o comm= 2>/dev/null | tr -d '[:space:]')"
  case "$parent_shell" in
    *bash) echo "bash" ; return ;;
    *zsh) echo "zsh" ; return ;;
    *fish) echo "fish" ; return ;;
  esac

  case "$(basename "${SHELL:-}")" in
    bash|zsh|fish) basename "${SHELL:-}" ;;
    *) echo "unknown" ;;
  esac
}

__explain_shell="${EXPLAIN_SHELL:-$(__explain_detect_shell)}"

case "$__explain_shell" in
  bash)
    source "$__explain_repo_root/scripts/explain_hook.sh"
    ;;
  zsh)
    source "$__explain_repo_root/scripts/explain_hook.zsh"
    ;;
  fish)
    echo "fish detected; run: source $__explain_repo_root/scripts/explain_init.fish" >&2
    ;;
  *)
    echo "Unsupported shell. Use bash, zsh, or fish. Detected: $__explain_shell" >&2
    ;;
esac

unset __explain_repo_root __explain_shell __explain_script_path
unset -f __explain_detect_shell 2>/dev/null || true
