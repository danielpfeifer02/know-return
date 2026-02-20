#!/usr/bin/env fish
# Full reset + activation for explainerr.
# Preferred usage: source scripts/activate_explain.fish

set -l repo_root (cd (dirname (status filename))/..; pwd)
set -l explain_bin "$repo_root/explain"

set -l explain_sock /tmp/explainerr.sock
if set -q EXPLAIN_SOCK
    set explain_sock "$EXPLAIN_SOCK"
end

set -l daemon_log /tmp/explainerr-daemon.log
if set -q EXPLAIN_DAEMON_LOG
    set daemon_log "$EXPLAIN_DAEMON_LOG"
end

# Best-effort reset of previously installed fish hook state.
functions -e __explain_preexec __explain_postexec __explain_send_with_retry __explain_wait_for_socket __explain_maybe_start_daemon __explain_is_truthy 2>/dev/null
set -e EXPLAIN_HOOK_INSTALLED_FISH EXPLAIN_WARNED_SEND_FAIL EXPLAIN_CMD_LINE EXPLAIN_CMD_START_MS

if command -q pgrep
    for pid in (pgrep -f "$explain_bin serve" 2>/dev/null)
        kill $pid 2>/dev/null
    end
end

rm -f "$explain_sock"
if not set -q EXPLAIN_KEEP_LOGS
    rm -f "$daemon_log"
    if set -q EXPLAIN_LOG
        rm -f "$EXPLAIN_LOG"
    end
end

source "$repo_root/scripts/start_explain.fish"
