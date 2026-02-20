#!/usr/bin/env fish
# fish hook for explainerr.
# fish does not use the same stderr redirection trick as bash/zsh, so stderr snippets may be empty.

if set -q EXPLAIN_HOOK_INSTALLED_FISH
    return 0
end

if not set -q EXPLAIN_SOCK
    set -gx EXPLAIN_SOCK /tmp/explainerr.sock
end

if not set -q EXPLAIN_BIN
    set -l resolved_bin (command -v explain 2>/dev/null)
    if test -z "$resolved_bin"
        set resolved_bin (command -v ./explain 2>/dev/null)
    end
    set -gx EXPLAIN_BIN "$resolved_bin"
end

if not set -q EXPLAIN_IDLE_MINUTES
    set -gx EXPLAIN_IDLE_MINUTES 30
end

if not set -q EXPLAIN_LOG
    set -gx EXPLAIN_LOG "/tmp/explainerr-stderr-$fish_pid.log"
end

if test -z "$EXPLAIN_BIN"
    echo "explain binary not found. Build with: go build -o explain ./cmd/explain" >&2
    return 0
end

function __explain_is_truthy
    set -l value (string lower -- "$argv[1]")
    switch "$value"
        case 1 true yes on
            return 0
        case '*'
            return 1
    end
end

function __explain_maybe_start_daemon
    if test -S "$EXPLAIN_SOCK"
        return 0
    end

    if __explain_is_truthy "$EXPLAIN_DEBUG"
        set -l log_file /tmp/explainerr-daemon.log
        if set -q EXPLAIN_DAEMON_LOG
            set log_file "$EXPLAIN_DAEMON_LOG"
        end
        echo "[explainerr] starting daemon with debug; logs at $log_file" >&2
        env EXPLAIN_DEBUG=1 "$EXPLAIN_BIN" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >"$log_file" 2>&1 &
        disown $last_pid 2>/dev/null
    else
        "$EXPLAIN_BIN" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >/dev/null 2>&1 &
        disown $last_pid 2>/dev/null
    end

    __explain_wait_for_socket
end

function __explain_wait_for_socket
    for _i in (seq 1 20)
        if test -S "$EXPLAIN_SOCK"
            return 0
        end
        sleep 0.05
    end
    return 1
end

function __explain_send_with_retry
    "$EXPLAIN_BIN" send \
        -socket "$EXPLAIN_SOCK" \
        -exit "$argv[1]" \
        -stderr "$argv[2]" \
        -cmd "$argv[3]" \
        -cwd "$argv[4]" \
        -duration "$argv[5]"
    if test $status -eq 0
        return 0
    end

    rm -f "$EXPLAIN_SOCK"
    __explain_maybe_start_daemon

    __explain_wait_for_socket; or return 1

    "$EXPLAIN_BIN" send \
        -socket "$EXPLAIN_SOCK" \
        -exit "$argv[1]" \
        -stderr "$argv[2]" \
        -cmd "$argv[3]" \
        -cwd "$argv[4]" \
        -duration "$argv[5]"
end

function __explain_preexec --on-event fish_preexec
    set -gx EXPLAIN_CMD_LINE "$argv"
    set -gx EXPLAIN_CMD_START_MS (date +%s%3N 2>/dev/null; or date +%s000)
end

function __explain_postexec --on-event fish_postexec
    set -l exit_code $status
    if test $exit_code -eq 0
        return 0
    end

    set -l now_ms (date +%s%3N 2>/dev/null; or date +%s000)
    set -l cmd_start_ms "$EXPLAIN_CMD_START_MS"
    if test -z "$cmd_start_ms"
        set cmd_start_ms "$now_ms"
    end
    set -l dur_ms (math "$now_ms - $cmd_start_ms")

    __explain_maybe_start_daemon
    __explain_send_with_retry "$exit_code" "" "$EXPLAIN_CMD_LINE" "$PWD" "$dur_ms"
    if test $status -ne 0
        if __explain_is_truthy "$EXPLAIN_DEBUG"
            echo "[explainerr] failed to send request" >&2
        else if not set -q EXPLAIN_WARNED_SEND_FAIL
            set -gx EXPLAIN_WARNED_SEND_FAIL 1
            echo "[explainerr] unable to reach daemon; re-source scripts/start_explain.fish or set EXPLAIN_DEBUG=1" >&2
        end
    end

    return $exit_code
end

set -gx EXPLAIN_HOOK_INSTALLED_FISH 1
__explain_maybe_start_daemon
