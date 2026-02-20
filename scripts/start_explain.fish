#!/usr/bin/env fish
# Build explainerr and initialize fish hooks in current shell.
# Usage:
#   source scripts/start_explain.fish

if test (status filename) = ""
    echo "[start_explain] source this script from fish: source scripts/start_explain.fish" >&2
    exit 1
end

set -l repo_root (cd (dirname (status filename))/..; pwd)
set -l explain_bin "$repo_root/explain"

if not set -q EXPLAIN_SOCK
    set -gx EXPLAIN_SOCK /tmp/explainerr.sock
end
if not set -q EXPLAIN_IDLE_MINUTES
    set -gx EXPLAIN_IDLE_MINUTES 30
end

if not GOCACHE=/tmp/go-cache go build -o "$explain_bin" "$repo_root/cmd/explain"
    echo "[start_explain] build failed" >&2
    return 1
end

if test -e "$EXPLAIN_SOCK"; and not test -S "$EXPLAIN_SOCK"
    rm -f "$EXPLAIN_SOCK"
end

if not test -S "$EXPLAIN_SOCK"
    if string match -rqi '^(1|true|yes|on)$' -- "$EXPLAIN_DEBUG"
        set -l daemon_log /tmp/explainerr-daemon.log
        if set -q EXPLAIN_DAEMON_LOG
            set daemon_log "$EXPLAIN_DAEMON_LOG"
        end
        env EXPLAIN_DEBUG=1 "$explain_bin" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >"$daemon_log" 2>&1 &
        disown $last_pid 2>/dev/null
    else
        "$explain_bin" serve -socket "$EXPLAIN_SOCK" -idle-minutes "$EXPLAIN_IDLE_MINUTES" >/dev/null 2>&1 &
        disown $last_pid 2>/dev/null
    end
    for _i in (seq 1 20)
        if test -S "$EXPLAIN_SOCK"
            break
        end
        sleep 0.05
    end
end

if not test -S "$EXPLAIN_SOCK"
    echo "[start_explain] warning: daemon socket was not created at $EXPLAIN_SOCK" >&2
end

set -gx EXPLAIN_BIN "$explain_bin"
source "$repo_root/scripts/explain_init.fish"

echo "[start_explain] ready in current fish shell. Try: definitely-not-a-real-command"
