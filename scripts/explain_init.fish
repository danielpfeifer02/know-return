#!/usr/bin/env fish
# Source this file from fish to install explainerr hooks.

set -l repo_root (cd (dirname (status filename))/..; pwd)
source "$repo_root/scripts/explain_hook.fish"
