#!/bin/bash

set -e -u -o pipefail

readonly NL='
'

log() {
    printf "%s\n" "$*" 1>&2
}

err() {
    log "${BASH_SOURCE[1]}:${BASH_LINENO[0]}:${FUNCNAME[1]}: $*"
    log "stack: ${FUNCNAME[*]:1}"

    # pause to ensure that log reaches the final destionation outside container
    sleep 1
    exit 1
}

arg_err() {
    log "${BASH_SOURCE[2]}:${BASH_LINENO[1]}:${FUNCNAME[2]}: $*"
    log "stack: ${FUNCNAME[*]:1}"

    # pause to ensure that log reaches the final destionation outside container
    sleep 1
    exit 1
}

assert_err() {
    local s="$*"
    err "failed assertion${s:+ - }$s"
}

getopts_err() {
    err "unknown option '$opt'"
}

warn() {
    log "${@/#/WARNING }"
}

cmd_log() {
    [[ $# -ge 1 ]] || err "Command must be given"
    log "  $*"
    "$@"
}

start_logpipe() {
    local path="$1"

    # Start a cat process to copy named pipe input into stderr that
    # goes into Docker. To keep the pipe openned by at least one
    # reader, open it in a read-write mode and use that as stdin to
    # cat. This is Linux-specific.
    cat <> $path 1>&2 &
}
