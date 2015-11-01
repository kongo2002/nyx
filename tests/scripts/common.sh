#!/bin/sh

NYX="../../nyx -q"
MAX_TERMINATE_ATTEMPTS=15

function die() {
    echo ERROR: $@
    exit 1
}

function log() {
    echo "***" $@
}

function run() {
    log "Starting configuration '$1'"

    $NYX -c "$1.yaml" >/dev/null || die nyx is already running
    sleep 0.1
}

function check_nyx() {
    # check for the connector interface and a running
    # nyx process as well
    $NYX ping >/dev/null 2>&1 || pgrep nyx >/dev/null
    return $?
}

function check_status() {
    check_nyx || die nyx should be running
    STATUS=`$NYX status $1 | cut -d ' ' -f 2` 2>/dev/null || die "status of '$1' failed"

    [ "$STATUS" == "$2" ] || die "expected status '$2', received '$STATUS'"
}

function check_running() {
    check_status $1 "running"
}

function check_stopped() {
    check_status $1 "stopped"
}

function stop() {
    $NYX stop $1 >/dev/null || die nyx should be running
}

function check_nyx_off() {
    check_nyx && die nyx should not be running
    return 0
}

function terminate() {
    $NYX terminate >/dev/null
    for i in `seq 1 $MAX_TERMINATE_ATTEMPTS`; do
        check_nyx || return 0
        sleep 1
    done

    die "failed to terminate nyx after $MAX_TERMINATE_ATTEMPTS retries"
}
function quit() {
    $NYX quit >/dev/null
    for i in `seq 1 $MAX_TERMINATE_ATTEMPTS`; do
        check_nyx || return 0
        sleep 1
    done

    die "failed to quit nyx after $MAX_TERMINATE_ATTEMPTS retries"
}
