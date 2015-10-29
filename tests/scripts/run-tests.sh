#!/bin/sh

NYX="../../nyx -q"

cd "$(dirname $0)"

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
    $NYX ping >/dev/null 2>&1
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

function quit() {
    log "Quitting nyx instance"

    $NYX quit >/dev/null
    for i in `seq 1 5`; do
        check_nyx || return 0
        sleep 1
    done

    die failed to quit nyx after 5 retries
}

# intital check
check_nyx_off

# test with sleep
run sleep
check_running sleep
stop sleep
sleep 2
check_stopped sleep

# shutdown nyx
quit
