#!/bin/sh

cd "$(dirname $0)"

source ./common.sh

log "CONFIGURATION TESTS"

function load_config() {
    base=$(basename $1)
    log " - starting nyx with '$base'"

    $NYX -c "$1" >/dev/null
}

log "INVALID CONFIGURATIONS"

# test some invalid configurations
for f in ./configs/invalid*.yaml; do
    load_config $f && die loading invalid config should have failed
done

log "SINGLE WATCH CONFIGURATIONS"

# test some single watch configurations
for f in ./configs/single*.yaml; do
    load_config $f || die "failed to start with configuration (code $?)"
    sleep 0.5
    NUM_WATCHES=`$NYX -q watches 2>/dev/null | wc -l`
    terminate

    [ "$NUM_WATCHES" -eq 1 ] || die "expected 1 configured watch; got $NUM_WATCHES instead"
done
