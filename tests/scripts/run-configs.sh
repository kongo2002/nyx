#!/bin/sh

cd "$(dirname $0)"

source ./common.sh

function load_config() {
    base=$(basename $1)
    log " - starting nyx with '$base'"

    $NYX -c "$1" >/dev/null
}

# test some invalid configurations
for f in ./configs/invalid*.yaml; do
    load_config $f && die loading invalid config should have failed
done

# test some single watch configurations
for f in ./configs/single*.yaml; do
    load_config $f || die "failed to start with configuration (code $?)"
    terminate
done
