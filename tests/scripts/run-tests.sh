#!/bin/sh

cd "$(dirname $0)"

source ./common.sh

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
