#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Regression tests for the SO_TXTIME interface

set -e

readonly DEV="vcan0"
readonly CANGEN="./cangen"
readonly CANDUMP="./candump"
readonly SSH=( ssh -o VisualHostKey=no -o ControlMaster=auto -o ControlPersist=60 )
readonly RAND="$(mktemp -u XXXXXX)"
readonly NSPREFIX="ns-${RAND}"
readonly NS_TX="${NSPREFIX}-tx"
readonly NS_RX="${NSPREFIX}-rx"
readonly NUM_FRAMES=512

DEV_TX=${DEV}
DEV_RX=${DEV}

cleanup() {
    set +e

    if [ -n "${CANDUMP_PID}" ]; then
	kill -9 ${CANDUMP_PID}
    fi

    "${EXEC_TX[@]}" tc qdisc replace dev "${DEV_TX}" root pfifo_fast

    ip netns del "${NS_TX}"
    ip netns del "${NS_RX}"
}

trap cleanup EXIT

setup_netns() {
    # Create virtual ethernet pair between network namespaces
    ip netns add "${NS_TX}"
    ip netns add "${NS_RX}"
    ip link add "${DEV_TX}" netns "${NS_TX}" type vxcan \
       peer name "${DEV_RX}" netns "${NS_RX}"

    # Bring the devices up
    ip -netns "${NS_TX}" link set "${DEV_TX}" up
    ip -netns "${NS_RX}" link set "${DEV_RX}" up

    EXEC_TX=( ip netns exec "${NS_TX}" )
    EXEC_RX=( ip netns exec "${NS_RX}" )
}

do_test() {
    local readonly START="$(date +%s%N --date="+ 3 seconds")"

    echo "---------------- ${@} ----------------"

    "${EXEC_RX[@]}" "${CANDUMP}" "${DEV_RX},0:0,#FFFFFFFF" --start="${START}" -cexdtz -n ${NUM_FRAMES} &
    CANDUMP_PID="$!"
    "${EXEC_TX[@]}" "${CANGEN}" "${DEV_TX}" --start="${START}" -Di -L1 -I2 -g 10 -n ${NUM_FRAMES} "${@}"
    wait ${CANDUMP_PID}
    unset CANDUMP_PID
}

if [ ${#} -eq 0 ]; then
    setup_netns
else
    if [ "${1}" != '-' ]; then
	EXEC_TX=( "${SSH[@]}" "${1}" -- )
    fi

    if [ "${2}" != '-' ]; then
	DEV_TX="${2}"
    else
	DEV_TX="can0"
    fi

    if [ "${3}" != '-' ]; then
	EXEC_RX=( "${SSH[@]}" "${3}" -- )
    fi

    if [ "${4}" != '-' ]; then
	DEV_RX="${4}"
    else
	DEV_RX="can0"
    fi
fi

"${EXEC_TX[@]}" tc qdisc replace dev "${DEV_TX}" root pfifo_fast

do_test
do_test -a

# if "${EXEC_TX[@]}" tc qdisc replace dev "${DEV_TX}" root fq; then
# 	do_test -t
# else
# 	echo "tc ($(tc -V)) does not support qdisc fq. skipping"
# fi

if "${EXEC_TX[@]}" tc qdisc replace dev "${DEV_TX}" root etf clockid CLOCK_TAI delta 400000; then
	do_test -t
else
	echo "tc ($(tc -V)) does not support qdisc etf. skipping"
fi

echo OK. All tests passed
