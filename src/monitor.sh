#!/bin/sh
# usage: ./monitor.sh <n>
#
# Run tcpdump and a GDB script for n emulator instances.

set -x

n=$1
[ "$n" -gt 0 ] || exit 1
[ "$n" -le 4 ] || exit 1
shift 1

gdb_script=$1
[ -r "$gdb_script" ] || exit 1
shift 1

[ -n "$*" ] && exit 1

out=$(mktemp -d "$(pwd)/monitor_XXXXX")
workdir=$(mktemp -d)

for i in $(seq 0 $((n-1))); do
    # need separate dirs for tmp files to not collide
    wdir="$workdir/$i"
    mkdir "$wdir"
    cd "$wdir"
    gdb -x "$gdb_script" \
        -ex 'target remote :'$((1234+i)) \
        -ex 'monitor' \
        > "$out/gdb$i.txt" &
    pids="$pids $!"
    cd -
done

trap "
    kill $pids
    rm -rf $workdir
    chmod 777 -R $out
    exit" INT

tcpdump "udp port xbox" -w "$out/traffic.pcap"
