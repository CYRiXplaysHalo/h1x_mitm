#!/bin/sh
# usage: ./emulate.sh <hdd> <n> &
#
# Launch n emulators in parallel
#
# Make sure xemu has set up network and remaining files (game disc, bios,
# mcpx).
#
# Each instance must use a separate hdd and eeprom, they are copied from the
# specified ones. The mac address in eeprom is patched to be unique so system
# link connections are not rejected.

set -x

hdd=$1
[ -r "$hdd" ] || exit 1
shift 1

n=$1
[ "$n" -gt 0 ] || exit 1
[ "$n" -le 4 ] || exit 1
shift 1

[ -n "$*" ] && exit 1

eeprom=$(echo ~/.local/share/xemu/xemu/eeprom.bin)
[ -r "$eeprom" ] || exit 1

tmpdir=$(mktemp -d)
pids=
for i in $(seq 0 $((n-1))); do
    my_hdd="$tmpdir/emu$i-$(basename $hdd)"
    my_eeprom="$tmpdir/emu$i-$(basename $eeprom)"
    # ensure mac address unique
    cp "$hdd" "$my_hdd"
    cp "$eeprom" "$my_eeprom"
    printf "%d" "$i" | dd of="$my_eeprom" seek=67 conv=notrunc bs=1 count=1
    xemu "$my_hdd" -device smbus-storage,file="$my_eeprom" -gdb tcp::$((1234+i)) &
    pids="$pids $!"
done

wait $pids
rm -rf "$tmpdir"
