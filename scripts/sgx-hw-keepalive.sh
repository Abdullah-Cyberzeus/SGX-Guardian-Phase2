#!/bin/sh
# HW watchdog keep-alive. Holds /dev/watchdog0 open and pings every 15s.
# If THIS process dies AND no further pings occur within 60s, the board reboots.
# That is the intended safety-net behaviour.

WD=/dev/watchdog0
[ -c "$WD" ] || exit 0

# Open fd 3 permanently — this ARMS the hardware watchdog.
exec 3>"$WD" || exit 1

# On clean shutdown, send a ping (NOT a stop — MAGICCLOSE not supported on imx2+).
trap 'echo 1 >&3 2>/dev/null; exit 0' TERM INT

while :; do
    echo 1 >&3 2>/dev/null || exit 1
    sleep 15
done
