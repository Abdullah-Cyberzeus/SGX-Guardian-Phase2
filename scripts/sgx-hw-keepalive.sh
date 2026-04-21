#!/bin/sh
# Long-lived holder of /dev/watchdog0. Pings every 15s.
# Must be started once at boot. The kernel only resets the board if THIS
# process dies AND no further pings occur within the HW timeout (60s).

WD=/dev/watchdog0
[ -c "$WD" ] || exit 0

# Open fd 3 permanently
exec 3>"$WD" || exit 1

trap 'echo "V" >&3 2>/dev/null; exit 0' TERM INT

while :; do
    echo 1 >&3 2>/dev/null || exit 1
    sleep 15
done
