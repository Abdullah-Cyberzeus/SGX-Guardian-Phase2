#!/bin/sh
# Reset all ssscli / SE050 session state. Safe to run any time.

# Kill any running ssscli process.
pkill -9 -f ssscli 2>/dev/null

# Drop the cached PlatformSCP session pickle. Old pickles cause hangs when
# the on-chip session was invalidated by a prior SIGKILL mid-transaction.
rm -f /home/root/*.ssscli_session.pkl
rm -f /root/*.ssscli_session.pkl

# Re-establish a clean session.
ssscli disconnect >/dev/null 2>&1
sleep 1
ssscli connect --auth_type PlatformSCP \
    --scpkey /home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt \
    se05x t1oi2c none >/tmp/ssscli_connect.log 2>&1

# Probe: read UID. If this hangs, SE050/I2C bus is wedged — reboot is the only fix.
timeout 5 ssscli se05x uniqueid >/tmp/ssscli_uid.log 2>&1
if [ $? -ne 0 ]; then
    echo "WARN: ssscli uniqueid failed — SE050/I2C may be wedged. Consider reboot." >&2
    exit 1
fi

echo "ssscli session reset OK"
exit 0
