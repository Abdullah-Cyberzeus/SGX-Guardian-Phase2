#!/bin/sh
set -e

# Config is root-owned
chown -R root:root /etc/sgx-guardian
chmod -R 755 /etc/sgx-guardian

# Runtime writable by service
chown -R sgxguardian:sgxguardian /var/lib/sgx-guardian /var/log/sgx-guardian
chmod 750 /var/lib/sgx-guardian /var/log/sgx-guardian

exit 0
