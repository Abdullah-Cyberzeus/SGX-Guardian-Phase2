#!/bin/sh
set -e

# Config layout
mkdir -p /etc/sgx-guardian
mkdir -p /etc/sgx-guardian/schemas
mkdir -p /etc/sgx-guardian/policies
mkdir -p /etc/sgx-guardian/threat
mkdir -p /etc/suricata/rules
mkdir -p /var/log/suricata

# Runtime
mkdir -p /var/lib/sgx-guardian
mkdir -p /var/lib/sgx-guardian/sgx-agent
mkdir -p /var/lib/sgx-guardian/threat
mkdir -p /var/log/sgx-guardian

exit 0
