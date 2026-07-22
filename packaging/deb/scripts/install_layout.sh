#!/bin/sh
set -e

# Config layout
mkdir -p /etc/sgx-guardian
mkdir -p /etc/sgx-guardian/schemas
mkdir -p /etc/sgx-guardian/policies

# Runtime
mkdir -p /var/lib/sgx-guardian
mkdir -p /var/lib/sgx-guardian/sgx-agent
mkdir -p /var/log/sgx-guardian

# Scripts
mkdir -p /usr/lib/sgx-guardian/scripts

exit 0
