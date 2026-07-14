#!/bin/sh

test -d /etc/sgx-guardian || exit 1
test -d /etc/sgx-guardian/threat || exit 1
test -d /var/lib/sgx-guardian || exit 1
test -d /var/lib/sgx-guardian/threat || exit 1
test -d /var/log/sgx-guardian || exit 1

exit 0
