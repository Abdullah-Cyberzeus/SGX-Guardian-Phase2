#!/bin/sh
### BEGIN INIT INFO
# Provides:          sgx-hw-keepalive
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SGX hardware watchdog keep-alive
### END INIT INFO

case "$1" in
    start)
        if pidof -x sgx-hw-keepalive.sh > /dev/null; then
            echo "sgx-hw-keepalive already running"
            exit 0
        fi
        echo "Starting sgx-hw-keepalive..."
        setsid /home/root/sgx-hw-keepalive.sh < /dev/null > /dev/null 2>&1 &
        ;;
    stop)
        pkill -f sgx-hw-keepalive.sh
        ;;
    status)
        if pidof -x sgx-hw-keepalive.sh > /dev/null; then
            echo "running (PID=$(pidof -x sgx-hw-keepalive.sh))"
        else
            echo "stopped"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
