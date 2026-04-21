#!/bin/sh
### BEGIN INIT INFO
# Provides:          sgx-guardian
# Required-Start:    $network $remote_fs
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       SGX Guardian Client
### END INIT INFO

NODE_ID="nodeA"  # Change per board: nodeA, nodeB, nodeC

case "$1" in
    start)
        echo "Starting SGX Guardian ($NODE_ID)..."
        /root/run_node.sh $NODE_ID
        ;;
    stop)
        echo "Stopping SGX Guardian..."
        pkill -f sgx_guardian_client 2>/dev/null
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        PID=$(pidof sgx_guardian_client 2>/dev/null)
        if [ -n "$PID" ]; then
            echo "Running (PID $PID)"
            cat /tmp/sgx_guardian_heartbeat 2>/dev/null
        else
            echo "Not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
