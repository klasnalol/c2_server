#!/bin/bash
# C2 Server Management Script

C2_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_PID=$(pgrep -f "python3.*c2_server.py")

case "$1" in
    start)
        if [ -n "$SERVER_PID" ]; then
            echo "C2 Server already running (PID: $SERVER_PID)"
        else
            cd $C2_DIR
            nohup python3 c2_server.py > c2_server.log 2>&1 &
            sleep 2
            echo "C2 Server started (PID: $!)"
            echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080/dashboard"
        fi
        ;;
    stop)
        if [ -n "$SERVER_PID" ]; then
            kill $SERVER_PID
            echo "C2 Server stopped"
        else
            echo "C2 Server not running"
        fi
        ;;
    status)
        if [ -n "$SERVER_PID" ]; then
            echo "C2 Server is running (PID: $SERVER_PID)"
            curl -s http://localhost:8080/status | python3 -m json.tool 2>/dev/null || echo "Server not responding"
        else
            echo "C2 Server is not running"
        fi
        ;;
    logs)
        tail -f $C2_DIR/logs/c2_log.json 2>/dev/null || echo "No logs yet"
        ;;
    compare)
        cd $C2_DIR
        python3 compare_flag_detection.py
        ;;
    import-manual)
        if [ -z "$2" ]; then
            echo "Usage: $0 import-manual /path/to/manual_labels.json"
            exit 1
        fi
        mkdir -p $C2_DIR/logs
        cp "$2" $C2_DIR/logs/manual_labels.json
        echo "Imported manual labels to logs/manual_labels.json"
        ;;
    dashboard)
        IP=$(ip addr show br0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -z "$IP" ]; then
            IP=$(hostname -I | awk '{print $1}')
        fi
        echo "Dashboard: http://$IP:8080/dashboard"
        ;;
    clean)
        read -p "Clear all logs? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f $C2_DIR/logs/* $C2_DIR/flags_received/*
            echo "Logs cleared"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status|logs|compare|import-manual <file>|dashboard|clean}"
        exit 1
        ;;
esac
