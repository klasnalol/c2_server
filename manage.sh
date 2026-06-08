#!/bin/bash
# C2 Server Management Script

C2_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_PID=$(pgrep -f "python3.*c2_server.py")
AI_PID=$(pgrep -f "python3.*ai_detection_backend.py")
VIRSH="virsh -c qemu:///system"

case "$1" in
    start)
        if [ -n "$SERVER_PID" ]; then
            echo "C2 Server already running (PID: $SERVER_PID)"
        else
            cd $C2_DIR
            source .venv/bin/activate
            nohup python3 c2_server.py > c2_server.log 2>&1 &
            sleep 2
            echo "C2 Server started (PID: $!)"
            echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080/dashboard"
        fi
        ;;
    ai-start)
        if [ -n "$AI_PID" ]; then
            echo "AI Backend already running (PID: $AI_PID)"
        else
            cd $C2_DIR
            source .venv/bin/activate
            nohup python3 ai_detection_backend.py > ai_backend.log 2>&1 &
            sleep 2
            echo "AI Backend started (PID: $!)"
            echo "Endpoint: http://$(hostname -I | awk '{print $1}'):8090/status"
        fi
        ;;
    stop)
        if [ -n "$SERVER_PID" ]; then
            kill $SERVER_PID
            echo "C2 Server stopped"
        else
            echo "C2 Server not running"
        fi
        sleep 1
        ;;
    ai-stop)
        if [ -n "$AI_PID" ]; then
            kill $AI_PID
            echo "AI Backend stopped"
        else
            echo "AI Backend not running"
        fi
        ;;
    status)
        if [ -n "$SERVER_PID" ]; then
            echo "C2 Server is running (PID: $SERVER_PID)"
            curl -s http://localhost:8080/status | python3 -m json.tool 2>/dev/null || echo "Server not responding"
        else
            echo "C2 Server is not running"
        fi
        echo ""
        echo "VMs:"
        $VIRSH list --all 2>/dev/null || echo "  libvirt not available"
        ;;
    logs)
        tail -f $C2_DIR/logs/c2_log.json 2>/dev/null || echo "No logs yet"
        ;;
    ai-status)
        if [ -n "$AI_PID" ]; then
            echo "AI Backend is running (PID: $AI_PID)"
            curl -s http://localhost:8090/status | python3 -m json.tool 2>/dev/null || echo "AI backend not responding"
        else
            echo "AI Backend is not running"
        fi
        ;;
    compare)
        cd $C2_DIR
        source .venv/bin/activate
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
    # Forensic analysis commands
    forensic-analyze)
        if [ -z "$2" ]; then
            echo "Usage: $0 forensic-analyze /path/to/memory.raw [--pid N]"
            exit 1
        fi
        cd $C2_DIR
        shift
        source .venv/bin/activate
        python3 analyze_dump.py "$@"
        ;;
    forensic-strings)
        if [ -z "$2" ]; then
            echo "Usage: $0 forensic-strings /path/to/memory.raw"
            exit 1
        fi
        cd $C2_DIR
        source .venv/bin/activate
        python3 analyze_dump.py "$2" --strings-only
        ;;
    forensic-yara)
        if [ -z "$2" ]; then
            echo "Usage: $0 forensic-yara /path/to/memory.raw"
            exit 1
        fi
        cd $C2_DIR
        source .venv/bin/activate
        python3 analyze_dump.py "$2" --yara-only
        ;;
    forensic-correlate)
        cd $C2_DIR
        source .venv/bin/activate
        python3 analyze_dump.py logs/c2_log.json --correlate-only 2>/dev/null || python3 -c "
import json
from forensic_analysis import correlate_with_c2
result = correlate_with_c2([], 'logs/c2_log.json', 300)
print(json.dumps(result, indent=2))
"
        ;;
    forensic-reports)
        OUTPUT_DIR="${C2_DIR}/forensic_output"
        if [ -d "$OUTPUT_DIR" ]; then
            ls -lt "$OUTPUT_DIR"/forensic_report_*.json 2>/dev/null | head -20
        else
            echo "No forensic output directory yet"
        fi
        ;;
    dump-memory)
        if [ -z "$2" ]; then
            echo "Usage: $0 dump-memory <dump_filename.raw> [--vm win10]"
            echo "Examples:"
            echo "  $0 dump-memory R1-D1-active.raw"
            echo "  $0 dump-memory R1-D0-baseline.raw --vm win10"
            exit 1
        fi
        VM_NAME="${3:-win10}"
        cd $C2_DIR/lab
        ./dump_memory.sh "$VM_NAME" "$2"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|logs|compare|import-manual <file>|dashboard|clean|ai-start|ai-stop|ai-status|dump-memory <file>|forensic-analyze <dump>|forensic-strings <dump>|forensic-yara <dump>|forensic-correlate|forensic-reports}"
        exit 1
        ;;
esac
