#!/bin/bash
# Streamlined memory dump + auto-report script
# Dumps VM memory and immediately outputs the exact analysis command

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
C2_DIR="$(dirname "$SCRIPT_DIR")"
DUMPS_DIR="$SCRIPT_DIR/dumps"
VM_NAME="${2:-win10}"

if [ -z "$1" ]; then
    echo "Usage: $0 <dump_name.raw> [vm_name]"
    echo ""
    echo "Examples:"
    echo "  $0 R1-D1-active.raw"
    echo "  $0 R1-D0-baseline.raw win10"
    echo ""
    exit 1
fi

DUMP_NAME="$1"
DUMP_PATH="$DUMPS_DIR/$DUMP_NAME"

mkdir -p "$DUMPS_DIR"

# Check VM is running
if ! virsh -c qemu:///system list --name | grep -qx "$VM_NAME"; then
    echo "ERROR: VM '$VM_NAME' is not running."
    echo "Start it: virsh -c qemu:///system start $VM_NAME"
    exit 1
fi

echo "=========================================="
echo "Memory Dump + Report Streamliner"
echo "=========================================="
echo "VM:       $VM_NAME"
echo "Output:   $DUMP_PATH"
echo ""

# Get VM memory size
MEM_KB=$(virsh -c qemu:///system dominfo "$VM_NAME" | grep "Used memory" | awk '{print $3}')
if [ -z "$MEM_KB" ]; then
    MEM_KB=$(virsh -c qemu:///system dominfo "$VM_NAME" | grep "Max memory" | awk '{print $3}')
fi
MEM_BYTES=$((MEM_KB * 1024))

echo "Dumping ${MEM_KB} KiB of memory..."
virsh -c qemu:///system qemu-monitor-command "$VM_NAME" --hmp "pmemsave 0 $MEM_BYTES $DUMP_PATH" 2>/dev/null || true

if [ ! -f "$DUMP_PATH" ]; then
    echo "pmemsave failed, trying virsh dump fallback..."
    virsh -c qemu:///system dump --memory-only "$VM_NAME" "$DUMP_PATH"
fi

# Fix ownership if needed
if [ -f "$DUMP_PATH" ]; then
    sudo chown "$USER:$USER" "$DUMP_PATH" 2>/dev/null || true
    SIZE=$(du -h "$DUMP_PATH" | cut -f1)
    echo ""
    echo "✅ DUMP SAVED: $DUMP_PATH ($SIZE)"
    echo ""
    echo "=========================================="
    echo "NEXT STEPS — Copy and paste one of these:"
    echo "=========================================="
    echo ""
    echo "1. ANALYZE VIA CLI:"
    echo "   cd $C2_DIR && ./manage.sh forensic-analyze lab/dumps/$DUMP_NAME"
    echo ""
    echo "2. ANALYZE VIA DASHBOARD:"
    echo "   Open http://192.168.122.1:8080/dashboard"
    echo "   Paste this path into the Forensic panel:"
    echo "   $DUMP_PATH"
    echo ""
    echo "3. ASYNC ANALYZE WITH PROGRESS TRACKING:"
    echo "   curl -X POST http://192.168.122.1:8080/forensic/analyze-async \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -d '{\"dump_path\":\"$DUMP_PATH\"}'"
    echo ""
else
    echo "ERROR: Dump failed."
    exit 1
fi
