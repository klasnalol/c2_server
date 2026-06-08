#!/bin/bash
# Memory dump acquisition helper for forensic experiments

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DUMPS_DIR="$SCRIPT_DIR/dumps"

usage() {
    echo "Usage: $0 <vm_name> <dump_filename.raw>"
    echo ""
    echo "Examples:"
    echo "  $0 win10-forensic R1-D1-active.raw"
    echo "  $0 win10-forensic R1-D0-baseline.raw"
    echo "  $0 win10-forensic R1-D2-persist.raw"
    echo ""
    echo "Dumps are saved to: $DUMPS_DIR"
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

VM_NAME="$1"
DUMP_FILE="$2"
DUMP_PATH="$DUMPS_DIR/$DUMP_FILE"

mkdir -p "$DUMPS_DIR"

# Check VM is running
if ! virsh -c qemu:///system list --name | grep -qx "$VM_NAME"; then
    echo "ERROR: VM '$VM_NAME' is not running. Start it first:"
    echo "  virsh start $VM_NAME"
    exit 1
fi

# Get VM memory size in bytes
MEM_KB=$(virsh -c qemu:///system dominfo "$VM_NAME" | grep "Used memory" | awk '{print $3}')
if [ -z "$MEM_KB" ]; then
    echo "WARNING: Could not detect VM memory size. Trying Max memory..."
    MEM_KB=$(virsh -c qemu:///system dominfo "$VM_NAME" | grep "Max memory" | awk '{print $3}')
fi

MEM_BYTES=$((MEM_KB * 1024))

echo "=========================================="
echo "Memory Dump Acquisition"
echo "=========================================="
echo "VM:       $VM_NAME"
echo "Memory:   ${MEM_KB} KiB (${MEM_BYTES} bytes)"
echo "Output:   $DUMP_PATH"
echo ""

# Method 1: QEMU monitor pmemsave (fastest, most reliable)
# Use decimal for size; QEMU HMP pmemsave accepts decimal expressions
echo "Method: QEMU monitor pmemsave..."
echo "Running: virsh qemu-monitor-command $VM_NAME --hmp \"pmemsave 0 $MEM_BYTES $DUMP_PATH\""

virsh -c qemu:///system qemu-monitor-command "$VM_NAME" --hmp "pmemsave 0 $MEM_BYTES $DUMP_PATH"

if [ -f "$DUMP_PATH" ]; then
    SIZE=$(du -h "$DUMP_PATH" | cut -f1)
    echo ""
    echo "SUCCESS: Dump saved ($SIZE)"
    echo "  $DUMP_PATH"
    echo ""
    echo "Analyze with:"
    echo "  cd /home/klasnalol/repos/c2_server"
    echo "  ./manage.sh forensic-analyze lab/dumps/$DUMP_FILE"
    echo ""
    echo "Or via dashboard: http://$(hostname -I | awk '{print $1}'):8080/dashboard"
else
    echo "ERROR: Dump file was not created."
    echo "Trying alternative method (virsh dump)..."
    virsh -c qemu:///system dump --memory-only "$VM_NAME" "$DUMP_PATH"
    if [ -f "$DUMP_PATH" ]; then
        SIZE=$(du -h "$DUMP_PATH" | cut -f1)
        echo "SUCCESS (fallback): Dump saved ($SIZE)"
    else
        echo "ERROR: Both methods failed."
        exit 1
    fi
fi
