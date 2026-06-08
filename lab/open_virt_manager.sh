#!/bin/bash
# Open virt-manager GUI for QEMU/KVM management

if ! command -v virt-manager &>/dev/null; then
    echo "virt-manager is not installed."
    echo "Run: sudo dnf install -y virt-manager"
    exit 1
fi

if ! systemctl is-active --quiet libvirtd; then
    echo "libvirtd is not running."
    echo "Run: sudo systemctl start libvirtd"
    exit 1
fi

echo "Opening virt-manager..."
virt-manager &
