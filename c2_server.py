#!/usr/bin/env python3
"""
MITRE ATT&CK C2 Server for Windows VM Detection Testing
Runs on Fedora, auto-detects IP, serves Windows payloads
"""

import json
import os
import socket
import subprocess
import datetime
import re
from pathlib import Path
from flask import Flask, request, send_file, jsonify, render_template_string

app = Flask(__name__)

# ------------------------------------------------------------
# Configuration (auto-detect IP, or use config file)
# ------------------------------------------------------------
CONFIG_FILE = Path(__file__).parent / "c2_config.json"
DEFAULT_CONFIG = {
    "c2_port": 8080,
    "payload_dir": "payloads",
    "log_dir": "logs",
    "flags_dir": "flags_received",
    "host_ip": None          # Will auto-detect
}

def get_best_local_ip():
    """Return the most likely IP address for VMs to reach this host."""
    # 1. Check common bridge interfaces (libvirt default, custom bridge)
    for iface in ['virbr0', 'br0', 'docker0']:
        try:
            result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass

    # 2. Fallback: IP of default route interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# Load config file if exists, otherwise create with auto-detected IP
if CONFIG_FILE.exists():
    with open(CONFIG_FILE, 'r') as f:
        saved = json.load(f)
        DEFAULT_CONFIG.update(saved)

if not DEFAULT_CONFIG["host_ip"]:
    DEFAULT_CONFIG["host_ip"] = get_best_local_ip()

# Ensure directories exist
for dir_name in [DEFAULT_CONFIG["payload_dir"], DEFAULT_CONFIG["log_dir"], DEFAULT_CONFIG["flags_dir"]]:
    Path(dir_name).mkdir(parents=True, exist_ok=True)

# In-memory session tracking
active_sessions = {}

# ------------------------------------------------------------
# HTML Dashboard
# ------------------------------------------------------------
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>MITRE ATT&CK C2 Dashboard</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #4ec9b0; }
        .container { max-width: 1200px; margin: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #3e3e3e; }
        th { background: #2d2d2d; color: #4ec9b0; }
        .flag { color: #ce9178; }
        .timestamp { color: #6a9955; }
        .endpoint { color: #9cdcfe; }
        .payload-list a { color: #4ec9b0; text-decoration: none; }
        .payload-list a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="container">
    <h1>🎯 MITRE ATT&CK C2 Server</h1>
    <p>Host IP: <strong>{{ host_ip }}:{{ port }}</strong> | VM Bridge Network</p>

    <h2>📊 Received Flags (Last 50)</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Technique</th><th>Details</th></tr>
        {% for entry in logs %}
        <tr>
            <td class="timestamp">{{ entry.timestamp }}</td>
            <td>{{ entry.source_ip }}</td>
            <td class="flag">{{ entry.technique }}</td>
            <td>{{ entry.details[:80] }}{% if entry.details|length > 80 %}...{% endif %}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>📦 Windows Payloads</h2>
    <div class="payload-list">
        <ul>
        {% for payload in payloads %}
            <li><a href="/get/{{ payload }}">{{ payload }}</a> - <span class="endpoint">GET /get/{{ payload }}</span></li>
        {% endfor %}
        </ul>
    </div>

    <h2>🔌 C2 Endpoints</h2>
    <ul>
        <li><span class="endpoint">POST /collect</span> - Receive flags from Windows VMs</li>
        <li><span class="endpoint">GET /get/&lt;filename&gt;</span> - Download Windows payloads</li>
        <li><span class="endpoint">GET /dashboard</span> - This dashboard</li>
        <li><span class="endpoint">GET /api/flags</span> - JSON API</li>
        <li><span class="endpoint">GET /status</span> - Health check</li>
    </ul>

    <h2>💻 Active VM Sessions</h2>
    <table>
        <tr><th>VM IP</th><th>First Seen</th><th>Last Seen</th><th>Techniques</th></tr>
        {% for ip, session in sessions.items() %}
        <tr>
            <td>{{ ip }}</td>
            <td class="timestamp">{{ session.first_seen }}</td>
            <td class="timestamp">{{ session.last_seen }}</td>
            <td>{{ session.techniques|join(', ') }}</td>
        </tr>
        {% endfor %}
    </table>
</div>
</body>
</html>
'''

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.route('/')
@app.route('/dashboard')
def dashboard():
    # Read last 50 log entries
    logs = []
    log_file = Path(DEFAULT_CONFIG["log_dir"]) / "c2_log.json"
    if log_file.exists():
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    pass
    logs = logs[-50:]

    payloads = [f.name for f in Path(DEFAULT_CONFIG["payload_dir"]).iterdir() if f.is_file()]

    return render_template_string(DASHBOARD_HTML,
                                  logs=logs,
                                  payloads=payloads,
                                  sessions=active_sessions,
                                  host_ip=DEFAULT_CONFIG["host_ip"],
                                  port=DEFAULT_CONFIG["c2_port"])

@app.route('/status')
def status():
    return jsonify({
        "status": "online",
        "host_ip": DEFAULT_CONFIG["host_ip"],
        "port": DEFAULT_CONFIG["c2_port"],
        "payloads_available": len(list(Path(DEFAULT_CONFIG["payload_dir"]).iterdir())),
        "active_sessions": len(active_sessions)
    })

@app.route('/collect', methods=['POST'])
def collect():
    source_ip = request.remote_addr
    flag_data = request.get_data(as_text=True)
    timestamp = datetime.datetime.now().isoformat()

    # Extract MITRE technique ID from flag (e.g., FLAG{T1059.001-...})
    technique = "Unknown"
    match = re.search(r'FLAG\{([^}-]+)', flag_data)
    if match:
        technique = match.group(1)

    # Log to JSON file
    log_entry = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "technique": technique,
        "details": flag_data[:200]
    }
    log_file = Path(DEFAULT_CONFIG["log_dir"]) / "c2_log.json"
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    # Save raw flag to separate file
    flag_file = Path(DEFAULT_CONFIG["flags_dir"]) / f"flag_{timestamp.replace(':', '-')}_{source_ip.replace('.', '_')}.txt"
    with open(flag_file, 'w') as f:
        f.write(f"Timestamp: {timestamp}\nSource IP: {source_ip}\nTechnique: {technique}\nData: {flag_data}\n")

    # Update session tracking
    if source_ip not in active_sessions:
        active_sessions[source_ip] = {
            "first_seen": timestamp,
            "last_seen": timestamp,
            "techniques": []
        }
    else:
        active_sessions[source_ip]["last_seen"] = timestamp

    if technique not in active_sessions[source_ip]["techniques"]:
        active_sessions[source_ip]["techniques"].append(technique)

    print(f"\033[92m[+] {timestamp} | {source_ip} | {technique}\033[0m")
    print(f"    {flag_data[:100]}")

    return jsonify({"status": "logged", "technique": technique})

@app.route('/get/<filename>')
def get_payload(filename):
    # Security: prevent path traversal
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400

    filepath = Path(DEFAULT_CONFIG["payload_dir"]) / filename
    if filepath.exists() and filepath.is_file():
        # Log download
        timestamp = datetime.datetime.now().isoformat()
        print(f"\033[94m[↓] {timestamp} | {request.remote_addr} downloaded {filename}\033[0m")
        download_log = Path(DEFAULT_CONFIG["log_dir"]) / "downloads.log"
        with open(download_log, 'a') as f:
            f.write(f"{timestamp} | {request.remote_addr} | {filename}\n")
        return send_file(filepath, as_attachment=True)
    else:
        return f"Payload not found: {filename}", 404

@app.route('/api/flags')
def api_flags():
    flags = []
    log_file = Path(DEFAULT_CONFIG["log_dir"]) / "c2_log.json"
    if log_file.exists():
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    flags.append(json.loads(line))
                except:
                    pass
    return jsonify(flags)

@app.route('/clear', methods=['POST'])
def clear_logs():
    for d in [DEFAULT_CONFIG["log_dir"], DEFAULT_CONFIG["flags_dir"]]:
        for f in Path(d).iterdir():
            f.unlink()
    active_sessions.clear()
    return jsonify({"status": "cleared"})

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == '__main__':
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║     MITRE ATT&CK C2 Server - Windows Payloads Only       ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Host IP: {DEFAULT_CONFIG['host_ip']:<44} ║
    ║  Port: {DEFAULT_CONFIG['c2_port']:<44} ║
    ║  Dashboard: http://{DEFAULT_CONFIG['host_ip']}:{DEFAULT_CONFIG['c2_port']}/dashboard ║
    ║  Payload Dir: {DEFAULT_CONFIG['payload_dir']:<44} ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=DEFAULT_CONFIG['c2_port'], debug=False, threaded=True)
