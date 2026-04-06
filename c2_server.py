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
import uuid
from urllib.parse import urlparse
from pathlib import Path
from flask import Flask, request, send_file, jsonify, render_template_string
from ai_backend_client import analyze_with_backend
from flag_detection import manual_detect, summarize_detection

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
    "ai_backend_url": "http://127.0.0.1:8090/analyze",
    "ai_backend_timeout_seconds": 8,
    "ai_analysis_enabled": True,
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
MANUAL_LABELS_FILE = Path(DEFAULT_CONFIG["log_dir"]) / "manual_labels.json"


def load_manual_labels():
    if MANUAL_LABELS_FILE.exists():
        try:
            with open(MANUAL_LABELS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except:
            pass
    return {}


def save_manual_labels(labels):
    with open(MANUAL_LABELS_FILE, 'w') as f:
        json.dump(labels, f, indent=2)


def save_runtime_config():
    persisted = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                existing = json.load(f)
                if isinstance(existing, dict):
                    persisted.update(existing)
        except:
            pass

    for key in [
        "c2_port",
        "host_ip",
        "ai_backend_url",
        "ai_backend_timeout_seconds",
        "ai_analysis_enabled",
    ]:
        persisted[key] = DEFAULT_CONFIG.get(key)

    with open(CONFIG_FILE, 'w') as f:
        json.dump(persisted, f, indent=4)


def parse_backend_target(url_value):
    parsed = urlparse(url_value or "")
    return {
        "ip": parsed.hostname or "127.0.0.1",
        "port": parsed.port or 8090,
    }


def get_ai_result(text, event_id):
    if not DEFAULT_CONFIG.get("ai_analysis_enabled", True):
        return {
            "detected": False,
            "score": 0.0,
            "reasons": ["ai analysis disabled"],
            "techniques": [],
            "provider": "disabled",
            "model": "disabled",
            "mode": "disabled",
        }

    return analyze_with_backend(
        text,
        event_id,
        DEFAULT_CONFIG["ai_backend_url"],
        int(DEFAULT_CONFIG["ai_backend_timeout_seconds"]),
    )


def _event_key(entry):
    if entry.get("event_id"):
        return entry["event_id"]
    return f"{entry.get('timestamp', '')}|{entry.get('source_ip', '')}"


def apply_detection_fields(entry, labels):
    entry = dict(entry)
    details = entry.get("details", "")
    event_id = entry.get("event_id", "")
    manual = manual_detect(details)

    # AI side is provided by separate backend app.
    if "ai_detected" in entry and "ai_score" in entry:
        ai_result = {
            "detected": bool(entry.get("ai_detected")),
            "score": float(entry.get("ai_score", 0.0)),
            "reasons": entry.get("ai_reasons", []),
            "techniques": entry.get("ai_techniques", []),
            "provider": entry.get("ai_provider", "unknown"),
            "model": entry.get("ai_model", "unknown"),
            "mode": entry.get("ai_mode", "model"),
        }
    else:
        ai_result = get_ai_result(details, event_id)

    entry["ai_detected"] = ai_result["detected"]
    entry["ai_score"] = ai_result["score"]
    entry["ai_reasons"] = ai_result["reasons"]
    entry["ai_techniques"] = ai_result["techniques"]
    entry["ai_provider"] = ai_result["provider"]
    entry["ai_model"] = ai_result["model"]
    entry["ai_mode"] = ai_result["mode"]

    # Manual side prefers external analyst/tool labels.
    label = labels.get(_event_key(entry), {})
    if "detected" in label:
        entry["manual_detected"] = bool(label.get("detected"))
        entry["manual_source"] = label.get("tool", "external")
        entry["manual_notes"] = label.get("notes", "")
        entry["manual_techniques"] = label.get("techniques", [])
    else:
        entry["manual_detected"] = manual["detected"]
        entry["manual_source"] = "fallback-regex"
        entry["manual_notes"] = "No external analyst verdict yet"
        entry["manual_techniques"] = manual["techniques"]

    entry["agreement"] = entry["manual_detected"] == entry["ai_detected"]
    return entry

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
        .settings-card { border: 1px solid #3e3e3e; padding: 12px; margin-top: 20px; background: #252525; }
        .settings-grid { display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 8px; }
        .settings-grid input { background: #1d1d1d; color: #d4d4d4; border: 1px solid #4a4a4a; padding: 6px; }
        .settings-grid button { background: #007f6b; color: #fff; border: 0; padding: 8px; cursor: pointer; }
        .settings-grid button.stop { background: #8a3b3b; }
        .settings-grid button.test { background: #385e8a; }
        #ai-settings-status { margin-top: 8px; color: #dcdcaa; min-height: 20px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🎯 MITRE ATT&CK C2 Server</h1>
    <p>Host IP: <strong>{{ host_ip }}:{{ port }}</strong> | VM Bridge Network</p>

    <div class="settings-card">
        <h2>⚙ AI Backend Settings</h2>
        <div class="settings-grid">
            <input id="ai-backend-ip" placeholder="AI Backend IP" value="{{ ai_backend_ip }}" />
            <input id="ai-backend-port" placeholder="Port" value="{{ ai_backend_port }}" />
            <input id="ai-timeout" placeholder="Timeout (s)" value="{{ ai_backend_timeout_seconds }}" />
            <button onclick="saveAiSettings()">Save IP/Port</button>
            <button onclick="startAiAnalysis()">Start AI Analysis</button>
            <button class="stop" onclick="stopAiAnalysis()">Stop AI Analysis</button>
            <button class="test" onclick="testAiBackend()">Test Backend</button>
            <div>Current: {{ 'enabled' if ai_analysis_enabled else 'disabled' }}</div>
        </div>
        <div id="ai-settings-status"></div>
    </div>

    <h2>📊 Received Flags (Last 50)</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Technique</th><th>Manual</th><th>Manual Source</th><th>AI</th><th>AI Backend</th><th>Details</th></tr>
        {% for entry in logs %}
        <tr>
            <td class="timestamp">{{ entry.timestamp }}</td>
            <td>{{ entry.source_ip }}</td>
            <td class="flag">{{ entry.technique }}</td>
            <td>{{ 'yes' if entry.manual_detected else 'no' }}</td>
            <td>{{ entry.manual_source }}</td>
            <td>{{ 'yes' if entry.ai_detected else 'no' }} ({{ entry.ai_score }})</td>
            <td>{{ entry.ai_provider }}/{{ entry.ai_model }} ({{ entry.ai_mode }})</td>
            <td>{{ entry.details[:80] }}{% if entry.details|length > 80 %}...{% endif %}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>🤖 AI vs Manual Comparison</h2>
    <table>
        <tr><th>Total</th><th>Manual Hits</th><th>AI Hits</th><th>Agreement</th><th>Manual Only</th><th>AI Only</th><th>Neither</th></tr>
        <tr>
            <td>{{ detection_summary.total }}</td>
            <td>{{ detection_summary.manual_detected }}</td>
            <td>{{ detection_summary.ai_detected }}</td>
            <td>{{ detection_summary.agreement }} ({{ detection_summary.agreement_rate }})</td>
            <td>{{ detection_summary.manual_only }}</td>
            <td>{{ detection_summary.ai_only }}</td>
            <td>{{ detection_summary.neither }}</td>
        </tr>
    </table>

    <h2>⚠ Disagreements (Latest 20)</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Manual</th><th>AI</th><th>AI Score</th><th>Excerpt</th></tr>
        {% for row in detection_summary.disagreements %}
        <tr>
            <td class="timestamp">{{ row.timestamp }}</td>
            <td>{{ row.source_ip }}</td>
            <td>{{ 'yes' if row.manual_detected else 'no' }}</td>
            <td>{{ 'yes' if row.ai_detected else 'no' }}</td>
            <td>{{ row.ai_score }}</td>
            <td>{{ row.excerpt }}</td>
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
        <li><span class="endpoint">POST /manual/label</span> - Attach external manual verdict (Volatility/IR)</li>
        <li><span class="endpoint">AI Backend URL</span> - {{ ai_backend_url }}</li>
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
<script>
async function postJson(url, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {})
    });
    return response.json();
}

function setStatus(message) {
    document.getElementById('ai-settings-status').textContent = message;
}

async function saveAiSettings() {
    const ip = document.getElementById('ai-backend-ip').value.trim();
    const port = document.getElementById('ai-backend-port').value.trim();
    const timeout = document.getElementById('ai-timeout').value.trim();
    const result = await postJson('/api/settings/ai', { ip, port, timeout });
    setStatus(result.message || JSON.stringify(result));
}

async function startAiAnalysis() {
    const result = await postJson('/api/settings/ai/start', {});
    setStatus(result.message || JSON.stringify(result));
}

async function stopAiAnalysis() {
    const result = await postJson('/api/settings/ai/stop', {});
    setStatus(result.message || JSON.stringify(result));
}

async function testAiBackend() {
    const result = await postJson('/api/settings/ai/test', {
        text: 'FLAG{T1059.001-powershell-execution}'
    });
    setStatus(result.message || JSON.stringify(result));
}
</script>
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
    labels = load_manual_labels()
    log_file = Path(DEFAULT_CONFIG["log_dir"]) / "c2_log.json"
    if log_file.exists():
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    logs.append(apply_detection_fields(entry, labels))
                except:
                    pass
    logs = logs[-50:]
    detection_summary = summarize_detection(logs)

    payloads = [f.name for f in Path(DEFAULT_CONFIG["payload_dir"]).iterdir() if f.is_file()]
    backend = parse_backend_target(DEFAULT_CONFIG["ai_backend_url"])

    return render_template_string(DASHBOARD_HTML,
                                  logs=logs,
                                  detection_summary=detection_summary,
                                  payloads=payloads,
                                  sessions=active_sessions,
                                  ai_backend_url=DEFAULT_CONFIG["ai_backend_url"],
                                  ai_backend_ip=backend["ip"],
                                  ai_backend_port=backend["port"],
                                  ai_backend_timeout_seconds=DEFAULT_CONFIG["ai_backend_timeout_seconds"],
                                  ai_analysis_enabled=DEFAULT_CONFIG.get("ai_analysis_enabled", True),
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

    manual = manual_detect(flag_data)

    # Keep old behavior for manual extraction, with AI fallback for partial flags.
    technique = "Unknown"
    if manual["techniques"]:
        technique = manual["techniques"][0]

    event_id = str(uuid.uuid4())
    ai_result = get_ai_result(flag_data, event_id)

    if technique == "Unknown" and ai_result.get("techniques"):
        technique = ai_result["techniques"][0]

    # Log to JSON file
    log_entry = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "technique": technique,
        "details": flag_data[:200],
        "ai_detected": ai_result["detected"],
        "ai_score": ai_result["score"],
        "ai_reasons": ai_result["reasons"],
        "ai_techniques": ai_result["techniques"],
        "ai_provider": ai_result["provider"],
        "ai_model": ai_result["model"],
        "ai_mode": ai_result["mode"],
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

    return jsonify({
        "status": "logged",
        "event_id": log_entry["event_id"],
        "technique": technique,
        "manual_detected": manual["detected"],
        "ai_detected": ai_result["detected"],
        "ai_score": ai_result["score"],
        "ai_provider": ai_result["provider"],
        "ai_model": ai_result["model"],
        "ai_mode": ai_result["mode"],
        "agreement": manual["detected"] == ai_result["detected"],
    })


@app.route('/api/settings/ai', methods=['POST'])
def api_settings_ai():
    payload = request.get_json(silent=True) or {}
    ip = str(payload.get("ip", "")).strip()
    port = str(payload.get("port", "8090")).strip()
    timeout = str(payload.get("timeout", DEFAULT_CONFIG["ai_backend_timeout_seconds"]))

    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return jsonify({"status": "error", "message": "Invalid IP format"}), 400

    if not port.isdigit():
        return jsonify({"status": "error", "message": "Port must be numeric"}), 400

    timeout_int = int(timeout)
    if timeout_int < 1 or timeout_int > 120:
        return jsonify({"status": "error", "message": "Timeout must be between 1 and 120 seconds"}), 400

    DEFAULT_CONFIG["ai_backend_url"] = f"http://{ip}:{int(port)}/analyze"
    DEFAULT_CONFIG["ai_backend_timeout_seconds"] = timeout_int
    save_runtime_config()

    return jsonify({
        "status": "ok",
        "ai_backend_url": DEFAULT_CONFIG["ai_backend_url"],
        "message": f"Saved AI backend to {DEFAULT_CONFIG['ai_backend_url']}"
    })


@app.route('/api/settings/ai/start', methods=['POST'])
def api_settings_ai_start():
    DEFAULT_CONFIG["ai_analysis_enabled"] = True
    save_runtime_config()
    return jsonify({
        "status": "ok",
        "message": "AI analysis enabled"
    })


@app.route('/api/settings/ai/stop', methods=['POST'])
def api_settings_ai_stop():
    DEFAULT_CONFIG["ai_analysis_enabled"] = False
    save_runtime_config()
    return jsonify({
        "status": "ok",
        "message": "AI analysis disabled"
    })


@app.route('/api/settings/ai/test', methods=['POST'])
def api_settings_ai_test():
    payload = request.get_json(silent=True) or {}
    sample_text = payload.get("text", "FLAG{T1059.001-powershell-execution}")
    test_result = analyze_with_backend(
        sample_text,
        "dashboard-test",
        DEFAULT_CONFIG["ai_backend_url"],
        int(DEFAULT_CONFIG["ai_backend_timeout_seconds"]),
    )
    return jsonify({
        "status": "ok",
        "message": (
            f"Test result: detected={test_result['detected']} "
            f"score={test_result['score']} mode={test_result['mode']}"
        ),
        "result": test_result,
    })


@app.route('/manual/label', methods=['POST'])
def manual_label():
    payload = request.get_json(silent=True) or {}
    event_id = payload.get("event_id")
    timestamp = payload.get("timestamp")
    source_ip = payload.get("source_ip")
    detected = payload.get("detected")
    tool = payload.get("tool", "external")
    techniques = payload.get("techniques", [])
    notes = payload.get("notes", "")

    if detected is None:
        return jsonify({"error": "'detected' is required"}), 400

    if event_id:
        key = event_id
    elif timestamp and source_ip:
        key = f"{timestamp}|{source_ip}"
    else:
        return jsonify({"error": "Provide either event_id or (timestamp and source_ip)"}), 400

    labels = load_manual_labels()
    labels[key] = {
        "detected": bool(detected),
        "tool": tool,
        "techniques": techniques,
        "notes": notes,
        "labeled_at": datetime.datetime.now().isoformat(),
    }
    save_manual_labels(labels)
    return jsonify({"status": "saved", "key": key})

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
    labels = load_manual_labels()
    log_file = Path(DEFAULT_CONFIG["log_dir"]) / "c2_log.json"
    if log_file.exists():
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    flags.append(apply_detection_fields(entry, labels))
                except:
                    pass
    return jsonify({
        "flags": flags,
        "summary": summarize_detection(flags),
    })

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
