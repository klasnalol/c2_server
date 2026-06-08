#!/usr/bin/env python3
"""Forensic analysis orchestrator for memory dump investigation.

Wraps Volatility3, MemProcFS (if available), YARA, strings, and C2 log
correlation. Designed to support the methodology described in the diploma
work: triage, extraction, correlation, scan, manual review, and reporting.
"""

import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

# Optional imports
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
VOLATILITY_BIN = (BASE_DIR / ".venv" / "bin" / "vol").resolve()
if not VOLATILITY_BIN.exists():
    VOLATILITY_BIN = "vol"

FORENSIC_CONFIG_FILE = BASE_DIR / "forensic_config.json"
C2_LOG_FILE = BASE_DIR / "logs" / "c2_log.json"
YARA_RULES_DIR = BASE_DIR / "yara_rules"

DEFAULT_FORENSIC_CONFIG = {
    "volatility_bin": str(VOLATILITY_BIN),
    "yara_rules_dir": str(YARA_RULES_DIR),
    "strings_min_length": 8,
    "output_dir": str(BASE_DIR / "forensic_output"),
    "ai_backend_url": "http://127.0.0.1:8090/analyze",
    "ai_backend_timeout_seconds": 15,
    "c2_log_file": str(C2_LOG_FILE),
    "correlation_window_seconds": 300,
    "c2_ip_hint": "192.168.122.1",
    "c2_port_hint": 8080,
}

# ATT&CK-mapped indicators for memory triage
C2_INDICATORS = [
    r"FLAG\{[^{}\n]+\}",
    r"192\.168\.\d+\.\d+:\d+",
    r"Invoke-WebRequest",
    r"IEX\s*\(",
    r"New-Object\s+Net\.WebClient",
    r"DownloadString",
    r"T\d{4}(?:\.\d{3})?",
    r"System\.Convert::FromBase64String",
    r"powershell\.exe\s+-NoProfile",
    r"-ExecutionPolicy\s+Bypass",
]


def load_forensic_config() -> dict:
    cfg = dict(DEFAULT_FORENSIC_CONFIG)
    if FORENSIC_CONFIG_FILE.exists():
        try:
            with open(FORENSIC_CONFIG_FILE, "r") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
        except Exception:
            pass
    return cfg


def save_forensic_config(cfg: dict):
    with open(FORENSIC_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)


def _run_volatility(dump_path: str, plugin: str, extra_args: list[str] = None,
                    vol_bin: str = None, output_dir: str = None) -> dict:
    """Run a Volatility3 plugin and return structured output."""
    vol_bin = vol_bin or str(VOLATILITY_BIN)
    args = [vol_bin, "-f", dump_path, "-r", "json", plugin]
    if extra_args:
        args.extend(extra_args)
    if output_dir:
        args.extend(["-o", output_dir])

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "plugin": plugin, "records": []}
    except FileNotFoundError:
        return {"error": "volatility not found", "plugin": plugin, "records": []}

    records = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return {
        "plugin": plugin,
        "returncode": result.returncode,
        "stderr": result.stderr.strip()[:500] if result.stderr else "",
        "records": records,
    }


def run_info(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.info.Info", vol_bin=vol_bin)


def run_pslist(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.pslist.PsList", vol_bin=vol_bin)


def run_psscan(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.psscan.PsScan", vol_bin=vol_bin)


def run_pstree(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.pstree.PsTree", vol_bin=vol_bin)


def run_cmdline(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.cmdline.CmdLine", vol_bin=vol_bin)


def run_netscan(dump_path: str, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.netscan.NetScan", vol_bin=vol_bin)


def run_vadinfo(dump_path: str, pid: int, vol_bin: str = None) -> dict:
    return _run_volatility(dump_path, "windows.vadinfo.VadInfo",
                           extra_args=["--pid", str(pid)], vol_bin=vol_bin)


def run_malfind(dump_path: str, pid: int = None, vol_bin: str = None) -> dict:
    extra = []
    if pid is not None:
        extra = ["--pid", str(pid)]
    return _run_volatility(dump_path, "windows.malfind.Malfind",
                           extra_args=extra, vol_bin=vol_bin)


def run_envars(dump_path: str, pid: int = None, vol_bin: str = None) -> dict:
    extra = []
    if pid is not None:
        extra = ["--pid", str(pid)]
    return _run_volatility(dump_path, "windows.envars.Envars",
                           extra_args=extra, vol_bin=vol_bin)


def run_dlllist(dump_path: str, pid: int = None, vol_bin: str = None) -> dict:
    extra = []
    if pid is not None:
        extra = ["--pid", str(pid)]
    return _run_volatility(dump_path, "windows.dlllist.DllList",
                           extra_args=extra, vol_bin=vol_bin)


def dump_vad_region(dump_path: str, pid: int, output_dir: str,
                    vol_bin: str = None) -> dict:
    """Dump VAD regions for a PID to output_dir using dumpfiles or memmap."""
    os.makedirs(output_dir, exist_ok=True)
    # Use windows.memmap.Memmap to dump process memory
    return _run_volatility(
        dump_path,
        "windows.memmap.Memmap",
        extra_args=["--pid", str(pid), "--dump"],
        vol_bin=vol_bin,
        output_dir=output_dir,
    )


def extract_strings_from_file(filepath: str, min_length: int = 8) -> list[str]:
    """Run `strings` on a file and return decoded strings."""
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_length), filepath],
            capture_output=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    strings_found = []
    for line in result.stdout.splitlines():
        try:
            decoded = line.decode("utf-8", errors="ignore")
            if decoded.strip():
                strings_found.append(decoded.strip())
        except Exception:
            continue
    return strings_found


def extract_strings_from_dump(dump_path: str, min_length: int = 8) -> list[str]:
    return extract_strings_from_file(dump_path, min_length)


def search_indicators(strings_list: list[str],
                      patterns: list[str] = None) -> list[dict]:
    """Search extracted strings for C2/ATT&CK indicators."""
    patterns = patterns or C2_INDICATORS
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    hits = []
    for s in strings_list:
        for pat in compiled:
            if pat.search(s):
                hits.append({
                    "string": s,
                    "pattern": pat.pattern,
                    "offset": None,
                })
                break
    return hits


def load_yara_rules(rules_dir: str = None) -> Any:
    """Compile YARA rules from directory."""
    if not YARA_AVAILABLE:
        return None
    rules_dir = Path(rules_dir or YARA_RULES_DIR)
    if not rules_dir.exists():
        return None

    rule_sources = {}
    for f in rules_dir.glob("*.yar"):
        try:
            with open(f, "r") as handle:
                rule_sources[f.name] = handle.read()
        except Exception:
            continue

    if not rule_sources:
        return None
    try:
        return yara.compile(sources=rule_sources)
    except Exception:
        return None


def scan_with_yara(target_path: str, rules: Any = None) -> list[dict]:
    """Scan a file or directory with YARA rules."""
    if not YARA_AVAILABLE or rules is None:
        return []

    target = Path(target_path)
    if not target.exists():
        return []

    matches = []
    files_to_scan = [target] if target.is_file() else list(target.rglob("*"))

    for f in files_to_scan:
        if not f.is_file():
            continue
        try:
            for match in rules.match(str(f)):
                string_matches = []
                for s in (match.strings or []):
                    # Handle both old tuple API and new object API
                    if hasattr(s, "identifier"):
                        # yara-python >= 4.3.0
                        for instance in (s.instances or []):
                            raw = instance.matched_data
                            data = ""
                            if raw:
                                try:
                                    data = raw[:200].decode("utf-8", errors="replace")
                                except Exception:
                                    data = raw[:200].hex()
                            string_matches.append({
                                "identifier": s.identifier,
                                "offset": instance.offset,
                                "data": data,
                            })
                    else:
                        # older tuple API (identifier, offset, data)
                        string_matches.append({
                            "identifier": s[0],
                            "offset": s[1],
                            "data": s[2][:200] if s[2] else "",
                        })
                matches.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "strings": string_matches,
                    "file": str(f),
                })
        except Exception:
            continue
    return matches


def correlate_with_c2(events: list[dict],
                      c2_log_path: str = None,
                      window_seconds: int = 300) -> dict:
    """Correlate memory-derived events with C2 server logs."""
    c2_log_path = c2_log_path or str(C2_LOG_FILE)
    c2_events = []
    if Path(c2_log_path).exists():
        with open(c2_log_path, "r") as f:
            for line in f:
                try:
                    c2_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Build a simple correlation map: match source IP, technique markers,
    # and timestamps within a window.
    correlations = []
    for mem_event in events:
        for c2_event in c2_events:
            score = 0
            reasons = []

            # Technique match
            mem_tech = mem_event.get("technique", "")
            c2_tech = c2_event.get("technique", "")
            if mem_tech and c2_tech and mem_tech == c2_tech:
                score += 0.4
                reasons.append("technique match")

            # Source IP match
            mem_ip = mem_event.get("source_ip", "")
            c2_ip = c2_event.get("source_ip", "")
            if mem_ip and c2_ip and mem_ip == c2_ip:
                score += 0.3
                reasons.append("source IP match")

            # Timestamp proximity
            mem_ts = mem_event.get("timestamp", "")
            c2_ts = c2_event.get("timestamp", "")
            if mem_ts and c2_ts:
                try:
                    t1 = datetime.fromisoformat(mem_ts.replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(c2_ts.replace("Z", "+00:00"))
                    delta = abs((t1 - t2).total_seconds())
                    if delta <= window_seconds:
                        score += max(0, 0.3 - (delta / window_seconds) * 0.3)
                        reasons.append(f"timestamp proximity ({int(delta)}s)")
                except Exception:
                    pass

            if score > 0:
                correlations.append({
                    "memory_event": mem_event,
                    "c2_event": c2_event,
                    "correlation_score": round(score, 3),
                    "reasons": reasons,
                })

    return {
        "c2_events_count": len(c2_events),
        "correlations": sorted(correlations,
                               key=lambda x: x["correlation_score"],
                               reverse=True),
    }


def ai_triage_artifact(text: str, artifact_type: str = "memory_string",
                       backend_url: str = None, timeout: int = 15) -> dict:
    """Send an extracted artifact to the AI backend for triage scoring."""
    backend_url = backend_url or DEFAULT_FORENSIC_CONFIG["ai_backend_url"]
    body = {
        "text": text,
        "event_id": f"forensic-{artifact_type}",
    }
    req = urllib.request.Request(
        backend_url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(raw)
            result = payload.get("result", {})
            return {
                "detected": bool(result.get("detected", False)),
                "score": float(result.get("score", 0.0)),
                "reasons": result.get("reasons", []),
                "techniques": result.get("techniques", []),
                "provider": result.get("provider", "unknown"),
                "model": result.get("model", "unknown"),
                "mode": result.get("mode", "model"),
            }
    except Exception as exc:
        return {
            "detected": False,
            "score": 0.0,
            "reasons": [f"backend error: {type(exc).__name__}"],
            "techniques": [],
            "provider": "unavailable",
            "model": "unavailable",
            "mode": "error",
        }


class ForensicAnalyzer:
    """High-level forensic analysis orchestrator."""

    def __init__(self, dump_path: str, config: dict = None):
        self.dump_path = dump_path
        self.config = config or load_forensic_config()
        self.vol_bin = self.config.get("volatility_bin", str(VOLATILITY_BIN))
        self.output_dir = Path(self.config.get("output_dir",
                                               str(BASE_DIR / "forensic_output")))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report = {
            "dump_path": dump_path,
            "analyzed_at": datetime.now().isoformat(),
            "phases": {},
        }
        self._yara_rules = None

    def _phase(self, name: str, data: dict):
        self.report["phases"][name] = data

    def triage(self) -> dict:
        """Phase 1: Basic system info and process triage."""
        info = run_info(self.dump_path, self.vol_bin)
        pslist = run_pslist(self.dump_path, self.vol_bin)
        psscan = run_psscan(self.dump_path, self.vol_bin)
        pstree = run_pstree(self.dump_path, self.vol_bin)
        self._phase("triage", {
            "info": info,
            "pslist": pslist,
            "psscan": psscan,
            "pstree": pstree,
        })
        return self.report["phases"]["triage"]

    def extract_cmdline(self) -> dict:
        """Phase 2: Command-line extraction."""
        cmdline = run_cmdline(self.dump_path, self.vol_bin)
        self._phase("cmdline", cmdline)
        return cmdline

    def extract_network(self) -> dict:
        """Phase 3: Network artifact recovery."""
        netscan = run_netscan(self.dump_path, self.vol_bin)
        self._phase("network", netscan)
        return netscan

    def inspect_vad_and_malfind(self, pid: int = None) -> dict:
        """Phase 4: VAD inspection and malfind for prioritized PIDs."""
        result = {"vadinfo": {}, "malfind": {}, "dumped_regions": []}
        if pid:
            result["vadinfo"][pid] = run_vadinfo(self.dump_path, pid, self.vol_bin)
            result["malfind"][pid] = run_malfind(self.dump_path, pid, self.vol_bin)
            dump_dir = str(self.output_dir / f"pid_{pid}_regions")
            dumped = dump_vad_region(self.dump_path, pid, dump_dir, self.vol_bin)
            result["dumped_regions"].append({"pid": pid, "output_dir": dump_dir,
                                             "dump_result": dumped})
        self._phase("vad_malfind", result)
        return result

    def extract_strings(self, region_dir: str = None) -> dict:
        """Phase 5: String extraction from dump or exported regions."""
        all_strings = []
        source = "full_dump"
        if region_dir and Path(region_dir).exists():
            source = "exported_regions"
            for f in Path(region_dir).rglob("*"):
                if f.is_file():
                    all_strings.extend(extract_strings_from_file(
                        str(f), self.config.get("strings_min_length", 8)))
        else:
            all_strings = extract_strings_from_dump(
                self.dump_path, self.config.get("strings_min_length", 8))

        indicators = search_indicators(all_strings)
        self._phase("strings", {
            "source": source,
            "total_strings": len(all_strings),
            "indicator_hits": indicators,
        })
        return self.report["phases"]["strings"]

    def scan_yara(self, target: str = None) -> dict:
        """Phase 6: YARA-style rule matching."""
        if self._yara_rules is None:
            self._yara_rules = load_yara_rules(self.config.get("yara_rules_dir"))

        target = target or self.dump_path
        matches = scan_with_yara(target, self._yara_rules)
        self._phase("yara", {
            "target": target,
            "matches": matches,
        })
        return self.report["phases"]["yara"]

    def correlate(self, events: list[dict] = None) -> dict:
        """Phase 7: Correlate findings with C2 logs."""
        if events is None:
            # Build simple events from indicator hits
            strings_phase = self.report["phases"].get("strings", {})
            hits = strings_phase.get("indicator_hits", [])
            events = [{"details": h["string"], "timestamp": "",
                       "source_ip": "", "technique": ""} for h in hits]
        corr = correlate_with_c2(
            events,
            self.config.get("c2_log_file"),
            self.config.get("correlation_window_seconds", 300),
        )
        self._phase("correlation", corr)
        return corr

    def ai_triage(self, max_artifacts: int = 20) -> dict:
        """Phase 8: AI-assisted triage of top string indicators."""
        strings_phase = self.report["phases"].get("strings", {})
        hits = strings_phase.get("indicator_hits", [])[:max_artifacts]
        triage_results = []
        for hit in hits:
            result = ai_triage_artifact(
                hit["string"],
                backend_url=self.config.get("ai_backend_url"),
                timeout=self.config.get("ai_backend_timeout_seconds", 15),
            )
            triage_results.append({
                "string": hit["string"],
                "pattern": hit["pattern"],
                "ai": result,
            })
        self._phase("ai_triage", {"artifacts_scored": len(triage_results),
                                   "results": triage_results})
        return self.report["phases"]["ai_triage"]

    def prioritize_processes(self) -> list[dict]:
        """Build a prioritized list of suspicious processes from triage data."""
        triage = self.report["phases"].get("triage", {})
        pslist = triage.get("pslist", {})
        cmdline = self.report["phases"].get("cmdline", {})
        network = self.report["phases"].get("network", {})

        processes = {}
        for rec in pslist.get("records", []):
            row = rec.get("__children", [rec])[0] if "__children" in rec else rec
            pid = row.get("PID", row.get("pid", "unknown"))
            processes[pid] = {
                "pid": pid,
                "ppid": row.get("PPID", row.get("ppid", "")),
                "name": row.get("ImageFileName", row.get("name", "")),
                "start_time": row.get("CreateTime", ""),
                "score": 0.0,
                "reasons": [],
            }

        # Boost for PowerShell / cmd / WMI
        suspicious_names = ["powershell.exe", "cmd.exe", "wscript.exe",
                            "cscript.exe", "mshta.exe", "WmiPrvSE.exe"]
        for p in processes.values():
            name_lower = (p["name"] or "").lower()
            if any(s in name_lower for s in suspicious_names):
                p["score"] += 0.3
                p["reasons"].append("suspicious process name")

        # Boost for cmdline containing C2 indicators
        for rec in cmdline.get("records", []):
            row = rec.get("__children", [rec])[0] if "__children" in rec else rec
            pid = row.get("PID", row.get("pid", ""))
            args = row.get("Args", row.get("args", ""))
            if pid in processes and args:
                args_lower = args.lower()
                if "invoke-webrequest" in args_lower or "iex" in args_lower:
                    processes[pid]["score"] += 0.4
                    processes[pid]["reasons"].append("download/execute in cmdline")
                if "192.168." in args_lower and ":8080" in args_lower:
                    processes[pid]["score"] += 0.3
                    processes[pid]["reasons"].append("C2 URL in cmdline")

        # Boost for network connections to C2
        for rec in network.get("records", []):
            row = rec.get("__children", [rec])[0] if "__children" in rec else rec
            pid = row.get("PID", row.get("pid", ""))
            remote = row.get("ForeignAddr", row.get("remote", ""))
            if pid in processes and remote:
                if "192.168." in remote and ":8080" in remote:
                    processes[pid]["score"] += 0.3
                    processes[pid]["reasons"].append("C2 socket")

        sorted_procs = sorted(processes.values(),
                              key=lambda x: x["score"],
                              reverse=True)
        self._phase("prioritized_processes", sorted_procs)
        return sorted_procs

    def full_analysis(self, target_pid: int = None) -> dict:
        """Run the complete forensic workflow."""
        self.triage()
        self.extract_cmdline()
        self.extract_network()
        prioritized = self.prioritize_processes()

        # Inspect top suspicious PID if none given
        if target_pid is None and prioritized:
            for p in prioritized:
                if p["score"] > 0:
                    target_pid = p["pid"]
                    break

        if target_pid:
            self.inspect_vad_and_malfind(target_pid)
            region_dir = str(self.output_dir / f"pid_{target_pid}_regions")
            self.extract_strings(region_dir)
            self.scan_yara(region_dir)
        else:
            self.extract_strings()
            self.scan_yara(self.dump_path)

        self.correlate()
        self.ai_triage()
        return self.report

    def save_report(self, filepath: str = None) -> str:
        """Save the JSON report to disk."""
        if filepath is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"forensic_report_{ts}.json"
            filepath = str(self.output_dir / name)
        with open(filepath, "w") as f:
            json.dump(self.report, f, indent=2)
        return filepath


# --- Convenience wrappers for direct import / CLI ---

def analyze_dump(dump_path: str, target_pid: int = None,
                 output_dir: str = None, config: dict = None) -> dict:
    """Run full forensic analysis on a memory dump and return the report."""
    cfg = dict(config or load_forensic_config())
    if output_dir:
        cfg["output_dir"] = output_dir
    analyzer = ForensicAnalyzer(dump_path, cfg)
    analyzer.full_analysis(target_pid)
    report_path = analyzer.save_report()
    analyzer.report["report_path"] = report_path
    return analyzer.report



# ============================================================
# Async task tracking + enhanced reporting
# ============================================================

import threading
import uuid

_TASKS = {}
_TASKS_LOCK = threading.Lock()
_MAX_TASKS = 50          # Keep at most this many tasks in memory
_TASK_RETENTION_SEC = 1800  # 30 minutes before pruning completed tasks


def _update_task(task_id: str, update: dict):
    with _TASKS_LOCK:
        if task_id in _TASKS:
            _TASKS[task_id].update(update)


def _prune_tasks():
    """Remove oldest completed/failed tasks if we exceed _MAX_TASKS or retention time."""
    with _TASKS_LOCK:
        now = datetime.now()
        # First prune by retention
        to_remove = []
        for tid, t in _TASKS.items():
            status = t.get("status", "")
            if status in ("completed", "error", "failed"):
                created = t.get("created_at", "")
                if created:
                    try:
                        dt = datetime.fromisoformat(created)
                        if (now - dt).total_seconds() > _TASK_RETENTION_SEC:
                            to_remove.append(tid)
                    except Exception:
                        pass
        # Then prune by count (oldest completed/error/failed first) if still over limit
        for tid in to_remove:
            _TASKS.pop(tid, None)
        if len(_TASKS) > _MAX_TASKS:
            removable = [
                (tid, t) for tid, t in _TASKS.items()
                if t.get("status", "") in ("completed", "error", "failed")
            ]
            removable.sort(key=lambda x: x[1].get("created_at", ""))
            excess = len(_TASKS) - _MAX_TASKS
            for tid, _ in removable[:excess]:
                _TASKS.pop(tid, None)


def run_forensic_task(task_id: str, dump_path: str, target_pid: int = None,
                      config: dict = None):
    """Run forensic analysis in background and update task status."""
    _update_task(task_id, {
        "status": "running",
        "progress": 0,
        "message": "Starting analysis...",
        "phases_completed": [],
    })

    cfg = dict(config or load_forensic_config())
    analyzer = ForensicAnalyzer(dump_path, cfg)

    phases = [
        ("triage", "Running triage: info, pslist, psscan, pstree..."),
        ("cmdline", "Extracting command lines..."),
        ("network", "Recovering network artifacts..."),
        ("prioritize", "Prioritizing suspicious processes..."),
        ("vad_malfind", "Inspecting VAD regions and malfind..."),
        ("strings", "Extracting strings and indicators..."),
        ("yara", "Running YARA scan..."),
        ("correlate", "Correlating with C2 logs..."),
        ("ai_triage", "AI-assisted triage..."),
    ]

    try:
        analyzer.triage()
        _update_task(task_id, {"progress": 11, "phases_completed": ["triage"],
                                "message": phases[1][1]})

        analyzer.extract_cmdline()
        _update_task(task_id, {"progress": 22, "phases_completed": ["triage", "cmdline"],
                                "message": phases[2][1]})

        analyzer.extract_network()
        _update_task(task_id, {"progress": 33, "phases_completed": ["triage", "cmdline", "network"],
                                "message": phases[3][1]})

        prioritized = analyzer.prioritize_processes()
        _update_task(task_id, {"progress": 44, "phases_completed": ["triage", "cmdline", "network", "prioritize"],
                                "message": phases[4][1], "prioritized_processes": prioritized[:5]})

        if target_pid is None and prioritized:
            for p in prioritized:
                if p["score"] > 0:
                    target_pid = p["pid"]
                    break

        if target_pid:
            _update_task(task_id, {
                "progress": 48,
                "message": f"Inspecting VAD/malfind for PID {target_pid}... (may take a few minutes on large dumps)",
            })
            analyzer.inspect_vad_and_malfind(target_pid)
            _update_task(task_id, {"progress": 55, "message": "Extracting strings from memory regions..."})
            region_dir = str(analyzer.output_dir / f"pid_{target_pid}_regions")
            analyzer.extract_strings(region_dir)
            _update_task(task_id, {"progress": 60, "message": "Running YARA scan on memory regions..."})
            analyzer.scan_yara(region_dir)
        else:
            _update_task(task_id, {"progress": 50, "message": "Extracting strings from full dump..."})
            analyzer.extract_strings()
            _update_task(task_id, {"progress": 60, "message": "Running YARA scan on full dump..."})
            analyzer.scan_yara(analyzer.dump_path)

        _update_task(task_id, {"progress": 66, "phases_completed": ["triage", "cmdline", "network", "prioritize", "vad_malfind", "strings", "yara"],
                                "message": phases[7][1]})

        analyzer.correlate()
        _update_task(task_id, {"progress": 77, "phases_completed": ["triage", "cmdline", "network", "prioritize", "vad_malfind", "strings", "yara", "correlate"],
                                "message": phases[8][1]})

        analyzer.ai_triage()
        _update_task(task_id, {"progress": 88, "phases_completed": ["triage", "cmdline", "network", "prioritize", "vad_malfind", "strings", "yara", "correlate", "ai_triage"],
                                "message": "Finalizing report..."})

        # Enhance report with human-readable findings
        enhanced = _enhance_report(analyzer.report)
        analyzer.report["findings"] = enhanced["findings"]
        analyzer.report["summary"] = enhanced["summary"]

        report_path = analyzer.save_report()
        _update_task(task_id, {
            "status": "completed",
            "progress": 100,
            "message": "Analysis complete",
            "report_path": report_path,
            "report": analyzer.report,
            "phases_completed": [p[0] for p in phases],
        })

    except Exception as exc:
        _update_task(task_id, {
            "status": "error",
            "progress": 0,
            "message": f"Error: {exc}",
        })
    finally:
        _prune_tasks()


def start_forensic_task(dump_path: str, target_pid: int = None,
                        config: dict = None) -> str:
    """Start a background forensic task and return task ID."""
    _prune_tasks()
    task_id = str(uuid.uuid4())
    with _TASKS_LOCK:
        _TASKS[task_id] = {
            "id": task_id,
            "status": "queued",
            "progress": 0,
            "message": "Queued...",
            "dump_path": dump_path,
            "created_at": datetime.now().isoformat(),
        }

    t = threading.Thread(
        target=run_forensic_task,
        args=(task_id, dump_path, target_pid, config),
        daemon=True,
    )
    t.start()
    return task_id


def get_task(task_id: str) -> dict:
    """Get task status by ID."""
    with _TASKS_LOCK:
        return dict(_TASKS.get(task_id, {}))


def list_tasks() -> list[dict]:
    """List all tasks, newest first."""
    _prune_tasks()
    with _TASKS_LOCK:
        return sorted(_TASKS.values(), key=lambda x: x.get("created_at", ""), reverse=True)


def _enhance_report(report: dict) -> dict:
    """Build a human-readable findings list from the raw report."""
    findings = []
    phases = report.get("phases", {})

    # Process findings
    triage = phases.get("triage", {})
    pslist = triage.get("pslist", {})
    for rec in pslist.get("records", [])[:20]:
        row = rec.get("__children", [rec])[0] if "__children" in rec else rec
        name = row.get("ImageFileName", row.get("name", ""))
        pid = row.get("PID", row.get("pid", ""))
        if name and pid:
            findings.append({
                "type": "process",
                "severity": "info",
                "what": f"Process {name} (PID {pid})",
                "where": "windows.pslist",
                "why": "Baseline process enumeration",
            })

    prioritized = phases.get("prioritized_processes", [])
    for p in prioritized[:5]:
        if p.get("score", 0) > 0:
            findings.append({
                "type": "suspicious_process",
                "severity": "high",
                "what": f"{p.get('name', 'Unknown')} (PID {p.get('pid', '?')})",
                "where": "Prioritized process scoring",
                "why": f"Score {p['score']:.2f}: {', '.join(p.get('reasons', []))}",
            })

    # Command-line findings
    cmdline = phases.get("cmdline", {})
    for rec in cmdline.get("records", [])[:10]:
        row = rec.get("__children", [rec])[0] if "__children" in rec else rec
        pid = row.get("PID", row.get("pid", ""))
        args = row.get("Args", row.get("args", ""))
        if args:
            flag_matches = [m.group(0) for m in re.finditer(r"FLAG\{[^{}\n]+\}", args, re.IGNORECASE)]
            c2_match = re.search(r"192\.168\.\d+\.\d+:\d+", args)
            if flag_matches or c2_match or "powershell" in args.lower():
                findings.append({
                    "type": "command_line",
                    "severity": "critical" if (flag_matches or c2_match) else "medium",
                    "what": args[:120],
                    "where": f"PID {pid} command line",
                    "why": f"{'FLAG marker found; ' if flag_matches else ''}{'C2 URL found; ' if c2_match else ''}{'PowerShell execution' if 'powershell' in args.lower() else 'Suspicious command-line pattern'}",
                })

    # Network findings
    network = phases.get("network", {})
    for rec in network.get("records", [])[:10]:
        row = rec.get("__children", [rec])[0] if "__children" in rec else rec
        pid = row.get("PID", row.get("pid", ""))
        proc = row.get("Owner", row.get("process", ""))
        remote = row.get("ForeignAddr", row.get("remote", ""))
        state = row.get("State", "")
        if remote and "192.168.122.1:8080" in remote:
            findings.append({
                "type": "network",
                "severity": "high",
                "what": f"{proc or 'Unknown'} (PID {pid}) -> {remote} [{state}]",
                "where": "windows.netscan",
                "why": "Connection to C2 server (192.168.122.1:8080)",
            })

    # String indicator findings
    strings_phase = phases.get("strings", {})
    for hit in strings_phase.get("indicator_hits", [])[:15]:
        findings.append({
            "type": "memory_string",
            "severity": "high" if "FLAG" in hit["string"] else "medium",
            "what": hit["string"][:200],
            "where": "Extracted strings from memory dump",
            "why": f"Matched pattern: {hit['pattern']}",
        })

    # YARA findings
    yara_phase = phases.get("yara", {})
    for match in yara_phase.get("matches", [])[:10]:
        rule = match.get("rule", "")
        file_path = match.get("file", "")
        findings.append({
            "type": "yara",
            "severity": "high",
            "what": rule,
            "where": file_path,
            "why": f"YARA rule matched: {rule}",
        })

    # C2 correlation findings
    corr = phases.get("correlation", {})
    for c in corr.get("correlations", [])[:10]:
        c2_event = c.get("c2_event", {})
        findings.append({
            "type": "c2_correlation",
            "severity": "high",
            "what": f"Technique {c2_event.get('technique', '?')}",
            "where": "C2 log correlation",
            "why": f"Correlation score {c['correlation_score']:.2f}: {', '.join(c.get('reasons', []))}",
        })

    # AI triage findings
    ai_phase = phases.get("ai_triage", {})
    for r in ai_phase.get("results", [])[:10]:
        if r.get("ai_detected") or (r.get("ai_score", 0) >= 0.5):
            findings.append({
                "type": "ai_triage",
                "severity": "high" if r.get("ai_detected") else "medium",
                "what": r.get("artifact", "")[:120],
                "where": f"AI backend ({r.get('pattern', 'unknown')})",
                "why": r.get("ai_explanation", f"AI score: {r.get('ai_score', 0):.2f}") or f"AI score: {r.get('ai_score', 0):.2f}",
            })

    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
        "info": sum(1 for f in findings if f["severity"] == "info"),
    }

    return {"findings": findings, "summary": summary}
