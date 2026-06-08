#!/usr/bin/env python3
"""Flag detection helpers for manual and AI-assisted comparison.

Extended with forensic artifact detection for memory dump analysis.
"""

import math
import re
from collections import Counter

FLAG_PATTERN = re.compile(r"FLAG\{([^{}\n]+)\}", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
PARTIAL_FLAG_PATTERN = re.compile(r"\bflag\s*\{", re.IGNORECASE)
BRACED_TOKEN_PATTERN = re.compile(r"\{([A-Z0-9_\-]{8,120})\}")

CONTEXT_KEYWORDS = {
    "powershell",
    "execution",
    "discovery",
    "exfiltration",
    "ingress",
    "c2",
    "mitre",
    "attack",
    "tactic",
    "technique",
}

# Forensic artifact patterns for memory-derived strings
C2_URL_PATTERN = re.compile(r"192\.168\.\d+\.\d+:\d+", re.IGNORECASE)
DOWNLOAD_CRADLE_PATTERN = re.compile(
    r"(Invoke-WebRequest|IEX\s*\(|DownloadString|New-Object\s+Net\.WebClient)",
    re.IGNORECASE,
)
BASE64_DECODE_PATTERN = re.compile(
    r"(System\.Convert::FromBase64String|FromBase64String)",
    re.IGNORECASE,
)
REGISTRY_RUN_PATTERN = re.compile(
    r"(CurrentVersion\\Run|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
    re.IGNORECASE,
)
WMI_PERSISTENCE_PATTERN = re.compile(
    r"(__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding|WmiPrvSE\.exe)",
    re.IGNORECASE,
)
POWERSHELL_BYPASS_PATTERN = re.compile(
    r"powershell\.exe.*-ExecutionPolicy\s+Bypass",
    re.IGNORECASE,
)
SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "WmiPrvSE.exe",
}


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _extract_techniques(text: str) -> list[str]:
    found = []
    seen = set()
    for match in TECHNIQUE_PATTERN.finditer(text or ""):
        technique = match.group(0).upper()
        if technique not in seen:
            seen.add(technique)
            found.append(technique)
    return found


def manual_detect(text: str) -> dict:
    text = text or ""
    flags = [match.group(0) for match in FLAG_PATTERN.finditer(text)]
    techniques = _extract_techniques("\n".join(flags) if flags else text)
    return {
        "detected": bool(flags),
        "flags": flags,
        "techniques": techniques,
    }


def ai_assisted_detect(text: str) -> dict:
    text = text or ""
    reasons = []
    score = 0.0

    manual = manual_detect(text)
    if manual["detected"]:
        score += 0.65
        reasons.append("strict FLAG{...} match")

    if PARTIAL_FLAG_PATTERN.search(text):
        score += 0.20
        reasons.append("partial flag marker")

    techniques = _extract_techniques(text)
    if techniques:
        score += 0.20
        reasons.append("MITRE technique marker")

    lowered = text.lower()
    keyword_hits = [word for word in CONTEXT_KEYWORDS if word in lowered]
    if keyword_hits:
        score += min(0.24, 0.08 * len(keyword_hits))
        reasons.append(f"context keywords ({', '.join(sorted(keyword_hits[:3]))})")

    braced_tokens = [match.group(1) for match in BRACED_TOKEN_PATTERN.finditer(text)]
    if braced_tokens:
        score += 0.15
        reasons.append("structured token in braces")

    entropy_value = _shannon_entropy(text)
    if entropy_value >= 3.6:
        score += 0.08
        reasons.append("high entropy payload")

    score = min(1.0, round(score, 3))
    detected = score >= 0.45

    detected_flags = manual["flags"]
    if not detected_flags and detected and techniques:
        detected_flags = [f"FLAG{{{techniques[0]}-inferred}}"]

    if not reasons:
        reasons.append("no strong indicators")

    return {
        "detected": detected,
        "score": score,
        "reasons": reasons,
        "flags": detected_flags,
        "techniques": techniques,
    }


def compare_detection(text: str) -> dict:
    manual = manual_detect(text)
    ai = ai_assisted_detect(text)
    return {
        "manual": manual,
        "ai": ai,
        "agreement": manual["detected"] == ai["detected"],
    }


def summarize_detection(log_entries: list[dict]) -> dict:
    summary = {
        "total": 0,
        "manual_detected": 0,
        "ai_detected": 0,
        "agreement": 0,
        "manual_only": 0,
        "ai_only": 0,
        "neither": 0,
        "disagreements": [],
    }

    for entry in log_entries:
        entry = entry or {}
        details = entry.get("details", "")
        manual_hit = entry.get("manual_detected")
        ai_hit = entry.get("ai_detected")
        ai_score = entry.get("ai_score")

        if manual_hit is None or ai_hit is None:
            comparison = compare_detection(details)
            manual_hit = comparison["manual"]["detected"]
            ai_hit = comparison["ai"]["detected"]
            ai_score = comparison["ai"]["score"]

        agreement = manual_hit == ai_hit

        summary["total"] += 1
        summary["manual_detected"] += int(manual_hit)
        summary["ai_detected"] += int(ai_hit)
        summary["agreement"] += int(agreement)

        if manual_hit and not ai_hit:
            summary["manual_only"] += 1
        elif ai_hit and not manual_hit:
            summary["ai_only"] += 1
        elif not manual_hit and not ai_hit:
            summary["neither"] += 1

        if not agreement and len(summary["disagreements"]) < 20:
            summary["disagreements"].append({
                "timestamp": entry.get("timestamp", "unknown"),
                "source_ip": entry.get("source_ip", "unknown"),
                "manual_detected": manual_hit,
                "ai_detected": ai_hit,
                "ai_score": ai_score,
                "excerpt": details[:120],
            })

    if summary["total"]:
        summary["agreement_rate"] = round(summary["agreement"] / summary["total"], 3)
    else:
        summary["agreement_rate"] = 0.0

    return summary


def forensic_detect_strings(strings_list: list[str]) -> dict:
    """Score a list of memory-extracted strings for forensic relevance.

    Returns a structured result similar to ai_assisted_detect so it can
    be fed into the same comparison pipeline.
    """
    text = "\n".join(strings_list) if strings_list else ""
    reasons = []
    score = 0.0
    flags = []
    techniques = []

    # Exact flag markers
    for s in strings_list:
        flags.extend([m.group(0) for m in FLAG_PATTERN.finditer(s)])
        techniques.extend(_extract_techniques(s))

    if flags:
        score += 0.65
        reasons.append("strict FLAG{...} match in memory strings")

    # C2 URL references
    c2_urls = []
    for s in strings_list:
        c2_urls.extend(C2_URL_PATTERN.findall(s))
    if c2_urls:
        score += 0.30
        reasons.append("C2 URL in memory strings")

    # Download cradle indicators
    cradle_hits = []
    for s in strings_list:
        cradle_hits.extend(DOWNLOAD_CRADLE_PATTERN.findall(s))
    if cradle_hits:
        score += 0.25
        reasons.append("PowerShell download cradle in memory")

    # Base64 decode at runtime
    base64_hits = []
    for s in strings_list:
        base64_hits.extend(BASE64_DECODE_PATTERN.findall(s))
    if base64_hits:
        score += 0.20
        reasons.append("Base64 decode routine in memory")

    # Registry persistence
    reg_hits = []
    for s in strings_list:
        reg_hits.extend(REGISTRY_RUN_PATTERN.findall(s))
    if reg_hits:
        score += 0.20
        reasons.append("registry Run key persistence in memory")

    # WMI persistence
    wmi_hits = []
    for s in strings_list:
        wmi_hits.extend(WMI_PERSISTENCE_PATTERN.findall(s))
    if wmi_hits:
        score += 0.20
        reasons.append("WMI persistence artifact in memory")

    # PowerShell bypass
    bypass_hits = []
    for s in strings_list:
        bypass_hits.extend(POWERSHELL_BYPASS_PATTERN.findall(s))
    if bypass_hits:
        score += 0.25
        reasons.append("PowerShell execution-policy bypass in memory")

    # Context keywords
    lowered = text.lower()
    keyword_hits = [word for word in CONTEXT_KEYWORDS if word in lowered]
    if keyword_hits:
        score += min(0.24, 0.08 * len(keyword_hits))
        reasons.append(f"context keywords ({', '.join(sorted(keyword_hits[:3]))})")

    score = min(1.0, round(score, 3))
    detected = score >= 0.45

    techniques = list(dict.fromkeys(techniques))
    if not flags and detected and techniques:
        flags = [f"FLAG{{{techniques[0]}-inferred}}"]

    if not reasons:
        reasons.append("no strong forensic indicators")

    return {
        "detected": detected,
        "score": score,
        "reasons": reasons,
        "flags": flags,
        "techniques": techniques,
        "c2_urls": list(set(c2_urls)) if c2_urls else [],
        "cradle_hits": list(set(cradle_hits)) if cradle_hits else [],
        "base64_hits": list(set(base64_hits)) if base64_hits else [],
        "registry_hits": list(set(reg_hits)) if reg_hits else [],
        "wmi_hits": list(set(wmi_hits)) if wmi_hits else [],
        "bypass_hits": list(set(bypass_hits)) if bypass_hits else [],
    }


def forensic_detect_process(process_entry: dict) -> dict:
    """Score a single process record for suspiciousness.

    process_entry should contain keys like:
        name, pid, ppid, cmdline, CreateTime, etc.
    """
    name = (process_entry.get("name") or process_entry.get("ImageFileName") or "").lower()
    cmdline = (process_entry.get("cmdline") or process_entry.get("Args") or "")
    score = 0.0
    reasons = []

    if name in {n.lower() for n in SUSPICIOUS_PROCESS_NAMES}:
        score += 0.25
        reasons.append(f"suspicious process name: {name}")

    cmd_lower = cmdline.lower()
    if "invoke-webrequest" in cmd_lower or "iex" in cmd_lower:
        score += 0.35
        reasons.append("download/execute in command line")
    if "192.168." in cmd_lower and ":8080" in cmd_lower:
        score += 0.30
        reasons.append("C2 URL in command line")
    if "-executionpolicy bypass" in cmd_lower:
        score += 0.25
        reasons.append("execution policy bypass")
    if "-windowstyle hidden" in cmd_lower:
        score += 0.20
        reasons.append("hidden window style")
    if "frombase64string" in cmd_lower:
        score += 0.20
        reasons.append("Base64 decode in command line")
    if "currentversion\\run" in cmd_lower:
        score += 0.20
        reasons.append("registry Run key reference")
    if "__eventfilter" in cmd_lower or "commandlineeventconsumer" in cmd_lower:
        score += 0.20
        reasons.append("WMI persistence reference")

    flags = [m.group(0) for m in FLAG_PATTERN.finditer(cmdline)]
    if flags:
        score += 0.40
        reasons.append("FLAG marker in command line")

    techniques = _extract_techniques(cmdline)

    score = min(1.0, round(score, 3))
    detected = score >= 0.45

    return {
        "detected": detected,
        "score": score,
        "reasons": reasons,
        "flags": flags,
        "techniques": techniques,
    }


def compare_forensic_detection(strings_list: list[str],
                               process_entry: dict = None) -> dict:
    """Compare forensic string detection with process-level detection."""
    strings_result = forensic_detect_strings(strings_list)
    proc_result = forensic_detect_process(process_entry or {})
    agreement = strings_result["detected"] == proc_result["detected"]
    return {
        "strings": strings_result,
        "process": proc_result,
        "agreement": agreement,
    }
