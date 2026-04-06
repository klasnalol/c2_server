#!/usr/bin/env python3
"""Flag detection helpers for manual and AI-assisted comparison."""

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