#!/usr/bin/env python3
"""Standalone AI detection backend for C2 flag analysis.

This app is intentionally separate from c2_server.py so AI inference can be
deployed/scaled independently from ingestion.
"""

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request

from flag_detection import ai_assisted_detect

app = Flask(__name__)

CONFIG_FILE = Path(__file__).parent / "ai_backend_config.json"
DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8090,
    "provider": "ollama",
    "model": "llama3.1:8b",
    "ollama_url": "http://127.0.0.1:11434/api/generate",
    "request_timeout_seconds": 15,
    "temperature": 0.1,
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as handle:
                loaded = json.load(handle)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
        except Exception:
            pass
    return cfg


CONFIG = load_config()


def _extract_first_json_object(text: str):
    if not text:
        return None
    # Try direct parse first.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Fallback to first {...} block.
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


def _normalize_ai_result(raw, fallback_reasons):
    if not isinstance(raw, dict):
        return None

    detected = raw.get("detected")
    score = raw.get("score")
    reasons = raw.get("reasons", [])
    techniques = raw.get("techniques", [])

    if not isinstance(detected, bool):
        return None

    try:
        score = float(score)
    except Exception:
        score = 1.0 if detected else 0.0

    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    if not isinstance(techniques, list):
        techniques = []

    return {
        "detected": detected,
        "score": max(0.0, min(1.0, round(score, 3))),
        "reasons": [str(item) for item in reasons] or fallback_reasons,
        "techniques": [str(item) for item in techniques],
        "provider": CONFIG["provider"],
        "model": CONFIG["model"],
        "mode": "model",
    }


def analyze_with_ollama(payload_text: str):
    prompt = (
        "You are a SOC analyst classifier. Analyze candidate C2/flag text and return ONLY JSON with keys: "
        "detected (bool), score (0..1), reasons (array of short strings), techniques (array of ATT&CK IDs). "
        "Use detected=true only if indicators strongly suggest a real flag/event marker."
        "\n\nTEXT:\n"
        f"{payload_text}"
    )
    body = {
        "model": CONFIG["model"],
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": CONFIG["temperature"],
        },
    }

    req = urllib.request.Request(
        CONFIG["ollama_url"],
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=CONFIG["request_timeout_seconds"]) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(raw)
        model_text = payload.get("response", "")
        parsed = _extract_first_json_object(model_text)
        normalized = _normalize_ai_result(parsed, ["model returned malformed payload"])
        if normalized:
            return normalized
        raise ValueError("Model response could not be normalized")


def analyze_payload(payload_text: str):
    payload_text = payload_text or ""
    try:
        if CONFIG["provider"].lower() == "ollama":
            return analyze_with_ollama(payload_text)
        raise ValueError(f"Unsupported provider: {CONFIG['provider']}")
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        fallback = ai_assisted_detect(payload_text)
        return {
            "detected": fallback["detected"],
            "score": fallback["score"],
            "reasons": fallback["reasons"] + [f"fallback reason: {type(exc).__name__}"],
            "techniques": fallback.get("techniques", []),
            "provider": CONFIG["provider"],
            "model": CONFIG["model"],
            "mode": "fallback",
        }


@app.route("/status")
def status():
    return jsonify(
        {
            "status": "online",
            "provider": CONFIG["provider"],
            "model": CONFIG["model"],
            "port": CONFIG["port"],
        }
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    event_id = payload.get("event_id")
    result = analyze_payload(text)
    return jsonify({
        "event_id": event_id,
        "result": result,
    })


if __name__ == "__main__":
    print(
        f"AI backend listening on {CONFIG['host']}:{CONFIG['port']} "
        f"provider={CONFIG['provider']} model={CONFIG['model']}"
    )
    app.run(host=CONFIG["host"], port=CONFIG["port"], debug=False, threaded=True)