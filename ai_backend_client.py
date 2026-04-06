#!/usr/bin/env python3
"""Client helpers for calling the standalone AI detection backend."""

import json
import urllib.error
import urllib.request


def analyze_with_backend(text: str, event_id: str, backend_url: str, timeout_seconds: int) -> dict:
    body = {
        "text": text or "",
        "event_id": event_id,
    }
    req = urllib.request.Request(
        backend_url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="replace")
            payload = json.loads(raw)
            result = payload.get("result", {})
            return {
                "detected": bool(result.get("detected", False)),
                "score": float(result.get("score", 0.0)),
                "reasons": result.get("reasons", ["no reasons provided"]),
                "techniques": result.get("techniques", []),
                "provider": result.get("provider", "unknown"),
                "model": result.get("model", "unknown"),
                "mode": result.get("mode", "model"),
            }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return {
            "detected": False,
            "score": 0.0,
            "reasons": [f"backend error: {type(exc).__name__}"],
            "techniques": [],
            "provider": "unavailable",
            "model": "unavailable",
            "mode": "error",
        }