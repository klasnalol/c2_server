#!/usr/bin/env python3
"""CLI comparison of manual vs AI-assisted flag detection."""

import json
from pathlib import Path

from flag_detection import compare_detection, summarize_detection


def load_entries(log_file: Path) -> list[dict]:
    entries = []
    if not log_file.exists():
        return entries

    with open(log_file, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def main() -> int:
    log_file = Path("logs") / "c2_log.json"
    entries = load_entries(log_file)

    if not entries:
        print(f"No entries found in {log_file}")
        return 0

    summary = summarize_detection(entries)
    print("Manual vs AI Flag Detection")
    print("=" * 30)
    print(f"Total entries    : {summary['total']}")
    print(f"Manual detected  : {summary['manual_detected']}")
    print(f"AI detected      : {summary['ai_detected']}")
    print(f"Agreement        : {summary['agreement']} ({summary['agreement_rate']:.3f})")
    print(f"Manual only      : {summary['manual_only']}")
    print(f"AI only          : {summary['ai_only']}")
    print(f"Neither          : {summary['neither']}")

    if summary["disagreements"]:
        print("\nDisagreements:")
        print("timestamp                  source_ip        manual  ai   ai_score  excerpt")
        for row in summary["disagreements"]:
            print(
                f"{row['timestamp'][:26]:<26} {row['source_ip']:<15} "
                f"{str(row['manual_detected']):<6} {str(row['ai_detected']):<4} "
                f"{row['ai_score']:<8} {row['excerpt'][:60]}"
            )
    else:
        print("\nNo disagreements found.")

    # Print one worked example to help tune thresholds.
    sample = entries[-1].get("details", "")
    sample_comparison = compare_detection(sample)
    print("\nLatest sample analysis:")
    print(f"Manual detected: {sample_comparison['manual']['detected']}")
    print(
        f"AI detected    : {sample_comparison['ai']['detected']} "
        f"(score={sample_comparison['ai']['score']}, reasons={'; '.join(sample_comparison['ai']['reasons'])})"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())