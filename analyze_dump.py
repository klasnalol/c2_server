#!/usr/bin/env python3
"""CLI tool for memory dump forensic analysis.

Usage:
    python3 analyze_dump.py /path/to/memory.raw
    python3 analyze_dump.py /path/to/memory.raw --pid 4788
    python3 analyze_dump.py /path/to/memory.raw --phase triage,cmdline,network
    python3 analyze_dump.py /path/to/memory.raw --correlate-only
    python3 analyze_dump.py /path/to/memory.raw --strings-only
    python3 analyze_dump.py /path/to/memory.raw --yara-only
"""

import argparse
import json
import sys
from pathlib import Path

from forensic_analysis import (
    ForensicAnalyzer,
    load_forensic_config,
    run_cmdline,
    run_info,
    run_malfind,
    run_netscan,
    run_pslist,
    run_psscan,
    run_pstree,
    run_vadinfo,
    scan_with_yara,
    load_yara_rules,
    extract_strings_from_dump,
    search_indicators,
    correlate_with_c2,
    ai_triage_artifact,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Memory dump forensic analyzer for C2/fileless investigations"
    )
    parser.add_argument("dump", help="Path to memory dump (.raw, .dmp, .vmem)")
    parser.add_argument("--pid", type=int, default=None,
                        help="Target PID for focused VAD/malfind analysis")
    parser.add_argument("--phase", type=str, default=None,
                        help="Comma-separated phases: triage,cmdline,network,"
                             "vad,malfind,strings,yara,correlate,ai_triage")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Override output directory for reports and exports")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to forensic_config.json")
    parser.add_argument("--report", type=str, default=None,
                        help="Save final JSON report to this path")
    parser.add_argument("--strings-only", action="store_true",
                        help="Only extract strings and indicators")
    parser.add_argument("--yara-only", action="store_true",
                        help="Only run YARA scan")
    parser.add_argument("--correlate-only", action="store_true",
                        help="Only correlate existing C2 logs")
    parser.add_argument("--vol-bin", type=str, default=None,
                        help="Path to vol binary")
    parser.add_argument("--quiet", action="store_true",
                        help="Minimal output")
    args = parser.parse_args()

    dump_path = Path(args.dump).resolve()
    if not dump_path.exists():
        print(f"ERROR: Dump file not found: {dump_path}", file=sys.stderr)
        return 1

    config = load_forensic_config()
    if args.config:
        try:
            with open(args.config, "r") as f:
                config.update(json.load(f))
        except Exception as exc:
            print(f"WARNING: Could not load config: {exc}", file=sys.stderr)
    if args.output_dir:
        config["output_dir"] = args.output_dir
    if args.vol_bin:
        config["volatility_bin"] = args.vol_bin

    phases = []
    if args.phase:
        phases = [p.strip() for p in args.phase.split(",")]

    vol_bin = config.get("volatility_bin", "vol")

    # --- Single-mode shortcuts ---
    if args.strings_only:
        strings = extract_strings_from_dump(str(dump_path),
                                            config.get("strings_min_length", 8))
        indicators = search_indicators(strings)
        result = {
            "total_strings": len(strings),
            "indicators": indicators,
        }
        print(json.dumps(result, indent=2))
        return 0

    if args.yara_only:
        rules = load_yara_rules(config.get("yara_rules_dir"))
        matches = scan_with_yara(str(dump_path), rules)
        print(json.dumps({"matches": matches}, indent=2))
        return 0

    if args.correlate_only:
        corr = correlate_with_c2(
            [],
            config.get("c2_log_file"),
            config.get("correlation_window_seconds", 300),
        )
        print(json.dumps(corr, indent=2))
        return 0

    # --- Full or partial workflow ---
    analyzer = ForensicAnalyzer(str(dump_path), config)

    if not phases or "triage" in phases:
        if not args.quiet:
            print("[1/8] Triage: info, pslist, psscan, pstree...")
        analyzer.triage()

    if not phases or "cmdline" in phases:
        if not args.quiet:
            print("[2/8] Extracting command lines...")
        analyzer.extract_cmdline()

    if not phases or "network" in phases:
        if not args.quiet:
            print("[3/8] Recovering network artifacts...")
        analyzer.extract_network()

    if not phases or "prioritize" in phases:
        if not args.quiet:
            print("[4/8] Prioritizing processes...")
        prioritized = analyzer.prioritize_processes()
        if not args.quiet:
            for p in prioritized[:10]:
                print(f"  PID {p['pid']:>6} {p['name']:<20} score={p['score']:.2f}  "
                      f"{', '.join(p['reasons'])}")

    target_pid = args.pid
    if not target_pid and prioritized:
        for p in prioritized:
            if p["score"] > 0:
                target_pid = p["pid"]
                break

    if target_pid and (not phases or "vad" in phases or "malfind" in phases):
        if not args.quiet:
            print(f"[5/8] VAD inspection and malfind for PID {target_pid}...")
        analyzer.inspect_vad_and_malfind(target_pid)

    if not phases or "strings" in phases:
        if not args.quiet:
            print("[6/8] Extracting strings...")
        region_dir = None
        if target_pid:
            region_dir = str(Path(config["output_dir"]) / f"pid_{target_pid}_regions")
        analyzer.extract_strings(region_dir)
        strings_phase = analyzer.report["phases"].get("strings", {})
        if not args.quiet:
            print(f"  Extracted {strings_phase.get('total_strings', 0)} strings, "
                  f"{len(strings_phase.get('indicator_hits', []))} indicator hits")

    if not phases or "yara" in phases:
        if not args.quiet:
            print("[7/8] YARA scanning...")
        target = str(dump_path)
        if target_pid:
            region_dir = str(Path(config["output_dir"]) / f"pid_{target_pid}_regions")
            if Path(region_dir).exists():
                target = region_dir
        analyzer.scan_yara(target)
        yara_phase = analyzer.report["phases"].get("yara", {})
        if not args.quiet:
            print(f"  {len(yara_phase.get('matches', []))} YARA matches")

    if not phases or "correlate" in phases:
        if not args.quiet:
            print("[8/8] Correlating with C2 logs...")
        analyzer.correlate()
        corr_phase = analyzer.report["phases"].get("correlation", {})
        if not args.quiet:
            print(f"  {corr_phase.get('c2_events_count', 0)} C2 events, "
                  f"{len(corr_phase.get('correlations', []))} correlations found")

    if not phases or "ai_triage" in phases:
        if not args.quiet:
            print("[AI] Running AI-assisted triage on top artifacts...")
        analyzer.ai_triage()

    report_path = analyzer.save_report(args.report)
    if not args.quiet:
        print(f"\nReport saved: {report_path}")
    else:
        print(report_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
