#!/usr/bin/env python3
"""
scripts/survey.py - Survey a directory of APKs and generate aggregate triage statistics.

Evaluates each APK against target device specifications (OS API level, 16KB page size,
supported ABIs, install floor) and produces formatted summary tables of GREEN/YELLOW/RED
verdicts along with breakdowns of blocker signals and required transforms.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.core.extractor import inspect_apk
from apkrevive.core.models import DeviceProfile
from apkrevive.core.triage import evaluate_triage


def run_survey(
    apk_dir: str,
    device_api: int = 35,
    page_size: int = 16384,
    device_abis: Optional[List[str]] = None,
    device_floor: int = 24,
) -> Dict[str, Any]:
    """
    Surveys a directory of APK files and generates aggregate compatibility statistics.
    """
    dir_path = Path(apk_dir)
    if not dir_path.exists():
        raise FileNotFoundError(f"APK directory not found: {apk_dir}")
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {apk_dir}")

    target_abis = device_abis or ["arm64-v8a"]
    dev = DeviceProfile(
        os_api_level=device_api,
        install_floor=device_floor,
        supported_abis=target_abis,
        page_size_bytes=page_size,
    )

    apk_files = sorted([p for p in dir_path.glob("**/*.apk") if p.is_file()])
    total_apks = len(apk_files)

    verdict_counts: Dict[str, int] = {
        "GREEN": 0,
        "YELLOW": 0,
        "RED": 0,
        "NEEDS_USER_INPUT": 0,
    }
    signals_breakdown: Dict[str, int] = {}
    transforms_breakdown: Dict[str, int] = {}
    fatal_blockers_breakdown: Dict[str, int] = {}

    per_apk_records: List[Dict[str, Any]] = []

    for apk_path in apk_files:
        try:
            meta = inspect_apk(str(apk_path))
            meta_dict = meta.to_dict()
            triage_res = evaluate_triage(meta_dict, dev)

            verdict = str(triage_res.get("verdict", "RED"))
            reason = str(triage_res.get("reason", "UNKNOWN"))
            transforms = list(triage_res.get("required_transforms", []))

            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            signals_breakdown[reason] = signals_breakdown.get(reason, 0) + 1

            for t in transforms:
                transforms_breakdown[t] = transforms_breakdown.get(t, 0) + 1

            record = {
                "apk_file": apk_path.name,
                "apk_path": str(apk_path),
                "package_name": meta.package_name,
                "target_sdk": meta.target_sdk,
                "min_sdk": meta.min_sdk,
                "abis": meta.abis,
                "verdict": verdict,
                "reason": reason,
                "install_method": triage_res.get("install_method", "DIRECT_INSTALL"),
                "required_transforms": transforms,
                "warnings": triage_res.get("warnings", []),
                "details": triage_res.get("details", ""),
            }
            per_apk_records.append(record)
        except Exception as e:
            verdict_counts["RED"] = verdict_counts.get("RED", 0) + 1
            signals_breakdown["CORRUPTED_OR_UNREADABLE"] = (
                signals_breakdown.get("CORRUPTED_OR_UNREADABLE", 0) + 1
            )
            per_apk_records.append({
                "apk_file": apk_path.name,
                "apk_path": str(apk_path),
                "package_name": "unknown",
                "target_sdk": 0,
                "min_sdk": 0,
                "abis": [],
                "verdict": "RED",
                "reason": "CORRUPTED_OR_UNREADABLE",
                "install_method": "CANNOT_INSTALL",
                "required_transforms": [],
                "warnings": [str(e)],
                "details": f"Failed to parse APK: {e}",
            })

    verdict_percentages: Dict[str, float] = {}
    for v, count in verdict_counts.items():
        verdict_percentages[v] = round((count / total_apks * 100.0), 1) if total_apks > 0 else 0.0

    return {
        "apk_dir": str(dir_path.resolve()),
        "device_api": device_api,
        "page_size": page_size,
        "device_abis": target_abis,
        "device_floor": device_floor,
        "total_apks": total_apks,
        "verdict_counts": verdict_counts,
        "verdict_percentages": verdict_percentages,
        "signals_breakdown": signals_breakdown,
        "transforms_breakdown": transforms_breakdown,
        "fatal_blockers_breakdown": fatal_blockers_breakdown,
        "per_apk_records": per_apk_records,
    }


def format_survey_report(survey_data: Dict[str, Any]) -> str:
    """Formats human-readable terminal summary tables."""
    total = survey_data.get("total_apks", 0)
    apk_dir = survey_data.get("apk_dir", "")
    api = survey_data.get("device_api", 35)
    page_size = survey_data.get("page_size", 16384)
    page_size_kb = page_size // 1024
    abis_str = ", ".join(survey_data.get("device_abis", ["arm64-v8a"]))

    lines = [
        "=" * 80,
        "  ApkRevive Legacy Compatibility Survey Report",
        "=" * 80,
        f"  Corpus Directory:   {apk_dir}",
        f"  Total APKs:         {total}",
        f"  Target Environment: Android API {api} ({abis_str}), Page Size: {page_size}B ({page_size_kb}KB)",
        "-" * 80,
        "  Verdict Summary:",
        f"  {'Verdict':<20} {'Count':<10} {'Percentage'}",
        "  " + "-" * 48,
    ]

    counts = survey_data.get("verdict_counts", {})
    percentages = survey_data.get("verdict_percentages", {})
    for v in ["GREEN", "YELLOW", "RED", "NEEDS_USER_INPUT"]:
        c = counts.get(v, 0)
        p = percentages.get(v, 0.0)
        lines.append(f"  {v:<20} {c:<10} {p:>5.1f}%")

    lines.extend([
        "-" * 80,
        "  Triage Signals Breakdown:",
        f"  {'Signal':<40} {'Count':<10} {'Percentage'}",
        "  " + "-" * 58,
    ])

    signals = survey_data.get("signals_breakdown", {})
    if signals:
        sorted_signals = sorted(signals.items(), key=lambda x: x[1], reverse=True)
        for sig, cnt in sorted_signals:
            sig_pct = (cnt / total * 100.0) if total > 0 else 0.0
            lines.append(f"  {sig:<40} {cnt:<10} {sig_pct:>5.1f}%")
    else:
        lines.append("  No signals recorded.")

    transforms = survey_data.get("transforms_breakdown", {})
    if transforms:
        lines.extend([
            "-" * 80,
            "  Required Transforms Breakdown:",
            f"  {'Transform':<40} {'Count':<10} {'Percentage'}",
            "  " + "-" * 58,
        ])
        sorted_transforms = sorted(transforms.items(), key=lambda x: x[1], reverse=True)
        for tr, cnt in sorted_transforms:
            tr_pct = (cnt / total * 100.0) if total > 0 else 0.0
            lines.append(f"  {tr:<40} {cnt:<10} {tr_pct:>5.1f}%")

    records = survey_data.get("per_apk_records", [])
    if records:
        lines.extend([
            "-" * 80,
            "  Per-APK Detail:",
            f"  {'APK File':<28} {'TargetSDK':<10} {'Verdict':<10} {'Signal / Reason'}",
            "  " + "-" * 76,
        ])
        for r in records:
            fn = r.get("apk_file", "")
            if len(fn) > 26:
                fn = fn[:23] + "..."
            tsdk = str(r.get("target_sdk", ""))
            vrd = r.get("verdict", "")
            rsn = r.get("reason", "")
            lines.append(f"  {fn:<28} {tsdk:<10} {vrd:<10} {rsn}")

    lines.append("=" * 80)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="survey.py",
        description="Survey a directory of legacy APKs and generate aggregate triage statistics.",
    )
    parser.add_argument("apk_dir", nargs="?", default=None, help="Directory containing target APK files")
    parser.add_argument("--apk-dir", dest="opt_apk_dir", default=None, help="Explicit directory path")
    parser.add_argument("--device-api", type=int, default=35, help="Target device OS API level (default: 35)")
    parser.add_argument("--page-size", type=int, default=16384, help="Target device page size in bytes (default: 16384)")
    parser.add_argument("--device-abis", default="arm64-v8a", help="Comma-separated supported device ABIs (default: arm64-v8a)")
    parser.add_argument("--device-floor", type=int, default=24, help="Target device install floor (default: 24)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
    parser.add_argument("-o", "--output", help="Path to write report (formatted text or JSON)")

    args = parser.parse_args(argv)
    target_dir = args.opt_apk_dir or args.apk_dir
    if not target_dir:
        parser.error("APK directory path is required (positional or via --apk-dir)")

    try:
        abis = [a.strip() for a in str(args.device_abis).split(",") if a.strip()]
        survey_res = run_survey(
            apk_dir=target_dir,
            device_api=args.device_api,
            page_size=args.page_size,
            device_abis=abis,
            device_floor=args.device_floor,
        )

        if args.json:
            output_content = json.dumps(survey_res, indent=2) + "\n"
        else:
            output_content = format_survey_report(survey_res) + "\n"

        if args.output:
            out_file = Path(args.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(output_content, encoding="utf-8")
            print(f"[+] Wrote survey report to: {out_file}")
        else:
            print(output_content, end="")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error running survey: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
