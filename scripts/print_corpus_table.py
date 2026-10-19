#!/usr/bin/env python3
import json
from pathlib import Path

report_path = Path("tests/corpus/emulator_test/corpus_emulator_report.json")
if not report_path.exists():
    print("Report file not found")
    exit(1)

with open(report_path, "r", encoding="utf-8") as f:
    data = json.load(f)

header = f"| {'Package':<40} | {'Triage':<6} | {'Exit':<4} | {'Output Exists':<17} | {'Pass 1 Result':<34} | {'Pass 2 (-g) Result':<20} | {'Top Resumed Activity':<46} | {'Crash':<5} |"
sep = "|" + "-"*42 + "+" + "-"*8 + "+" + "-"*6 + "+" + "-"*19 + "+" + "-"*36 + "+" + "-"*22 + "+" + "-"*48 + "+" + "-"*7 + "|"
print(sep)
print(header)
print(sep)
for r in data["results"]:
    pkg = r["package"]
    triage = r["triage_verdict"]
    exit_code = str(r["revive_exit_code"])
    out_exists = "YES" if r["output_apk_exists"] else "NO (fail-closed)"
    p1 = r["liveness_status"] or "SKIPPED"
    if r.get("pid"):
        p1 += f" (pid {r['pid']})"
    p2 = r.get("second_pass_status") or "N/A"
    if r.get("second_pass_pid"):
        p2 += f" (pid {r['second_pass_pid']})"
    top = r.get("second_pass_top_activity") or r.get("resumed_activity") or "N/A"
    if "topResumedActivity=" in top:
        top = top.split("topResumedActivity=")[-1].split("}")[0] + "}"
    crash = "YES" if r.get("crash_detected") else "NO"
    print(f"| {pkg:<40} | {triage:<6} | {exit_code:<4} | {out_exists:<17} | {p1:<34} | {p2:<20} | {top:<46} | {crash:<5} |")
print(sep)
