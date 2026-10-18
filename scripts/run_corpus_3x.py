#!/usr/bin/env python3
"""
Execute run_emulator_corpus.py across 3 sequential runs to benchmark repeatability
and ensure zero flakiness in pass-1 and pass-2 detection.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_emulator_corpus import run_corpus_on_device


def main():
    runs_results = []
    for run_idx in range(1, 4):
        print("\n=======================================================")
        print(f"STARTING CORPUS REPEATABILITY RUN #{run_idx} / 3")
        print("=======================================================")
        res = run_corpus_on_device(
            bump_target_sdk=24,
            use_bypass=False,
            grant_permissions=False,
        )
        out_file = REPO_ROOT / "tests" / "corpus" / "emulator_test" / f"corpus_emulator_report_run{run_idx}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        runs_results.append(res["results"])

    # Build comparison table
    packages = [r["package"] for r in runs_results[0]]
    print("\n\n=====================================================================================================================================")
    print("EMULATOR CORPUS 3-RUN PASS-1 & PASS-2 REPEATABILITY BENCHMARK (API 37 16KB)")
    print("=====================================================================================================================================")

    header = (
        f"| {'Package':<38} "
        f"| {'Run 1 Pass-1':<12} | {'Run 1 Pass-2':<12} "
        f"| {'Run 2 Pass-1':<12} | {'Run 2 Pass-2':<12} "
        f"| {'Run 3 Pass-1':<12} | {'Run 3 Pass-2':<12} "
        f"| {'Repeatability':<15} |"
    )
    sep = (
        "|" + "-"*40 + "+"
        + "-"*14 + "+" + "-"*14 + "+"
        + "-"*14 + "+" + "-"*14 + "+"
        + "-"*14 + "+" + "-"*14 + "+"
        + "-"*17 + "|"
    )
    print(sep)
    print(header)
    print(sep)

    for i, pkg in enumerate(packages):
        p1_1 = runs_results[0][i].get("liveness_status") or "SKIPPED"
        p2_1 = runs_results[0][i].get("second_pass_status") or "SKIPPED"

        p1_2 = runs_results[1][i].get("liveness_status") or "SKIPPED"
        p2_2 = runs_results[1][i].get("second_pass_status") or "SKIPPED"

        p1_3 = runs_results[2][i].get("liveness_status") or "SKIPPED"
        p2_3 = runs_results[2][i].get("second_pass_status") or "SKIPPED"

        identical = (p1_1 == p1_2 == p1_3 and p2_1 == p2_2 == p2_3)
        rep = "100% IDENTICAL" if identical else "MISMATCH"

        print(
            f"| {pkg:<38} "
            f"| {p1_1:<12} | {p2_1:<12} "
            f"| {p1_2:<12} | {p2_2:<12} "
            f"| {p1_3:<12} | {p2_3:<12} "
            f"| {rep:<15} |"
        )
    print(sep)


if __name__ == "__main__":
    main()
