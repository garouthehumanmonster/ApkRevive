#!/usr/bin/env python3
"""
Execute run_emulator_corpus.py across 3 sequential runs to benchmark repeatability
and ensure zero flakiness in pass-1 detection.
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
    print("\n\n=========================================================================================")
    print("EMULATOR CORPUS 3-RUN PASS-1 REPEATABILITY BENCHMARK (API 37 16KB)")
    print("=========================================================================================")

    header = f"| {'Package':<40} | {'Run 1 Pass-1':<34} | {'Run 2 Pass-1':<34} | {'Run 3 Pass-1':<34} | {'Repeatability':<13} |"
    sep = "|" + "-"*42 + "+" + "-"*36 + "+" + "-"*36 + "+" + "-"*36 + "+" + "-"*15 + "|"
    print(sep)
    print(header)
    print(sep)

    for i, pkg in enumerate(packages):
        p1_r1 = runs_results[0][i].get("liveness_status") or "SKIPPED"
        if runs_results[0][i].get("pid"):
            p1_r1 += f" (pid {runs_results[0][i]['pid']})"

        p1_r2 = runs_results[1][i].get("liveness_status") or "SKIPPED"
        if runs_results[1][i].get("pid"):
            p1_r2 += f" (pid {runs_results[1][i]['pid']})"

        p1_r3 = runs_results[2][i].get("liveness_status") or "SKIPPED"
        if runs_results[2][i].get("pid"):
            p1_r3 += f" (pid {runs_results[2][i]['pid']})"

        status1 = runs_results[0][i].get("liveness_status")
        status2 = runs_results[1][i].get("liveness_status")
        status3 = runs_results[2][i].get("liveness_status")

        identical = (status1 == status2 == status3)
        rep = "100% IDENTICAL" if identical else "MISMATCH"

        print(f"| {pkg:<40} | {p1_r1:<34} | {p1_r2:<34} | {p1_r3:<34} | {rep:<13} |")
    print(sep)


if __name__ == "__main__":
    main()
