#!/usr/bin/env python3
"""generate_matrix.py - Matrix generator for ApkRevive verification evidence.

Reads recorded execution results from `results/*.json` and generates a markdown
matrix table of the 8 canaries across standard execution environments:
- Local Verification Rig (Host AXML/ELF/Signer test harness)
- Android Emulator API 34 (4KB)
- Android Emulator API 35 (16KB)
- Physical Hardware API 35 (ARM64 16KB)
- Android 16 API 36 Preview (16KB)

Updates the Canary Results section in `docs/COMPATIBILITY.md` between marked delimiters.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results"
DEFAULT_DOC_PATH = PROJECT_ROOT / "docs" / "COMPATIBILITY.md"

DELIMITER_START = "<!-- CANARY_RESULTS_START -->"
DELIMITER_END = "<!-- CANARY_RESULTS_END -->"

STANDARD_ENVIRONMENTS: list[str] = [
    "Local Verification Rig",
    "Android Emulator API 34 (4KB)",
    "Android Emulator API 35 (16KB)",
    "Physical Hardware API 35 (ARM64 16KB)",
    "Android 16 API 36 Preview (16KB)",
]

ENVIRONMENT_DESCRIPTIONS: dict[str, str] = {
    "Local Verification Rig": "Host AXML/ELF/Signer test harness",
    "Android Emulator API 34 (4KB)": "Android Emulator API 34 (4KB)",
    "Android Emulator API 35 (16KB)": "Android Emulator API 35 (16KB)",
    "Physical Hardware API 35 (ARM64 16KB)": "Physical Hardware API 35 (ARM64 16KB)",
    "Android 16 API 36 Preview (16KB)": "Android 16 API 36 Preview (16KB)",
}

STANDARD_CANARIES: list[str] = [
    "canary_install_floor",
    "canary_apache_http",
    "canary_page_size",
    "canary_physics_tick",
    "canary_aspect_ratio",
    "canary_bionic_greylist",
    "canary_has_code",
    "canary_obb_version",
]

SCHEMA_FIELD_TYPES: dict[str, type] = {
    "device_model": str,
    "android_build": str,
    "kernel_page_size": int,
    "refresh_rate": int,
    "emulator_or_hardware": str,
    "date": str,
    "tool_commit": str,
    "canary_id": str,
    "expected": str,
    "observed": str,
    "pass_fail": str,
    "simulated": bool,
}

VALID_EMULATOR_OR_HARDWARE = {"emulator", "hardware", "local_host"}
VALID_PASS_FAIL = {"PASS", "FAIL"}


def validate_result_schema(data: dict[str, Any], source_file: Path | str) -> None:
    """Validates that a result dictionary conforms to the required evidence schema."""
    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON in {source_file}: expected an object")

    for field_name, expected_type in SCHEMA_FIELD_TYPES.items():
        if field_name not in data:
            raise ValueError(f"Missing required field '{field_name}' in {source_file}")
        val = data[field_name]
        if not isinstance(val, expected_type):
            raise ValueError(
                f"Field '{field_name}' in {source_file} expected {expected_type.__name__}, got {type(val).__name__}"
            )

    kind = data["emulator_or_hardware"]
    if kind not in VALID_EMULATOR_OR_HARDWARE:
        raise ValueError(
            f"Invalid 'emulator_or_hardware' value '{kind}' in {source_file}. Expected one of {VALID_EMULATOR_OR_HARDWARE}"
        )

    pf = data["pass_fail"]
    if pf not in VALID_PASS_FAIL:
        raise ValueError(f"Invalid 'pass_fail' value '{pf}' in {source_file}. Expected 'PASS' or 'FAIL'")


def load_results(results_dir: Path | str) -> list[dict[str, Any]]:
    """Loads and validates all JSON results from the specified directory."""
    results_path = Path(results_dir)
    if not results_path.exists() or not results_path.is_dir():
        return []

    results: list[dict[str, Any]] = []
    for json_file in sorted(results_path.glob("*.json")):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        validate_result_schema(data, json_file)
        results.append(data)

    return results


def match_environment(result: dict[str, Any]) -> str | None:
    """Matches a result dictionary to one of the standard evaluated environments."""
    # 1. Direct explicit environment match
    env_direct = result.get("environment") or result.get("env")
    if env_direct:
        for env_name in STANDARD_ENVIRONMENTS:
            if env_name.lower() == str(env_direct).lower():
                return env_name

    # 2. Check device_model against environment names
    model = str(result.get("device_model", ""))
    for env_name in STANDARD_ENVIRONMENTS:
        if env_name.lower() in model.lower():
            return env_name

    # 3. Check emulator_or_hardware, kernel_page_size, android_build
    kind = str(result.get("emulator_or_hardware", "")).lower()
    page_size = result.get("kernel_page_size", 0)
    build = str(result.get("android_build", ""))

    if kind == "local_host" or "local" in model.lower() or "rig" in model.lower():
        return "Local Verification Rig"

    if kind == "emulator":
        if ("36" in build or "36" in model or "16" in build) and page_size == 16384:
            return "Android 16 API 36 Preview (16KB)"
        if ("35" in build or "35" in model) and page_size == 16384:
            return "Android Emulator API 35 (16KB)"
        if ("34" in build or "34" in model) and page_size == 4096:
            return "Android Emulator API 34 (4KB)"

    if kind == "hardware":
        if ("35" in build or "35" in model) and page_size == 16384:
            return "Physical Hardware API 35 (ARM64 16KB)"

    return None


def format_markdown_table(results: list[dict[str, Any]]) -> str:
    """Formats a markdown matrix table for all 8 canaries across standard environments.

    Unrun canary/environment pairs will display 'NOT RUN'.
    """
    matrix: dict[tuple[str, str], str] = {}
    for res in results:
        env_name = match_environment(res)
        canary = res.get("canary_id")
        if env_name and canary:
            if res.get("simulated", False) and env_name != "Local Verification Rig":
                matrix[(canary, env_name)] = "NOT RUN"
            else:
                matrix[(canary, env_name)] = res.get("pass_fail", "NOT RUN")

    headers = ["Canary"] + STANDARD_ENVIRONMENTS
    alignments = ["---"] + [":---:"] * len(STANDARD_ENVIRONMENTS)

    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(alignments) + "|",
    ]

    for canary in STANDARD_CANARIES:
        row = [f"`{canary}`"]
        for env in STANDARD_ENVIRONMENTS:
            status = matrix.get((canary, env), "NOT RUN")
            row.append(status)
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)


def format_evidence_log(results: list[dict[str, Any]]) -> str:
    """Formats a markdown table of individual evidence execution records."""
    if not results:
        return ""

    sorted_results = sorted(results, key=lambda r: (str(r.get("canary_id", "")), str(r.get("date", ""))))
    headers = ["Canary", "Environment", "Tool Commit", "Date", "Observed Result", "Status"]
    alignments = ["---", "---", ":---:", ":---:", "---", ":---:"]

    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(alignments) + "|",
    ]

    for res in sorted_results:
        canary = f"`{res.get('canary_id', '')}`"
        env = match_environment(res) or str(res.get("device_model", "Unknown"))
        commit = f"`{res.get('tool_commit', '')}`"
        date = str(res.get("date", ""))
        observed = str(res.get("observed", "")).replace("|", "\\|")
        status = str(res.get("pass_fail", ""))
        lines.append(f"| {canary} | {env} | {commit} | {date} | {observed} | {status} |")

    return "\n".join(lines)


def format_results_section(results: list[dict[str, Any]]) -> str:
    """Builds the complete Canary Results documentation section with matrix and evidence log."""
    table = format_markdown_table(results)

    env_lines = ["*Standard Environments Evaluated:*"]
    for env in STANDARD_ENVIRONMENTS:
        desc = ENVIRONMENT_DESCRIPTIONS.get(env, env)
        env_lines.append(f"- **{env}**: {desc}")
    env_notes = "\n".join(env_lines)

    sections = [
        table,
        "",
        env_notes,
    ]

    evidence_table = format_evidence_log(results)
    if evidence_table:
        sections.extend([
            "",
            "#### Recorded Verification Evidence",
            "",
            evidence_table,
        ])

    return "\n".join(sections)


def update_compatibility_doc(doc_path: Path | str, new_content: str) -> bool:
    """Updates the Canary Results section in docs/COMPATIBILITY.md between marked delimiters."""
    doc_path = Path(doc_path)
    if not doc_path.exists():
        raise FileNotFoundError(f"Compatibility document not found at {doc_path}")

    text = doc_path.read_text(encoding="utf-8")
    block = f"{DELIMITER_START}\n\n{new_content.strip()}\n\n{DELIMITER_END}"

    if DELIMITER_START in text and DELIMITER_END in text:
        pattern = re.compile(
            rf"{re.escape(DELIMITER_START)}.*?{re.escape(DELIMITER_END)}",
            re.DOTALL,
        )
        updated_text = pattern.sub(block, text)
    else:
        # Delimiters not found yet, insert before section 4
        target_marker = "## 4. Execution Environments"
        if target_marker in text:
            insertion = f"### Canary Verification Results Matrix\n\n{block}\n\n---\n\n"
            updated_text = text.replace(target_marker, insertion + target_marker, 1)
        else:
            updated_text = text.rstrip() + f"\n\n### Canary Verification Results Matrix\n\n{block}\n"

    doc_path.write_text(updated_text, encoding="utf-8")
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate compatibility matrix from results/*.json and update docs/COMPATIBILITY.md"
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Path to results directory containing JSON result files",
    )
    parser.add_argument(
        "--doc-path",
        type=Path,
        default=DEFAULT_DOC_PATH,
        help="Path to docs/COMPATIBILITY.md",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print generated section to stdout without writing to disk",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    results = load_results(args.results_dir)
    results_section = format_results_section(results)

    if args.print_only:
        print(results_section)
        return 0

    update_compatibility_doc(args.doc_path, results_section)
    print(f"Successfully updated {args.doc_path} with {len(results)} verified canary results.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
