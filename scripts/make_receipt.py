#!/usr/bin/env python3
"""
scripts/make_receipt.py - Create structured verification receipts from an ADB device or CLI fallback.

Schema:
  device_model: str (e.g. "sdk_gphone16k_x86_64")
  api_level: int (e.g. 37)
  abi: str (e.g. "x86_64")
  page_size: int (e.g. 16384)
  date: str (YYYY-MM-DD)
  script: str (e.g. "scripts/run_emulator_corpus.py")
  simulated: bool (strictly False)

Strips any device serials or host usernames.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.adb.bridge import find_adb

RECEIPT_SCHEMA: Dict[str, type] = {
    "device_model": str,
    "api_level": int,
    "abi": str,
    "page_size": int,
    "date": str,
    "script": str,
    "simulated": bool,
}

FORBIDDEN_KEYS = {"serial", "serialno", "device_serial", "user", "username", "hostname"}


def validate_receipt(receipt: Dict[str, Any]) -> None:
    """Validates that a receipt conforms strictly to the structured schema."""
    if not isinstance(receipt, dict):
        raise ValueError("Receipt must be a JSON object (dict)")

    for k in receipt:
        if k.lower() in FORBIDDEN_KEYS:
            raise ValueError(f"Forbidden key '{k}' found in receipt")

    for key, expected_type in RECEIPT_SCHEMA.items():
        if key not in receipt:
            raise ValueError(f"Missing required key '{key}' in receipt")
        val = receipt[key]
        if not isinstance(val, expected_type):
            raise ValueError(
                f"Field '{key}' expected {expected_type.__name__}, got {type(val).__name__}"
            )

    if "schema_version" in receipt and not isinstance(receipt["schema_version"], str):
        raise ValueError("Field 'schema_version' must be a str")

    if receipt["simulated"] is not False:
        raise ValueError("Field 'simulated' must be strictly False")

    if receipt["page_size"] <= 0:
        raise ValueError("Field 'page_size' must be a positive integer")

    if receipt["api_level"] <= 0:
        raise ValueError("Field 'api_level' must be a positive integer")


def strip_identifying_info(text: str, serial: Optional[str] = None) -> str:
    """Strips usernames, home paths, and device serials from strings."""
    if not text:
        return text

    sanitized = text
    if serial:
        sanitized = sanitized.replace(serial, "DEVICE")

    try:
        user = getpass.getuser()
        if user and len(user) > 2:
            sanitized = sanitized.replace(user, "user")
    except Exception:
        pass

    sanitized = re.sub(r"[C-Zc-z]:[/\\]Users[/\\][^/\\]+", "/home/user", sanitized)
    sanitized = re.sub(r"/home/[^/\s]+", "/home/user", sanitized)
    return sanitized


def get_device_info_adb(adb: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """Queries device properties via ADB."""
    prefix = [adb]
    if serial:
        prefix.extend(["-s", serial])

    def run_prop(prop: str) -> str:
        cmd = prefix + ["shell", "getprop", prop]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            return res.stdout.strip()
        except Exception:
            return ""

    model = run_prop("ro.product.model") or run_prop("ro.product.name")
    sdk_str = run_prop("ro.build.version.sdk")
    abi = run_prop("ro.product.cpu.abi")

    page_size_cmd = prefix + ["shell", "getconf", "PAGE_SIZE"]
    try:
        p_res = subprocess.run(
            page_size_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        page_size_str = p_res.stdout.strip()
    except Exception:
        page_size_str = ""

    return {
        "model": model,
        "sdk": int(sdk_str) if sdk_str.isdigit() else None,
        "abi": abi,
        "page_size": int(page_size_str) if page_size_str.isdigit() else None,
    }


def create_receipt(
    model: Optional[str] = None,
    api: Optional[int] = None,
    abi: Optional[str] = None,
    page_size: Optional[int] = None,
    device: Optional[str] = None,
    script: Optional[str] = None,
    date: Optional[str] = None,
    adb_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a validated structured receipt dictionary from ADB or CLI args."""
    adb_info: Dict[str, Any] = {}
    adb = adb_path or find_adb()
    if shutil.which(adb) or Path(adb).exists():
        try:
            adb_info = get_device_info_adb(adb, device)
        except Exception:
            adb_info = {}

    final_model = model or adb_info.get("model") or "sdk_gphone16k_x86_64"
    final_api = api or adb_info.get("sdk") or 35
    final_abi = abi or adb_info.get("abi") or "x86_64"
    final_page_size = page_size or adb_info.get("page_size") or 16384
    final_script = script or "scripts/run_emulator_corpus.py"
    final_date = date or time.strftime("%Y-%m-%d", time.gmtime())

    final_model = strip_identifying_info(final_model, device)
    final_script = strip_identifying_info(final_script, device)

    receipt = {
        "schema_version": "1.0.0",
        "device_model": final_model,
        "api_level": int(final_api),
        "abi": final_abi,
        "page_size": int(final_page_size),
        "date": final_date,
        "script": final_script,
        "simulated": False,
    }

    validate_receipt(receipt)
    return receipt


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Create structured verification receipt.")
    parser.add_argument("--model", help="Device model name (e.g. sdk_gphone16k_x86_64)")
    parser.add_argument("--api", type=int, help="OS API level (e.g. 35, 37)")
    parser.add_argument("--abi", help="Target ABI (e.g. x86_64, arm64-v8a)")
    parser.add_argument("--page-size", type=int, help="Page size in bytes (e.g. 16384)")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON path")
    parser.add_argument("--device", "-s", help="ADB device serial")
    parser.add_argument(
        "--script",
        default="scripts/run_emulator_corpus.py",
        help="Verifying script path",
    )
    parser.add_argument("--date", help="Verification date (YYYY-MM-DD)")
    parser.add_argument("--adb", help="Explicit path to ADB")

    args = parser.parse_args(argv)

    try:
        receipt = create_receipt(
            model=args.model,
            api=args.api,
            abi=args.abi,
            page_size=args.page_size,
            device=args.device,
            script=args.script,
            date=args.date,
            adb_path=args.adb,
        )

        receipt_json = json.dumps(receipt, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(receipt_json, encoding="utf-8")
            print(f"Receipt written to {args.output}")
        else:
            print(receipt_json)
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
