#!/usr/bin/env python3
"""
scripts/make_receipt.py - Generate structured verification receipts from a target APK.

Runs the post-patch verification battery (16KB alignment, signing block, Central Directory
4KB alignment, AXML parsing, and multidex uniqueness), collects cryptographic hashes,
and writes structured receipt JSON.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.core.align import validate_zip_archive
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.verify import verify_apk_integrity


def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 hashes of a file."""
    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)

    return {
        "sha256": h_sha256.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "md5": h_md5.hexdigest(),
    }


def generate_receipt(
    apk_path: str,
    device_api: int = 35,
    page_size: int = 16384,
    simulated: bool = False,
    device_abi: Optional[str] = None,
    device_model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes verification battery on an APK and returns structured receipt dictionary.
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"Target APK not found: {apk_path}")

    validate_zip_archive(apk_path)
    file_size = os.path.getsize(apk_path)
    hashes = compute_file_hashes(apk_path)
    meta = inspect_apk(apk_path)
    vreport = verify_apk_integrity(apk_path)

    ts = datetime.now(timezone.utc)
    target_abi = device_abi or (meta.abis[0] if meta.abis else "x86_64")
    model_name = device_model or f"Android SDK built for {target_abi} (emulator)"

    align_details = vreport.details.get("alignment", {})
    sig_details = vreport.details.get("signing", {})

    aligned_16kb = bool(vreport.checks.get("alignment", False))
    entries_checked = int(align_details.get("entries_checked", 0)) if isinstance(align_details, dict) else 0

    has_sig_block = bool(sig_details.get("has_signing_block", False)) if isinstance(sig_details, dict) else False
    cd_aligned_4k = bool(sig_details.get("cd_aligned_4k", False)) if isinstance(sig_details, dict) else False

    receipt: Dict[str, Any] = {
        "verification_type": "apk_verification_receipt",
        "timestamp": ts.isoformat(),
        "date": ts.strftime("%Y-%m-%d"),
        "simulated": bool(simulated),
        "pass_fail": "PASS" if vreport.is_valid else "FAIL",
        "api_level": int(device_api),
        "os_api_level": int(device_api),
        "abi": target_abi,
        "device_abi": target_abi,
        "device_model": model_name,
        "page_size": int(page_size),
        "kernel_page_size": int(page_size),
        "script": "scripts/make_receipt.py",
        "target_apk": os.path.basename(apk_path),
        "apk_path": os.path.abspath(apk_path),
        "hashes": hashes,
        "file_size_bytes": file_size,
        "metadata": {
            "package_name": meta.package_name,
            "version_code": meta.version_code,
            "min_sdk": meta.min_sdk,
            "target_sdk": meta.target_sdk,
            "abis": meta.abis,
            "page_size_16kb_status": meta.elf_16kb_status,
        },
        "alignment": {
            "aligned_16kb": aligned_16kb,
            "entries_checked": entries_checked,
            "cd_aligned_4k": cd_aligned_4k,
        },
        "signing": {
            "has_signing_block": has_sig_block,
            "cd_aligned_4k": cd_aligned_4k,
            "is_unsigned": getattr(vreport, "is_unsigned", False),
        },
        "verification": {
            "is_valid": vreport.is_valid,
            "checks": vreport.checks,
            "errors": vreport.errors,
            "details": vreport.details,
            "is_unsigned": getattr(vreport, "is_unsigned", False),
        },
        "status": "SUCCESS" if vreport.is_valid else "FAILED",
    }
    return receipt


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="make_receipt.py",
        description="Generate structured verification receipt JSON from a target APK.",
    )
    parser.add_argument("apk", nargs="?", default=None, help="Path to input target APK file")
    parser.add_argument("--apk", dest="opt_apk", default=None, help="Explicit path to input APK")
    parser.add_argument("-o", "--output", help="Path to output receipt JSON file")
    parser.add_argument("--device-api", type=int, default=35, help="Target device OS API level (default: 35)")
    parser.add_argument("--page-size", type=int, default=16384, help="Target device page size in bytes (default: 16384)")
    parser.add_argument(
        "--simulated",
        action="store_true",
        default=False,
        help="Flag indicating verification was simulated / dry-run",
    )
    parser.add_argument("--abi", default=None, help="Target device ABI architecture (e.g. x86_64, arm64-v8a)")
    parser.add_argument("--model", default=None, help="Target device model description")

    args = parser.parse_args(argv)
    apk_target = args.opt_apk or args.apk
    if not apk_target:
        parser.error("Input APK path is required (positional or via --apk)")

    try:
        receipt = generate_receipt(
            apk_path=apk_target,
            device_api=args.device_api,
            page_size=args.page_size,
            simulated=args.simulated,
            device_abi=args.abi,
            device_model=args.model,
        )

        receipt_json = json.dumps(receipt, indent=2) + "\n"
        if args.output:
            out_file = Path(args.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(receipt_json, encoding="utf-8")
            print(f"[+] Wrote verification receipt to: {out_file}")
        else:
            print(receipt_json, end="")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error generating receipt: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
