"""
dex_surgeon.py - Dalvik Executable (DEX) shim injection engine.

Cleanly injects the precompiled ApkReviveInitProvider bytecode shim (multidex classesN.dex)
into legacy APK containers to unlock hidden APIs, disable StrictMode crashes, and swallow
legacy background/storage exceptions before Application.onCreate() runs.
"""

import hashlib
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple, Set
import zipfile

from apkrevive.core.align import validate_zip_archive
from apkrevive.shim.build_shim import CANONICAL_SHIM_SHA256, SHIM_DEX_PATH

CANONICAL_PROVIDER_CLASS = "com.apkrevive.runtime.ApkReviveInitProvider"
LEGACY_PROVIDER_CLASS = "apkrevive.shim.ApkReviveInitProvider"

DEX_CLASS_PATTERN = re.compile(r"^classes(\d*)\.dex$")


def load_canonical_shim() -> bytes:
    """
    Loads and cryptographically verifies the precompiled ApkReviveInitProvider shim.dex.
    Fails closed if the shim file is missing or fails SHA256 integrity verification.
    """
    if not SHIM_DEX_PATH.is_file():
        raise FileNotFoundError(f"Canonical shim.dex not found at {SHIM_DEX_PATH}")

    content = SHIM_DEX_PATH.read_bytes()
    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != CANONICAL_SHIM_SHA256:
        raise ValueError(
            f"Cryptographic hash mismatch for canonical shim.dex!\n"
            f"Expected: {CANONICAL_SHIM_SHA256}\n"
            f"Actual:   {actual_hash}"
        )
    return content


def is_shim_dex(dex_bytes: bytes) -> bool:
    """
    Determines whether a DEX blob contains the ApkReviveInitProvider implementation.
    """
    if len(dex_bytes) < 40 or not dex_bytes.startswith(b"dex\n"):
        return False
    return (
        b"ApkReviveInitProvider" in dex_bytes
        or b"Lcom/apkrevive/runtime/ApkReviveInitProvider;" in dex_bytes
        or b"Lapkrevive/shim/ApkReviveInitProvider;" in dex_bytes
    )


def scan_apk_dex_entries(apk_path: str) -> List[str]:
    """
    Scans an APK and returns a sorted list of all DEX entry names:
    ['classes.dex', 'classes2.dex', 'classes3.dex', ...]
    """
    validate_zip_archive(apk_path)
    dex_names: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for item in zf.infolist():
            if DEX_CLASS_PATTERN.match(item.filename):
                dex_names.append(item.filename)

    def sort_key(name: str) -> int:
        match = DEX_CLASS_PATTERN.match(name)
        if not match:
            return 999999
        suffix = match.group(1)
        return int(suffix) if suffix else 1

    return sorted(dex_names, key=sort_key)


def has_shim_in_apk(apk_path: str) -> bool:
    """
    Checks if any existing DEX in the APK already contains ApkReviveInitProvider.
    """
    validate_zip_archive(apk_path)
    with zipfile.ZipFile(apk_path, "r") as zf:
        for item in zf.infolist():
            if DEX_CLASS_PATTERN.match(item.filename):
                data = zf.read(item.filename)
                if is_shim_dex(data):
                    return True
    return False


def get_next_multidex_name(existing_dex_names: List[str]) -> str:
    """
    Calculates the next multidex entry name based on existing DEX filenames:
    - [] -> 'classes.dex'
    - ['classes.dex'] -> 'classes2.dex'
    - ['classes.dex', 'classes2.dex'] -> 'classes3.dex'
    """
    if not existing_dex_names:
        return "classes.dex"

    max_idx = 1
    has_classes_dex = False
    for name in existing_dex_names:
        match = DEX_CLASS_PATTERN.match(name)
        if match:
            suffix = match.group(1)
            if not suffix:
                has_classes_dex = True
                max_idx = max(max_idx, 1)
            else:
                max_idx = max(max_idx, int(suffix))

    if not has_classes_dex:
        return "classes.dex"
    return f"classes{max_idx + 1}.dex"


def inject_dex_shim(
    input_apk: str,
    output_apk: str,
    shim_bytes: Optional[bytes] = None,
) -> Tuple[bool, str]:
    """
    Injects the ApkReviveInitProvider shim into the APK as the next classesN.dex.
    If the shim is already present in any existing DEX file, the operation is idempotent
    and returns (False, 'ALREADY_PRESENT').

    Returns (injected_flag, injected_entry_name).
    """
    validate_zip_archive(input_apk)
    if has_shim_in_apk(input_apk):
        return False, "ALREADY_PRESENT"

    if shim_bytes is None:
        shim_bytes = load_canonical_shim()

    existing_dex_names = scan_apk_dex_entries(input_apk)
    next_dex_name = get_next_multidex_name(existing_dex_names)

    with zipfile.ZipFile(input_apk, "r") as zin, zipfile.ZipFile(output_apk, "w") as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        zout.writestr(next_dex_name, shim_bytes)

    return True, next_dex_name


__all__ = [
    "CANONICAL_PROVIDER_CLASS",
    "LEGACY_PROVIDER_CLASS",
    "load_canonical_shim",
    "is_shim_dex",
    "scan_apk_dex_entries",
    "has_shim_in_apk",
    "get_next_multidex_name",
    "inject_dex_shim",
]
