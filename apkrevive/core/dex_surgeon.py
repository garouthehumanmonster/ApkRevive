"""
dex_surgeon.py - Dalvik Executable (DEX) shim injection engine.

Cleanly injects the precompiled ApkReviveInitProvider bytecode shim (multidex classesN.dex)
into legacy APK containers to unlock hidden APIs, disable StrictMode crashes, and swallow
legacy background/storage exceptions before Application.onCreate() runs.
"""

import hashlib
import re
from typing import List, Optional, Tuple
import zipfile

from apkrevive.core.align import validate_zip_archive
from apkrevive.shim.build_shim import CANONICAL_SHIM_SHA256, SHIM_DEX_PATH

CANONICAL_PROVIDER_CLASS = "com.apkrevive.shim.ApkReviveInitProvider"
LEGACY_PROVIDER_CLASS = "apkrevive.shim.ApkReviveInitProvider"
LEGACY_PROVIDER_CLASSES = {
    "com.apkrevive.runtime.ApkReviveInitProvider",
    "apkrevive.shim.ApkReviveInitProvider",
}

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
        or b"Lcom/apkrevive/shim/ApkReviveInitProvider;" in dex_bytes
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

    indices = set()
    for name in existing_dex_names:
        match = DEX_CLASS_PATTERN.match(name)
        if match:
            suffix = match.group(1)
            indices.add(1 if not suffix else int(suffix))

    if 1 not in indices:
        return "classes.dex"

    idx = 2
    while idx in indices:
        idx += 1
    return f"classes{idx}.dex"


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


def fix_dex_header_checksums(dex_bytes: bytearray) -> bytes:
    """
    Recalculates DEX header checksums and file size in exact sequence:
    1. file_size (offset 32..36)
    2. SHA-1 signature (offset 12..32 over bytes 32..end)
    3. Adler32 checksum (offset 8..12 over bytes 12..end)
    Returns updated bytes.
    """
    import struct
    import zlib
    if len(dex_bytes) < 36 or not dex_bytes.startswith(b"dex\n"):
        raise ValueError("Invalid DEX header")

    # 1. file_size at offset 32..36
    struct.pack_into("<I", dex_bytes, 32, len(dex_bytes))

    # 2. SHA-1 signature at offset 12..32 over bytes 32..end
    sha1 = hashlib.sha1(dex_bytes[32:]).digest()
    dex_bytes[12:32] = sha1

    # 3. Adler32 checksum at offset 8..12 over bytes 12..end
    adler = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", dex_bytes, 8, adler)

    return bytes(dex_bytes)


__all__ = [
    "CANONICAL_PROVIDER_CLASS",
    "LEGACY_PROVIDER_CLASS",
    "load_canonical_shim",
    "is_shim_dex",
    "scan_apk_dex_entries",
    "has_shim_in_apk",
    "get_next_multidex_name",
    "inject_dex_shim",
    "fix_dex_header_checksums",
]
