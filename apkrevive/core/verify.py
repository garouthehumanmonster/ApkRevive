"""
verify.py - Post-patch verification engine for ApkRevive modernized APK containers.

Performs comprehensive validation battery:
1. 16KB container alignment: Stored .so and resources.arsc aligned to 16384 (0x4000), other stored entries 4-byte aligned.
2. V2/V3 signature validity: Central Directory 4KB aligned, APK signing block presence, and cert validation.
3. AndroidManifest.xml binary AXML parsing: Valid package name, <application> element present, optional aapt2 dump xmltree.
4. Multidex validation: Contiguous multidex numbering and no duplicate class descriptor collisions across DEX files.
"""

from dataclasses import dataclass, field
import os
import struct
import subprocess
from typing import Dict, Any, List, Optional, Tuple
import zipfile

from apkrevive.core.align import verify_apk_alignment, validate_zip_archive
from apkrevive.core.signer import verify_signing_block_padding, verify_apk_certs
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.dex_surgeon import DEX_CLASS_PATTERN
from apkrevive.core.toolchain import find_sdk_tool

VALID_DEX_MAGICS = {
    b"dex\n035\x00",
    b"dex\n036\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dex\n040\x00",
}


@dataclass
class VerificationReport:
    """Post-patch verification report dataclass."""
    apk_path: str
    is_valid: bool
    checks: Dict[str, bool] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "is_valid": self.is_valid,
            "checks": self.checks,
            "errors": self.errors,
            "details": self.details,
        }


def get_aapt2_cmd() -> Optional[str]:
    """Locates aapt2 binary in system PATH or Android SDK build-tools directories."""
    return find_sdk_tool("aapt2")


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes an unsigned LEB128 integer starting at offset, returning (value, new_offset)."""
    val = 0
    shift = 0
    idx = offset
    data_len = len(data)
    while idx < data_len:
        b = data[idx]
        idx += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, idx
        shift += 7
        if shift >= 35:
            raise ValueError("Malformed ULEB128 in DEX: shift overflow")
    raise ValueError("Truncated ULEB128 sequence in DEX data")


def parse_dex_class_descriptors(data: bytes) -> List[str]:
    """
    Pure-Python parser for Dalvik Executable (DEX) header and class definitions.
    Extracts all class descriptor strings (e.g. 'Lcom/example/MyClass;').
    Raises ValueError on corrupt or malformed DEX binary data.
    """
    if len(data) < 112:
        raise ValueError(f"DEX data truncated: expected >= 112 bytes, got {len(data)}")

    magic = data[:8]
    if magic not in VALID_DEX_MAGICS:
        if not (magic.startswith(b"dex\n") and len(magic) == 8 and magic[7] == 0):
            raise ValueError(f"Invalid DEX magic: {magic!r}")

    file_size, header_size, endian_tag = struct.unpack_from("<III", data, 0x20)
    if endian_tag != 0x12345678:
        raise ValueError(f"Unsupported DEX endian tag: 0x{endian_tag:08x} (only little-endian supported)")
    if header_size < 112:
        raise ValueError(f"Invalid DEX header_size: {header_size}")
    if file_size > len(data):
        raise ValueError(f"DEX declared file_size {file_size} exceeds actual payload length {len(data)}")

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)

    if string_ids_off + (string_ids_size * 4) > len(data):
        raise ValueError("DEX string_ids table extends beyond file buffer")
    if type_ids_off + (type_ids_size * 4) > len(data):
        raise ValueError("DEX type_ids table extends beyond file buffer")
    if class_defs_off + (class_defs_size * 32) > len(data):
        raise ValueError("DEX class_defs table extends beyond file buffer")

    # Parse string_ids table -> strings
    strings: List[str] = []
    for i in range(string_ids_size):
        str_data_off = struct.unpack_from("<I", data, string_ids_off + (i * 4))[0]
        if str_data_off >= len(data):
            raise ValueError(f"DEX string_data_off {str_data_off} out of bounds")
        utf16_len, pos = _read_uleb128(data, str_data_off)
        null_idx = data.find(b"\x00", pos)
        if null_idx == -1:
            raise ValueError(f"Unterminated DEX string at offset {pos}")
        str_val = data[pos:null_idx].decode("utf-8", errors="replace")
        strings.append(str_val)

    # Parse type_ids table -> descriptor strings
    types: List[str] = []
    for i in range(type_ids_size):
        desc_idx = struct.unpack_from("<I", data, type_ids_off + (i * 4))[0]
        if desc_idx >= len(strings):
            raise ValueError(f"DEX descriptor_idx {desc_idx} exceeds string pool size {len(strings)}")
        types.append(strings[desc_idx])

    # Parse class_defs table -> class descriptor strings
    class_descriptors: List[str] = []
    for i in range(class_defs_size):
        class_def_pos = class_defs_off + (i * 32)
        class_idx = struct.unpack_from("<I", data, class_def_pos)[0]
        if class_idx >= len(types):
            raise ValueError(f"DEX class_idx {class_idx} exceeds type_ids size {len(types)}")
        class_descriptors.append(types[class_idx])

    return class_descriptors


def verify_apk_integrity(apk_path: str, verbose: bool = False) -> VerificationReport:
    """
    Runs comprehensive post-patch verification battery against target APK.
    Returns VerificationReport indicating is_valid (True if ALL checks pass).
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    # Validate archive format
    validate_zip_archive(apk_path)

    checks: Dict[str, bool] = {
        "alignment": False,
        "signature": False,
        "axml": False,
        "dex": False,
    }
    errors: List[str] = []
    details: Dict[str, Any] = {}

    # =========================================================================
    # 1. 16KB Container Alignment Check
    # =========================================================================
    try:
        align_info = verify_apk_alignment(apk_path)
        details["alignment"] = align_info
        if align_info.get("aligned", False):
            checks["alignment"] = True
        else:
            checks["alignment"] = False
            unaligned = [
                f"{k} (offset={v.get('offset')}, required={v.get('required_align')})"
                for k, v in align_info.get("entries", {}).items()
                if not v.get("aligned", False)
            ]
            errors.append(f"16KB alignment failure: unaligned entries: {', '.join(unaligned)}")
    except Exception as e:
        checks["alignment"] = False
        errors.append(f"Alignment verification failed: {e}")

    # =========================================================================
    # 2. V2/V3 Signature Validity Check
    # =========================================================================
    try:
        pad_info = verify_signing_block_padding(apk_path)
        details["signing_block"] = pad_info

        cert_ok, cert_msg = verify_apk_certs(apk_path)
        details["signature_certs"] = {"valid": cert_ok, "output": cert_msg}

        sig_ok = True
        if not pad_info.get("has_signing_block", False):
            errors.append("V2/V3 signature check failed: Missing APK Signing Block")
            sig_ok = False
        if not pad_info.get("cd_aligned_4k", False):
            errors.append(f"Central Directory is not 4KB aligned: offset={pad_info.get('cd_offset')}")
            sig_ok = False
        if not cert_ok:
            errors.append(f"APK signature verification failed: {cert_msg}")
            sig_ok = False

        checks["signature"] = sig_ok
    except Exception as e:
        checks["signature"] = False
        errors.append(f"Signature verification failed: {e}")

    # =========================================================================
    # 3. AndroidManifest.xml Binary AXML Parsing Check
    # =========================================================================
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                errors.append("AndroidManifest.xml missing from APK archive")
                checks["axml"] = False
            else:
                manifest_data = zf.read("AndroidManifest.xml")
                root_node = AxmlSurgeon.parse(manifest_data)

                pkg_attr = root_node.get_attr("package")
                pkg_name = (pkg_attr.raw_value or pkg_attr.get_value()) if pkg_attr else None

                axml_ok = True
                if not pkg_name or not isinstance(pkg_name, str) or not pkg_name.strip():
                    errors.append(f"Invalid package name in AndroidManifest.xml: {pkg_name!r}")
                    axml_ok = False
                else:
                    details["package_name"] = pkg_name

                app_node = root_node.find_child("application")
                if app_node is None:
                    errors.append("Missing <application> element in AndroidManifest.xml")
                    axml_ok = False

                aapt2_bin = get_aapt2_cmd()
                if aapt2_bin:
                    try:
                        res = subprocess.run(
                            [aapt2_bin, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk_path)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        details["aapt2_exit_code"] = res.returncode
                        if res.returncode != 0:
                            errors.append(f"aapt2 dump xmltree failed: {res.stderr.strip()}")
                            axml_ok = False
                        else:
                            details["aapt2_dump"] = res.stdout
                    except Exception as ex:
                        errors.append(f"aapt2 execution error: {ex}")
                        axml_ok = False

                checks["axml"] = axml_ok
    except Exception as e:
        checks["axml"] = False
        errors.append(f"AXML manifest verification failed: {e}")

    # =========================================================================
    # 4. Multidex Contiguity & Class Collision Check
    # =========================================================================
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = [n for n in zf.namelist() if DEX_CLASS_PATTERN.match(n)]
            details["dex_files"] = dex_names

            if not dex_names:
                errors.append("No DEX files found in APK archive")
                checks["dex"] = False
            else:
                dex_ok = True
                indices: Dict[int, str] = {}
                for name in dex_names:
                    m = DEX_CLASS_PATTERN.match(name)
                    if m is None:
                        continue
                    sfx = m.group(1)
                    idx = 1 if not sfx else int(sfx)
                    if idx in indices:
                        errors.append(f"Duplicate multidex index mapping for {name} and {indices[idx]}")
                        dex_ok = False
                    indices[idx] = name

                max_idx = max(indices.keys())
                expected_indices = set(range(1, max_idx + 1))
                missing = expected_indices - set(indices.keys())
                if missing:
                    missing_names = [f"classes{i}.dex" if i > 1 else "classes.dex" for i in sorted(missing)]
                    errors.append(f"Non-contiguous multidex sequence: missing {', '.join(missing_names)}")
                    dex_ok = False

                seen_classes: Dict[str, str] = {}
                for idx in sorted(indices.keys()):
                    dex_name = indices[idx]
                    raw_dex = zf.read(dex_name)
                    try:
                        descriptors = parse_dex_class_descriptors(raw_dex)
                        for desc in descriptors:
                            if desc in seen_classes:
                                errors.append(
                                    f"Duplicate class descriptor '{desc}' found in {dex_name} "
                                    f"(already defined in {seen_classes[desc]})"
                                )
                                dex_ok = False
                            else:
                                seen_classes[desc] = dex_name
                    except Exception as ex:
                        errors.append(f"DEX parser error in {dex_name}: {ex}")
                        dex_ok = False

                details["total_classes_found"] = len(seen_classes)
                checks["dex"] = dex_ok
    except Exception as e:
        checks["dex"] = False
        errors.append(f"DEX verification failed: {e}")

    # =========================================================================
    # Final Result
    # =========================================================================
    is_valid = (
        checks["alignment"]
        and checks["signature"]
        and checks["axml"]
        and checks["dex"]
        and len(errors) == 0
    )

    return VerificationReport(
        apk_path=apk_path,
        is_valid=is_valid,
        checks=checks,
        errors=errors,
        details=details,
    )


__all__ = [
    "VerificationReport",
    "verify_apk_integrity",
    "parse_dex_class_descriptors",
    "get_aapt2_cmd",
    "VALID_DEX_MAGICS",
]
