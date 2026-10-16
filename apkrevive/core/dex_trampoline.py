"""
dex_trampoline.py - Dalvik (API < 21) multi-dex primary DEX trampoline and metadata injector.
Validates DEX 035 header, injects trampoline metadata/hook, and recomputes checksums.
"""

import hashlib
import struct
import zlib
from typing import Tuple

DEX_MAGIC = b"dex\n035\x00"
DEX_HEADER_SIZE = 0x70  # 112 bytes
DEX_ENDIAN_CONSTANT = 0x12345678

# Dalvik multi-dex trampoline payload signature
DALVIK_TRAMPOLINE_TAG = b"APKREVIVE_DALVIK_MULTIDEX_TRAMPOLINE_V1"


def validate_dex_header(dex_bytes: bytes) -> Tuple[int, int, int]:
    """
    Validates DEX 035 header structure and returns (file_size, data_off, data_size).
    Raises ValueError on invalid DEX data.
    """
    if len(dex_bytes) < DEX_HEADER_SIZE:
        raise ValueError(f"Invalid DEX binary: length {len(dex_bytes)} is smaller than header size {DEX_HEADER_SIZE}")

    magic = dex_bytes[:8]
    if magic != DEX_MAGIC:
        raise ValueError(f"Unsupported or invalid DEX magic: {magic!r}")

    endian_tag = struct.unpack_from("<I", dex_bytes, 0x28)[0]
    if endian_tag != DEX_ENDIAN_CONSTANT:
        raise ValueError(f"Unsupported DEX endian tag: 0x{endian_tag:08x}")

    header_size = struct.unpack_from("<I", dex_bytes, 0x24)[0]
    if header_size != DEX_HEADER_SIZE:
        raise ValueError(f"Unexpected DEX header size: {header_size}")

    file_size = struct.unpack_from("<I", dex_bytes, 0x20)[0]
    data_size = struct.unpack_from("<I", dex_bytes, 0x68)[0]
    data_off = struct.unpack_from("<I", dex_bytes, 0x6C)[0]

    return file_size, data_off, data_size


def recalculate_dex_checksums(dex_data: bytearray) -> None:
    """
    Recalculates SHA-1 signature (offset 32 to end) and Adler-32 checksum (offset 12 to end)
    and writes them into the DEX header in place.
    """
    if len(dex_data) < DEX_HEADER_SIZE:
        raise ValueError("Cannot recalculate checksums: buffer too small")

    # 1. SHA-1 signature over bytes [32:]
    sha1 = hashlib.sha1(bytes(dex_data[32:])).digest()
    dex_data[12:32] = sha1

    # 2. Adler-32 checksum over bytes [12:] (which includes the new SHA-1)
    adler = zlib.adler32(bytes(dex_data[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", dex_data, 8, adler)


def verify_dex_checksums(dex_bytes: bytes) -> bool:
    """Verifies that the Adler-32 checksum and SHA-1 signature in the DEX header match the contents."""
    if len(dex_bytes) < DEX_HEADER_SIZE or dex_bytes[:8] != DEX_MAGIC:
        return False

    expected_sha1 = hashlib.sha1(dex_bytes[32:]).digest()
    actual_sha1 = dex_bytes[12:32]
    if expected_sha1 != actual_sha1:
        return False

    expected_adler = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
    actual_adler = struct.unpack_from("<I", dex_bytes, 8)[0]
    return expected_adler == actual_adler


def patch_primary_dex_trampoline(dex_bytes: bytes) -> bytes:
    """
    Validates primary DEX (classes.dex) header, injects Dalvik multi-dex initialization
    trampoline metadata hook, updates header file size and data size, and recalculates
    checksum and signature.
    """
    file_size, data_off, data_size = validate_dex_header(dex_bytes)

    # Check if trampoline is already injected
    if DALVIK_TRAMPOLINE_TAG in dex_bytes:
        buf = bytearray(dex_bytes)
        recalculate_dex_checksums(buf)
        return bytes(buf)

    buf = bytearray(dex_bytes)

    # Prepare trampoline metadata payload:
    # 4-byte alignment padding + Tag + 4-byte payload length
    payload = DALVIK_TRAMPOLINE_TAG
    pad_len = (4 - (len(payload) % 4)) % 4
    trampoline_block = payload + (b"\x00" * pad_len) + struct.pack("<I", len(payload))

    # Append to end of DEX file / data section
    buf.extend(trampoline_block)
    new_len = len(buf)

    # Update file_size in header (offset 0x20)
    struct.pack_into("<I", buf, 0x20, new_len)

    # Update data_size in header (offset 0x68)
    new_data_size = data_size + len(trampoline_block)
    struct.pack_into("<I", buf, 0x68, new_data_size)

    # Recalculate SHA-1 and Adler-32 checksums
    recalculate_dex_checksums(buf)

    return bytes(buf)
