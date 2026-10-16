"""
zip_guard.py - Zero-Trust ZIP archive security validator.
Enforces strict anti-path-traversal (Zip-Slip), anti-symlink, and anti-compression-bomb invariants.
"""

import os
import struct
import zipfile


def validate_zip_archive(
    apk_path: str,
    max_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024,
    max_ratio: float = 100.0,
) -> None:
    """
    Validates zip archive integrity and enforces security constraints:
    - Verifies file exists and is non-empty.
    - Rejects path traversal (Zip-Slip): '..' in path, leading '/' or '\\', absolute drive paths ('C:'), null bytes ('\0').
    - Rejects symbolic link entries: checks (entry.external_attr >> 16) & 0o170000 == 0o120000.
    - Detects Zip bombs: compression ratio > max_ratio and single file > 10MB, or single file > 500MB,
      or total uncompressed > max_uncompressed_bytes.
    - Detects corrupted or truncated archives cleanly as ValueError("Truncated ZIP archive entry: ...").
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"Archive file not found: {apk_path}")
    if os.path.getsize(apk_path) == 0:
        raise ValueError(f"Archive file is empty: {apk_path}")

    total_uncompressed = 0
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for entry in zf.infolist():
                name = entry.filename

                # 1. Path traversal check (Zip-Slip)
                if (
                    ".." in name
                    or name.startswith("/")
                    or name.startswith("\\")
                    or ":" in name
                    or "\0" in name
                ):
                    raise ValueError(f"Zip-slip path traversal detected: {name}")

                # 2. Symlink entry check
                # S_IFMT is 0o170000, S_IFLNK is 0o120000
                if ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError(f"Zip symlink entry forbidden: {name}")

                # 3. Compression bomb checks
                if (
                    entry.compress_size > 0
                    and (entry.file_size / entry.compress_size) > max_ratio
                    and entry.file_size > 10 * 1024 * 1024
                ):
                    raise ValueError(f"Zip bomb detected (high compression ratio): {name}")

                if entry.file_size > 500 * 1024 * 1024:
                    raise ValueError(f"Zip entry exceeds maximum permitted size: {name}")

                total_uncompressed += entry.file_size
                if total_uncompressed > max_uncompressed_bytes:
                    raise ValueError("Zip bomb detected (total uncompressed size exceeds limit)")

    except (zipfile.BadZipFile, struct.error, EOFError, IndexError) as e:
        raise ValueError(f"Truncated ZIP archive entry: {e}")
