"""
obb.py - Strict OBB expansion validation for shell-privileged writer.
Uses re.fullmatch to reject trailing newlines, blocks directory traversal,
and verifies target package binding.
"""

import re
from typing import Dict, Any


OBB_REGEX = re.compile(r"(main|patch)\.([0-9]+)\.([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)\.obb")


def validate_obb_delivery(obb_filename: str, target_package: str, current_apk_version: int) -> Dict[str, Any]:
    if "\0" in obb_filename or "/" in obb_filename or "\\" in obb_filename or ".." in obb_filename:
        return {"valid": False, "reason": "PATH_TRAVERSAL_DETECTED"}

    m = OBB_REGEX.fullmatch(obb_filename)
    if not m:
        return {"valid": False, "reason": "INVALID_OBB_FILENAME_FORMAT (Trailing newline rejected by fullmatch)"}

    obb_type, obb_version_str, obb_pkg = m.groups()
    obb_version = int(obb_version_str)

    if obb_pkg != target_package:
        return {
            "valid": False,
            "reason": "PACKAGE_NAME_MISMATCH",
            "details": f"OBB package '{obb_pkg}' != '{target_package}'"
        }

    warning = None
    if obb_version > current_apk_version:
        warning = f"EXPANSION_VERSION_AHEAD_OF_APK ({obb_version} > {current_apk_version})"

    dest_path = f"/Android/obb/{target_package}/{obb_filename}"
    return {
        "valid": True,
        "obb_type": obb_type,
        "obb_version": obb_version,
        "destination_path": dest_path,
        "warning": warning
    }
