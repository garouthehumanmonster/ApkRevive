"""
ApkRevive - Legacy Android APK modernizer pipeline (Alpha).
"""

from pathlib import Path
import re
from typing import Optional


def _resolve_version(pyproject: Optional[Path] = None) -> str:
    ver = None
    p = pyproject if pyproject is not None else Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        if p.exists():
            content = p.read_text(encoding="utf-8")
            match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                ver = match.group(1)
    except Exception:
        pass

    if not ver:
        try:
            from importlib.metadata import version, PackageNotFoundError
            try:
                ver = version("apkrevive")
            except PackageNotFoundError:
                ver = None
        except ImportError:
            ver = None

    if not ver:
        ver = "0.5.1"

    return ver


__version__ = _resolve_version()
SCHEMA_VERSION = "1.1.0"
