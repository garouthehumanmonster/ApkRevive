"""
ApkRevive - Legacy Android APK modernizer pipeline (Alpha).
"""

from pathlib import Path
import re

__version__ = None

try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        __version__ = version("apkrevive")
    except PackageNotFoundError:
        __version__ = None
except ImportError:
    __version__ = None

if not __version__:
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject_path.exists():
        content = pyproject_path.read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            __version__ = match.group(1)

if not __version__:
    __version__ = "3.3.0"
