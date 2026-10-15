"""
doctor.py - Host environment prerequisite diagnostic engine for ApkRevive.
"""

import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, List


EXPECTED_SHIM_SOURCE_SHA256 = "d589872c5ea50fe537c07ecab3ed929261b03cd21aaecad588d080674c55fc28"
EXPECTED_SHIM_DEX_SHA256 = "609b5dcbc8f657b046a73809afbd666cb6feb567497dc068733b57212286e590"


def check_python() -> Dict[str, Any]:
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 9):
        return {"status": "PASS", "details": f"Python {ver_str} (>=3.9)"}
    return {"status": "FAIL", "details": f"Python {ver_str} (<3.9)"}


def check_jdk() -> Dict[str, Any]:
    keytool = shutil.which("keytool")
    javac = shutil.which("javac")
    if not keytool and os.environ.get("JAVA_HOME"):
        cand = Path(os.environ["JAVA_HOME"]) / "bin" / ("keytool.exe" if sys.platform == "win32" else "keytool")
        if cand.is_file():
            keytool = str(cand)
    if not javac and os.environ.get("JAVA_HOME"):
        cand = Path(os.environ["JAVA_HOME"]) / "bin" / ("javac.exe" if sys.platform == "win32" else "javac")
        if cand.is_file():
            javac = str(cand)

    found: List[str] = []
    missing: List[str] = []
    if keytool:
        found.append(f"keytool ({keytool})")
    else:
        missing.append("keytool")
    if javac:
        found.append(f"javac ({javac})")
    else:
        missing.append("javac")

    if keytool and javac:
        return {"status": "PASS", "details": f"Found {', '.join(found)}"}
    elif found:
        return {"status": "WARN", "details": f"Found {', '.join(found)}; missing {', '.join(missing)}"}
    else:
        return {"status": "WARN", "details": "Neither keytool nor javac found in PATH or JAVA_HOME"}


def check_android_sdk() -> Dict[str, Any]:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root and os.path.isdir(sdk_root):
        return {"status": "PASS", "details": f"Android SDK found at {sdk_root}"}
    return {"status": "WARN", "details": "ANDROID_HOME or ANDROID_SDK_ROOT not set or directory not found"}


def check_build_tools() -> Dict[str, Any]:
    tools = ["apksigner", "zipalign", "d8"]
    found: Dict[str, str] = {}
    missing: List[str] = []

    for t in tools:
        path = shutil.which(t)
        if path:
            found[t] = path

    if len(found) < len(tools):
        sdk_roots = [
            os.environ.get("ANDROID_HOME"),
            os.environ.get("ANDROID_SDK_ROOT"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
            os.path.expanduser("~/Library/Android/sdk"),
            os.path.expanduser("~/Android/Sdk"),
        ]
        for root in sdk_roots:
            if not root or not os.path.exists(root):
                continue
            bt_dir = os.path.join(root, "build-tools")
            if os.path.exists(bt_dir):
                versions = sorted(os.listdir(bt_dir), reverse=True)
                for ver in versions:
                    for t in tools:
                        if t not in found:
                            for candidate in [f"{t}.bat", t]:
                                p = os.path.join(bt_dir, ver, candidate)
                                if os.path.exists(p):
                                    found[t] = p

    for t in tools:
        if t not in found:
            missing.append(t)

    if not missing:
        return {"status": "PASS", "details": f"Found all build-tools: {', '.join(found.keys())}"}
    elif found:
        return {"status": "WARN", "details": f"Found {', '.join(found.keys())}; missing {', '.join(missing)}"}
    else:
        return {"status": "WARN", "details": f"None of {', '.join(tools)} found in PATH or Android SDK"}


def check_adb() -> Dict[str, Any]:
    adb = shutil.which("adb")
    if not adb:
        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if sdk_root:
            cand = Path(sdk_root) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb")
            if cand.is_file():
                adb = str(cand)
    if adb:
        return {"status": "PASS", "details": f"ADB found at {adb}"}
    return {"status": "WARN", "details": "ADB not found in PATH or Android SDK platform-tools"}


def check_keystore_dir() -> Dict[str, Any]:
    ks_dir = Path.home() / ".apkrevive"
    try:
        ks_dir.mkdir(parents=True, exist_ok=True)
        return {"status": "PASS", "details": f"Keystore directory verified at {ks_dir}"}
    except Exception as e:
        return {"status": "WARN", "details": f"Unable to create keystore directory {ks_dir}: {e}"}


def check_shim_dex() -> Dict[str, Any]:
    shim_dir = Path(__file__).resolve().parent.parent / "shim"
    source_path = shim_dir / "ApkReviveInitProvider.java"
    dex_path = shim_dir / "shim.dex"

    if not source_path.is_file():
        return {"status": "FAIL", "details": f"Shim source file missing at {source_path}"}
    if not dex_path.is_file():
        return {"status": "FAIL", "details": f"Shim DEX file missing at {dex_path}"}

    try:
        with open(source_path, "rb") as f:
            source_digest = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return {"status": "FAIL", "details": f"Error reading shim source: {e}"}

    if source_digest.lower() != EXPECTED_SHIM_SOURCE_SHA256.lower():
        return {
            "status": "FAIL",
            "details": f"Shim source SHA256 mismatch: expected {EXPECTED_SHIM_SOURCE_SHA256}, got {source_digest}",
        }

    try:
        with open(dex_path, "rb") as f:
            dex_digest = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return {"status": "FAIL", "details": f"Error reading shim DEX: {e}"}

    if dex_digest.lower() != EXPECTED_SHIM_DEX_SHA256.lower():
        return {
            "status": "FAIL",
            "details": f"Shim DEX SHA256 mismatch: expected {EXPECTED_SHIM_DEX_SHA256}, got {dex_digest}",
        }

    return {
        "status": "PASS",
        "details": f"Shim source & DEX integrity verified (src: {source_digest[:8]}..., dex: {dex_digest[:8]}...)",
    }


def run_doctor() -> Dict[str, Any]:
    checks = {
        "python": check_python(),
        "jdk": check_jdk(),
        "android_sdk": check_android_sdk(),
        "build_tools": check_build_tools(),
        "adb": check_adb(),
        "keystore_dir": check_keystore_dir(),
        "shim_dex": check_shim_dex(),
    }

    has_fail = any(c["status"] == "FAIL" for c in checks.values())
    has_warn = any(c["status"] == "WARN" for c in checks.values())

    if has_fail:
        overall = "FAIL"
    elif has_warn:
        overall = "WARN"
    else:
        overall = "PASS"

    pass_list = [name for name, c in checks.items() if c["status"] == "PASS"]
    warn_list = [name for name, c in checks.items() if c["status"] == "WARN"]
    fail_list = [name for name, c in checks.items() if c["status"] == "FAIL"]

    res: Dict[str, Any] = {
        "status": overall,
        "pass": pass_list,
        "warn": warn_list,
        "fail": fail_list,
        "checks": checks,
    }
    for k, v in checks.items():
        res[k] = v

    return res


def format_doctor_report(res: Dict[str, Any]) -> str:
    checks = res.get("checks", {})
    display_names = {
        "python": "Python Version",
        "jdk": "JDK / keytool",
        "android_sdk": "Android SDK",
        "build_tools": "Android Build Tools",
        "adb": "Android Debug Bridge (ADB)",
        "keystore_dir": "User Keystore Directory",
        "shim_dex": "Shim Provenance & Integrity",
    }
    lines = [
        "ApkRevive Doctor Report",
        "=======================",
    ]
    for key, name in display_names.items():
        if key in checks:
            c = checks[key]
            badge = f"[{c['status']}]"
            lines.append(f"{badge:<8} {name}: {c.get('details', '')}")

    overall = res.get("status", "UNKNOWN")
    lines.append("")
    lines.append(f"Overall Status: [{overall}]")
    return "\n".join(lines)
