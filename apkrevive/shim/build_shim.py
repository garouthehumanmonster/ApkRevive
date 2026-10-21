#!/usr/bin/env python3
"""
build_shim.py - Standalone build engine for ApkReviveInitProvider bytecode shim.
Compiles ApkReviveInitProvider.java using javac and d8 into canonical shim.dex.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

CANONICAL_SHIM_SHA256 = "ae45ed4ce54c24bb0ab8decd08a9ee577ff885991086cc72818580b0ebcea0af"
SHIM_DIR = Path(__file__).resolve().parent
SHIM_JAVA_PATH = SHIM_DIR / "ApkReviveInitProvider.java"
SHIM_DEX_PATH = SHIM_DIR / "shim.dex"


def find_sdk_root() -> Path:
    candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk") if os.environ.get("LOCALAPPDATA") else None,
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]
    for c in candidates:
        if c and os.path.isdir(c):
            return Path(c)
    return Path(os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ".")


def find_build_tools(sdk: Path) -> Path:
    bt = sdk / "build-tools"
    if (bt / "35.0.0").is_dir():
        return bt / "35.0.0"
    if bt.is_dir():
        versions = sorted([d for d in bt.iterdir() if d.is_dir()], reverse=True)
        if versions:
            return versions[0]
    return bt / "35.0.0"


def find_platform_dir(sdk: Path) -> Path:
    plat = sdk / "platforms"
    if (plat / "android-35").is_dir():
        return plat / "android-35"
    if plat.is_dir():
        versions = sorted([d for d in plat.iterdir() if d.is_dir()], reverse=True)
        if versions:
            return versions[0]
    return plat / "android-35"


def resolve_tool(name: str, build_tools_dir: Optional[Path] = None) -> str:
    found = shutil.which(name)
    if found:
        return found

    if sys.platform == "win32":
        for ext in [".exe", ".bat", ".cmd"]:
            cand = shutil.which(f"{name}{ext}")
            if cand:
                return cand

    if name == "javac":
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            javac_cand = Path(java_home) / "bin" / ("javac.exe" if sys.platform == "win32" else "javac")
            if javac_cand.is_file():
                return str(javac_cand)
        if sys.platform == "win32":
            known_windows_javacs = [
                r"C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\javac.exe",
            ]
            for win_javac in known_windows_javacs:
                if os.path.isfile(win_javac):
                    return win_javac
            prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            java_dir = Path(prog_files) / "Java"
            if java_dir.is_dir():
                for j_cand in sorted(java_dir.glob("**/javac.exe"), reverse=True):
                    return str(j_cand)
        return "javac.exe" if sys.platform == "win32" else "javac"

    if build_tools_dir and build_tools_dir.is_dir():
        candidates = [f"{name}.bat", f"{name}.exe", f"{name}.cmd", name] if sys.platform == "win32" else [name]
        for tool_name in candidates:
            tool_path = build_tools_dir / tool_name
            if tool_path.is_file():
                return str(tool_path)

    if sys.platform == "win32":
        ext = ".bat" if name in ("d8", "apksigner") else ".exe"
        if build_tools_dir:
            return str(build_tools_dir / f"{name}{ext}")
        return f"{name}{ext}"
    if build_tools_dir:
        return str(build_tools_dir / name)
    return name


def build_shim(output_dex_path: Optional[Path] = None, force: bool = False) -> bytes:
    """
    Compiles ApkReviveInitProvider.java into deterministic DEX bytecode.
    Verifies SHA256 against canonical hash unless force is True.
    Optionally writes output to output_dex_path.
    Returns generated DEX bytes.
    """
    if not SHIM_JAVA_PATH.is_file():
        raise FileNotFoundError(f"Shim source file not found: {SHIM_JAVA_PATH}")

    sdk_root = find_sdk_root()
    build_tools = find_build_tools(sdk_root)
    platform_dir = find_platform_dir(sdk_root)

    android_jar = platform_dir / "android.jar"
    if not android_jar.is_file():
        raise FileNotFoundError(f"android.jar not found at {android_jar}")

    javac_bin = resolve_tool("javac")
    d8_bin = resolve_tool("d8", build_tools)

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        tmp_bin = tmp_dir / "bin"
        tmp_bin.mkdir(parents=True, exist_ok=True)
        tmp_dex = tmp_dir / "dex"
        tmp_dex.mkdir(parents=True, exist_ok=True)

        java_sources = sorted(str(p) for p in SHIM_DIR.rglob("*.java"))
        if not java_sources:
            raise FileNotFoundError(f"No Java sources found in {SHIM_DIR}")

        cmd_javac = [
            javac_bin,
            "-cp", str(android_jar),
            "-d", str(tmp_bin),
        ] + java_sources
        res_javac = subprocess.run(cmd_javac, capture_output=True, text=True)
        if res_javac.returncode != 0:
            raise RuntimeError(f"javac compilation failed:\n{res_javac.stderr}")

        class_files = sorted(str(p) for p in tmp_bin.rglob("*.class"))
        if not class_files:
            raise RuntimeError("No .class files were produced by javac")

        cmd_d8 = [
            d8_bin,
            "--lib", str(android_jar),
            "--output", str(tmp_dex)
        ] + class_files
        res_d8 = subprocess.run(cmd_d8, capture_output=True, text=True)
        if res_d8.returncode != 0:
            raise RuntimeError(f"d8 translation failed:\n{res_d8.stderr}")

        dex_file = tmp_dex / "classes.dex"
        if not dex_file.is_file():
            raise RuntimeError("d8 did not generate classes.dex")

        dex_bytes = dex_file.read_bytes()

    actual_sha256 = hashlib.sha256(dex_bytes).hexdigest()
    if not force and actual_sha256 != CANONICAL_SHIM_SHA256:
        raise ValueError(
            f"Compiled shim.dex SHA256 mismatch!\n"
            f"Expected: {CANONICAL_SHIM_SHA256}\n"
            f"Actual:   {actual_sha256}"
        )

    if output_dex_path is not None:
        target_path = Path(output_dex_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(dex_bytes)

    return dex_bytes


def main():
    parser = argparse.ArgumentParser(description="ApkRevive bytecode shim builder and verifier")
    parser.add_argument("--force", action="store_true", help="Force building and overwriting shim.dex even if hash does not match CANONICAL_SHIM_SHA256")
    parser.add_argument("--verify", action="store_true", help="Verify committed shim.dex against CANONICAL_SHIM_SHA256")
    args = parser.parse_args()

    if args.verify:
        if not SHIM_DEX_PATH.exists():
            print(f"[-] shim.dex not found at {SHIM_DEX_PATH}", file=sys.stderr)
            return 1
        digest = hashlib.sha256(SHIM_DEX_PATH.read_bytes()).hexdigest()
        if digest != CANONICAL_SHIM_SHA256:
            print(f"[-] Verification failed! Expected {CANONICAL_SHIM_SHA256}, got {digest}", file=sys.stderr)
            return 1
        print(f"[+] Verified canonical hash match for {SHIM_DEX_PATH} ({digest})")
        return 0

    print(f"[*] Building ApkRevive shim from {SHIM_JAVA_PATH}...")
    dex_bytes = build_shim(output_dex_path=SHIM_DEX_PATH, force=args.force)
    digest = hashlib.sha256(dex_bytes).hexdigest()
    print(f"[+] Successfully generated {SHIM_DEX_PATH} ({len(dex_bytes)} bytes)")
    print(f"[+] SHA256: {digest}")
    if digest == CANONICAL_SHIM_SHA256:
        print("[+] Verified canonical hash match.")
        return 0
    else:
        if args.force:
            print(f"[!] Force mode: generated {SHIM_DEX_PATH} with new hash {digest}")
            print(f"[!] Update CANONICAL_SHIM_SHA256 in {__file__} to: {digest}")
            return 0
        print("[-] Hash verification failed!", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
