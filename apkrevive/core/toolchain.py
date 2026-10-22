"""
toolchain.py - Toolchain discovery, resolution, and environment diagnostics for ApkRevive.
Locates JDK binaries (javac, keytool) and Android SDK binaries (apksigner, aapt2, d8, adb)
across platform-specific locations and environment variables.
"""

import glob
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Dict, List, Optional


def find_jdk_tool(name: str) -> Optional[str]:
    """
    Resolves JDK binaries (javac, keytool) across platforms.
    Search order:
    a. shutil.which(name) and on win32 shutil.which(f"{name}.exe").
    b. os.environ.get("JAVA_HOME") / "bin" / name (and .exe on win32).
    c. Directory of `javac` on PATH: if shutil.which("javac") is found, resolve its
       real symlink path (Path(...).resolve()) and check (real_javac.parent / name).
    d. Common JVM roots across OSes:
       - Linux: glob /usr/lib/jvm/*/bin/{name}
       - macOS: glob /Library/Java/JavaVirtualMachines/*/Contents/Home/bin/{name}
       - Windows: C:\\Program Files\\Java\\*\\bin\\{name}.exe,
                  C:\\Program Files\\Microsoft\\*\\bin\\{name}.exe,
                  C:\\Program Files\\Eclipse Adoptium\\*\\bin\\{name}.exe.
    """
    base_name = re.sub(r"\.(exe|bat|cmd)$", "", name, flags=re.IGNORECASE)

    # a. shutil.which(name) and on win32 shutil.which(f"{name}.exe")
    found = shutil.which(base_name)
    if found:
        return found
    if sys.platform == "win32":
        found_exe = shutil.which(f"{base_name}.exe")
        if found_exe:
            return found_exe

    # b. JAVA_HOME / "bin" / name (and .exe on win32)
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        jh_path = Path(java_home)
        bin_dir = jh_path / "bin"
        candidates = [bin_dir / f"{base_name}.exe", bin_dir / base_name] if sys.platform == "win32" else [bin_dir / base_name]
        for cand in candidates:
            if cand.is_file():
                return str(cand)

    # c. Directory of `javac` on PATH: resolve real symlink path and check sibling
    javac_on_path = shutil.which("javac") or (shutil.which("javac.exe") if sys.platform == "win32" else None)
    if javac_on_path:
        try:
            real_javac = Path(javac_on_path).resolve()
            sibling_candidates = (
                [real_javac.parent / f"{base_name}.exe", real_javac.parent / base_name]
                if sys.platform == "win32"
                else [real_javac.parent / base_name]
            )
            for cand in sibling_candidates:
                if cand.is_file():
                    return str(cand)
        except Exception:
            pass

    # d. Common JVM roots across OSes
    pattern_candidates: List[str] = []
    if sys.platform == "win32":
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        for pf in (prog_files, prog_files_x86):
            if pf:
                pattern_candidates.extend([
                    os.path.join(pf, "Java", "*", "bin", f"{base_name}.exe"),
                    os.path.join(pf, "Microsoft", "*", "bin", f"{base_name}.exe"),
                    os.path.join(pf, "Eclipse Adoptium", "*", "bin", f"{base_name}.exe"),
                    os.path.join(pf, "Semeru", "*", "bin", f"{base_name}.exe"),
                ])
    elif sys.platform == "darwin":
        pattern_candidates.append(f"/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/{base_name}")
    else:
        # Linux and other UNIX
        pattern_candidates.extend([
            f"/usr/lib/jvm/*/bin/{base_name}",
            f"/usr/lib/jvm/*/*/bin/{base_name}",
            f"/usr/java/*/bin/{base_name}",
        ])

    for pattern in pattern_candidates:
        matches = sorted(glob.glob(pattern), reverse=True)
        for m in matches:
            if os.path.isfile(m):
                return m

    return None


def find_sdk_tool(name: str, build_tools_dir: Optional[Path] = None) -> Optional[str]:
    """
    Resolves Android SDK binaries (apksigner, aapt2, d8, adb).
    Search order:
    a. If build_tools_dir is provided and exists, search for candidate filenames
       (on win32: .bat, .exe, .cmd, name; on unix: name).
    b. shutil.which(name) and windows extensions.
    c. SDK roots: ANDROID_HOME, ANDROID_SDK_ROOT, %LOCALAPPDATA%\\Android\\Sdk,
       ~/Library/Android/sdk, ~/Android/Sdk, /usr/local/lib/android/sdk, /usr/lib/android-sdk.
       - For build-tools (apksigner, aapt2, d8): search build-tools/*/<name> sorted in reverse order (highest version first).
       - For platform-tools (adb): search platform-tools/<name>.
    """
    base_name = re.sub(r"\.(exe|bat|cmd)$", "", name, flags=re.IGNORECASE)

    # Candidate file names depending on platform
    if sys.platform == "win32":
        candidates = [f"{base_name}.bat", f"{base_name}.exe", f"{base_name}.cmd", base_name]
    else:
        candidates = [base_name]

    # a. If build_tools_dir is provided and exists
    if build_tools_dir is not None:
        bt_dir = Path(build_tools_dir)
        if bt_dir.is_dir():
            for cand_name in candidates:
                cand_file = bt_dir / cand_name
                if cand_file.is_file():
                    return str(cand_file)

    # b. shutil.which(name) and windows extensions
    found = shutil.which(base_name)
    if found:
        return found
    if sys.platform == "win32":
        for ext in (".bat", ".exe", ".cmd"):
            found_ext = shutil.which(f"{base_name}{ext}")
            if found_ext:
                return found_ext

    # c. SDK roots
    sdk_roots_raw = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk") if os.environ.get("LOCALAPPDATA") else None,
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
        "/usr/local/lib/android/sdk",
        "/usr/lib/android-sdk",
    ]

    sdk_roots = [Path(r) for r in sdk_roots_raw if r and os.path.isdir(r)]

    is_platform_tool = (base_name == "adb")

    for root in sdk_roots:
        if is_platform_tool:
            pt_dir = root / "platform-tools"
            if pt_dir.is_dir():
                for cand_name in candidates:
                    cand_file = pt_dir / cand_name
                    if cand_file.is_file():
                        return str(cand_file)
        else:
            bt_dir = root / "build-tools"
            if bt_dir.is_dir():
                try:
                    version_dirs = sorted([d for d in bt_dir.iterdir() if d.is_dir()], reverse=True)
                    for vdir in version_dirs:
                        for cand_name in candidates:
                            cand_file = vdir / cand_name
                            if cand_file.is_file():
                                return str(cand_file)
                except OSError:
                    continue

            # Fallback check platform-tools if not found in build-tools
            pt_dir = root / "platform-tools"
            if pt_dir.is_dir():
                for cand_name in candidates:
                    cand_file = pt_dir / cand_name
                    if cand_file.is_file():
                        return str(cand_file)

    return None


def diagnose_tools() -> Dict[str, Dict[str, Any]]:
    """
    Inspects: python, keytool, javac, d8, aapt2, apksigner, adb.
    Returns dict mapping tool name to: {"path": Optional[str], "found": bool, "required_for_signing": bool, "hint": str}.
    """
    jdk_hint = "Install OpenJDK (e.g. 'apt install openjdk-17-jdk' or 'brew install openjdk')"
    build_tools_hint = "Install Android SDK build-tools via sdkmanager 'build-tools;35.0.0'"
    platform_tools_hint = "Install Android SDK platform-tools via sdkmanager 'platform-tools'"

    python_path = sys.executable

    tools_to_check = [
        ("python", python_path, False, "Python runtime"),
        ("keytool", find_jdk_tool("keytool"), True, jdk_hint),
        ("javac", find_jdk_tool("javac"), False, jdk_hint),
        ("d8", find_sdk_tool("d8"), False, build_tools_hint),
        ("aapt2", find_sdk_tool("aapt2"), False, build_tools_hint),
        ("apksigner", find_sdk_tool("apksigner"), True, build_tools_hint),
        ("adb", find_sdk_tool("adb"), False, platform_tools_hint),
    ]

    report: Dict[str, Dict[str, Any]] = {}
    for name, resolved_path, required_for_signing, hint in tools_to_check:
        report[name] = {
            "path": resolved_path,
            "found": resolved_path is not None and (os.path.isfile(resolved_path) or shutil.which(resolved_path) is not None),
            "required_for_signing": required_for_signing,
            "hint": hint,
        }

    return report


def run_doctor() -> int:
    """
    Prints a clean, aligned terminal table:
    Columns: Tool, Status ([OK] or [MISSING]), Path or Install Hint.
    Exits 0 if signing tools (keytool and apksigner) or critical tools are present;
    exits 1 with clear summary if any critical signing tool is missing.
    """
    diag = diagnose_tools()

    print("================================================================================")
    print("  ApkRevive Toolchain Doctor")
    print("================================================================================")
    print(f"{'Tool':<12} {'Status':<11} {'Path / Install Hint'}")
    print("-" * 80)

    missing_signing: List[str] = []

    for name, info in diag.items():
        status = "[OK]" if info["found"] else "[MISSING]"
        desc = info["path"] if info["found"] else info["hint"]
        print(f"{name:<12} {status:<11} {desc}")

        if info["required_for_signing"] and not info["found"]:
            missing_signing.append(name)

    print("-" * 80)

    if missing_signing:
        print(f"[-] Toolchain check failed: missing required signing tool(s): {', '.join(missing_signing)}")
        print("    APK signing will fail unless these tools are installed or '--no-sign' is specified.")
        print("    Remediation:")
        for name in missing_signing:
            print(f"      - {name}: {diag[name]['hint']}")
        return 1

    print("[+] Toolchain check passed: all required signing tools are available.")
    return 0


__all__ = [
    "find_jdk_tool",
    "find_sdk_tool",
    "diagnose_tools",
    "run_doctor",
]
