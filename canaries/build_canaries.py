#!/usr/bin/env python3
"""
build_canaries.py - Authoritative build engine for ApkRevive v3.3 Canary Test Suite.
Builds all 8 canaries with Control and Failing variants (16 APKs + 2 OBBs) into canaries/build/.
"""

import os
import sys
import struct
import shutil
import zipfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from apkrevive.core.align import align_apk
from apkrevive.core.signer import sign_apk, verify_apk
from apkrevive.core.elf import parse_elf_load_align

def find_sdk_root() -> Path:
    candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk") if os.environ.get("LOCALAPPDATA") else None,
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
        r"C:\Users\Divyansh\AppData\Local\Android\Sdk",
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
    """Resolves tool binaries cross-platform via shutil.which, SDK search, and platform checks."""
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
            for p in known_windows_javacs:
                if os.path.isfile(p):
                    return p
            prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            java_dir = Path(prog_files) / "Java"
            if java_dir.is_dir():
                for cand in sorted(java_dir.glob("**/javac.exe"), reverse=True):
                    return str(cand)
        return "javac.exe" if sys.platform == "win32" else "javac"

    if build_tools_dir and build_tools_dir.is_dir():
        candidates = [f"{name}.bat", f"{name}.exe", f"{name}.cmd", name] if sys.platform == "win32" else [name]
        for cand in candidates:
            p = build_tools_dir / cand
            if p.is_file():
                return str(p)

    if sys.platform == "win32":
        ext = ".bat" if name in ("d8", "apksigner") else ".exe"
        if build_tools_dir:
            return str(build_tools_dir / f"{name}{ext}")
        return f"{name}{ext}"
    if build_tools_dir:
        return str(build_tools_dir / name)
    return name


SDK_ROOT = find_sdk_root()
BUILD_TOOLS = find_build_tools(SDK_ROOT)
PLATFORM_DIR = find_platform_dir(SDK_ROOT)

AAPT2_EXE = resolve_tool("aapt2", BUILD_TOOLS)
D8_BAT = resolve_tool("d8", BUILD_TOOLS)
APKSIGNER_BAT = resolve_tool("apksigner", BUILD_TOOLS)
ANDROID_JAR = str(PLATFORM_DIR / "android.jar")
APACHE_HTTP_JAR = str(PLATFORM_DIR / "optional" / "org.apache.http.legacy.jar")
JAVAC_EXE = resolve_tool("javac")

CANARIES_DIR = Path(__file__).resolve().parent
SRC_DIR = CANARIES_DIR / "src"
BUILD_DIR = CANARIES_DIR / "build"


def create_arm64_elf_so(p_align: int = 16384, needed_libs: Optional[List[str]] = None) -> bytes:
    """
    Generates a deterministic 64-bit ELF shared library (arm64-v8a) with specified
    PT_LOAD p_align and dynamic DT_NEEDED entries.
    """
    needed_libs = needed_libs or []

    # Dynamic string table (.dynstr)
    dynstr = b"\x00"
    needed_offsets = []
    for lib in needed_libs:
        needed_offsets.append(len(dynstr))
        dynstr += lib.encode("utf-8") + b"\x00"

    pad = (8 - (len(dynstr) % 8)) % 8
    dynstr += b"\x00" * pad

    # Dynamic table entries (Elf64_Dyn: 16 bytes each)
    dyn_entries = []
    for off in needed_offsets:
        dyn_entries.append((1, off))  # DT_NEEDED = 1

    phnum = 3
    phentsize = 56
    phoff = 64
    ph_table_size = phnum * phentsize

    seg1_filesz = phoff + ph_table_size + 64
    seg1_memsz = seg1_filesz

    seg2_offset = p_align
    seg2_vaddr = p_align

    num_dyn = len(dyn_entries) + 3  # + DT_STRTAB, DT_STRSZ, DT_NULL
    dyn_size = num_dyn * 16
    strtab_vaddr = seg2_vaddr + dyn_size

    dyn_entries.append((5, strtab_vaddr))   # DT_STRTAB = 5
    dyn_entries.append((10, len(dynstr)))   # DT_STRSZ = 10
    dyn_entries.append((0, 0))              # DT_NULL = 0

    dyn_bytes = b"".join(struct.pack("<QQ", tag, val) for tag, val in dyn_entries)
    seg2_data = dyn_bytes + dynstr
    seg2_filesz = len(seg2_data)
    seg2_memsz = seg2_filesz

    # ELF Header: 64 bytes
    e_ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elf_hdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,          # e_type: ET_DYN (3)
        0xB7,       # e_machine: EM_AARCH64 (183)
        1,          # e_version: EV_CURRENT (1)
        0,          # e_entry
        phoff,      # e_phoff
        0,          # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        phentsize,  # e_phentsize
        phnum,      # e_phnum
        64,         # e_shentsize
        0,          # e_shnum
        0           # e_shstrndx
    )

    # Elf64_Phdr: (type, flags, offset, vaddr, paddr, filesz, memsz, align)
    ph0 = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, seg1_filesz, seg1_memsz, p_align)
    ph1 = struct.pack("<IIQQQQQQ", 1, 6, seg2_offset, seg2_vaddr, seg2_vaddr, seg2_filesz, seg2_memsz, p_align)
    ph2 = struct.pack("<IIQQQQQQ", 2, 6, seg2_offset, seg2_vaddr, seg2_vaddr, dyn_size, dyn_size, 8)

    seg1_data = elf_hdr + ph0 + ph1 + ph2
    seg1_data += b"\x00" * (seg1_filesz - len(seg1_data))
    pad_to_seg2 = b"\x00" * (seg2_offset - len(seg1_data))

    return seg1_data + pad_to_seg2 + seg2_data


CANARY_DEFINITIONS: List[Dict[str, Any]] = [
    # 1. canary_install_floor
    {
        "id": "canary_install_floor",
        "variant": "control",
        "manifest": "canary_install_floor_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_install_floor variant=control targetSdk=24",
        "page_align": 16384,
    },
    {
        "id": "canary_install_floor",
        "variant": "failing",
        "manifest": "canary_install_floor_failing.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_install_floor variant=failing targetSdk=22",
        "page_align": 16384,
    },
    # 2. canary_apache_http
    {
        "id": "canary_apache_http",
        "variant": "control",
        "manifest": "canary_apache_http_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_apache_http variant=control targetSdk=22 uses_library=false",
        "page_align": 16384,
    },
    {
        "id": "canary_apache_http",
        "variant": "failing",
        "manifest": "canary_apache_http_failing.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_apache_http variant=failing targetSdk=28 uses_library=false",
        "page_align": 16384,
    },
    # 3. canary_page_size
    {
        "id": "canary_page_size",
        "variant": "control",
        "manifest": "canary_page_size_control.xml",
        "has_code": True,
        "native_so": ("libcanary_page_size.so", 16384, []),
        "logcat_line": "ApkReviveCanary: canary_page_size variant=control p_align=16384 abi=arm64-v8a",
        "page_align": 16384,
    },
    {
        "id": "canary_page_size",
        "variant": "failing",
        "manifest": "canary_page_size_failing.xml",
        "has_code": True,
        "native_so": ("libcanary_page_size.so", 4096, []),
        "logcat_line": "ApkReviveCanary: canary_page_size variant=failing p_align=4096 abi=arm64-v8a",
        "page_align": 4096,
    },
    # 4. canary_physics_tick
    {
        "id": "canary_physics_tick",
        "variant": "control",
        "manifest": "canary_physics_tick_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_physics_tick variant=control enable_60hz_lock=true mode=locked_60hz",
        "page_align": 16384,
    },
    {
        "id": "canary_physics_tick",
        "variant": "failing",
        "manifest": "canary_physics_tick_failing.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_physics_tick variant=failing enable_60hz_lock=false mode=free_running",
        "page_align": 16384,
    },
    # 5. canary_aspect_ratio
    {
        "id": "canary_aspect_ratio",
        "variant": "control",
        "manifest": "canary_aspect_ratio_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_aspect_ratio variant=control resizeableActivity=true",
        "page_align": 16384,
    },
    {
        "id": "canary_aspect_ratio",
        "variant": "failing",
        "manifest": "canary_aspect_ratio_failing.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_aspect_ratio variant=failing resizeableActivity=false max_aspect=1.777777",
        "page_align": 16384,
    },
    # 6. canary_bionic_greylist
    {
        "id": "canary_bionic_greylist",
        "variant": "control",
        "manifest": "canary_bionic_greylist_control.xml",
        "has_code": True,
        "native_so": ("libcanary_bionic.so", 16384, ["libcrypto.so"]),
        "logcat_line": "ApkReviveCanary: canary_bionic_greylist variant=control targetSdk=22 lib=libcrypto.so",
        "page_align": 16384,
    },
    {
        "id": "canary_bionic_greylist",
        "variant": "failing",
        "manifest": "canary_bionic_greylist_failing.xml",
        "has_code": True,
        "native_so": ("libcanary_bionic.so", 16384, ["libgui.so"]),
        "logcat_line": "ApkReviveCanary: canary_bionic_greylist variant=failing targetSdk=28 lib=libgui.so",
        "page_align": 16384,
    },
    # 7. canary_has_code
    {
        "id": "canary_has_code",
        "variant": "control",
        "manifest": "canary_has_code_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_has_code variant=control hasCode=true",
        "page_align": 16384,
    },
    {
        "id": "canary_has_code",
        "variant": "failing",
        "manifest": "canary_has_code_failing.xml",
        "has_code": False,
        "logcat_line": "ApkReviveCanary: canary_has_code variant=failing hasCode=false",
        "page_align": 16384,
    },
    # 8. canary_obb_version
    {
        "id": "canary_obb_version",
        "variant": "control",
        "manifest": "canary_obb_version_control.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_obb_version variant=control apk_vcode=150 obb_vcode=100 status=VALID",
        "page_align": 16384,
    },
    {
        "id": "canary_obb_version",
        "variant": "failing",
        "manifest": "canary_obb_version_failing.xml",
        "has_code": True,
        "logcat_line": "ApkReviveCanary: canary_obb_version variant=failing apk_vcode=100 obb_vcode=200 status=WARNING_AHEAD",
        "page_align": 16384,
    },
]


def compile_java_classes(tmp_dir: Path) -> Path:
    """Compiles all canary Java sources into DEX bytecodes."""
    bin_dir = tmp_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dex_dir = tmp_dir / "dex"
    dex_dir.mkdir(parents=True, exist_ok=True)

    java_files = list((SRC_DIR / "java").rglob("*.java"))
    if not java_files:
        raise RuntimeError("No Java source files found in canaries/src/java/")

    cp = f"{ANDROID_JAR}{os.pathsep}{APACHE_HTTP_JAR}" if os.path.exists(APACHE_HTTP_JAR) else ANDROID_JAR
    cmd_javac = [JAVAC_EXE, "-cp", cp, "-d", str(bin_dir)] + [str(f) for f in java_files]
    res_javac = subprocess.run(cmd_javac, capture_output=True, text=True)
    if res_javac.returncode != 0:
        raise RuntimeError(f"javac failed: {res_javac.stderr}")

    class_files = list(bin_dir.rglob("*.class"))
    cmd_d8 = [D8_BAT, "--lib", ANDROID_JAR, "--output", str(dex_dir)] + [str(f) for f in class_files]
    res_d8 = subprocess.run(cmd_d8, capture_output=True, text=True)
    if res_d8.returncode != 0:
        raise RuntimeError(f"d8 failed: {res_d8.stderr}")

    classes_dex = dex_dir / "classes.dex"
    if not classes_dex.exists():
        raise RuntimeError("classes.dex was not generated by d8")

    return classes_dex


def build_canary_apk(defn: Dict[str, Any], shared_classes_dex: Path, tmp_dir: Path) -> Path:
    """Builds, aligns, and signs a single canary APK variant."""
    canary_id = defn["id"]
    variant = defn["variant"]
    out_apk_name = f"{canary_id}_{variant}.apk"
    final_apk = BUILD_DIR / out_apk_name

    manifest_xml = SRC_DIR / "manifests" / defn["manifest"]
    if not manifest_xml.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_xml}")

    # Step 1: aapt2 link to produce compiled AndroidManifest.xml
    raw_apk = tmp_dir / f"raw_{out_apk_name}"
    cmd_aapt2 = [
        AAPT2_EXE, "link",
        "-I", ANDROID_JAR,
        "--manifest", str(manifest_xml),
        "-o", str(raw_apk)
    ]
    res_aapt2 = subprocess.run(cmd_aapt2, capture_output=True, text=True)
    if res_aapt2.returncode != 0:
        raise RuntimeError(f"aapt2 link failed for {out_apk_name}: {res_aapt2.stderr}")

    with zipfile.ZipFile(raw_apk, "r") as zf:
        manifest_bytes = zf.read("AndroidManifest.xml")

    # Step 2: Assemble unaligned APK
    unaligned_apk = tmp_dir / f"unaligned_{out_apk_name}"
    with zipfile.ZipFile(unaligned_apk, "w") as zout:
        # Write AndroidManifest.xml
        zout.writestr("AndroidManifest.xml", manifest_bytes)

        # Write classes.dex if has_code is True
        if defn.get("has_code", True):
            with open(shared_classes_dex, "rb") as df:
                zout.writestr("classes.dex", df.read())

        # Write canonical logcat info file
        logcat_line = defn.get("logcat_line", "")
        zout.writestr("assets/canary_logcat.txt", logcat_line.encode("utf-8") + b"\n")

        # Write native library if specified (stored uncompressed for page align)
        if "native_so" in defn:
            so_name, so_align, needed_libs = defn["native_so"]
            so_bytes = create_arm64_elf_so(p_align=so_align, needed_libs=needed_libs)
            zinfo = zipfile.ZipInfo(f"lib/arm64-v8a/{so_name}")
            zinfo.compress_type = zipfile.ZIP_STORED
            zout.writestr(zinfo, so_bytes)

    # Step 3: Align APK
    page_align = defn.get("page_align", 16384)
    align_apk(str(unaligned_apk), str(final_apk), page_align_64bit=page_align)

    # Step 4: Sign APK
    if not sign_apk(str(final_apk)):
        raise RuntimeError(f"Signing failed for {final_apk}")

    # Step 5: Verify APK signature
    v_res = verify_apk(str(final_apk))
    if not v_res.get("verified"):
        raise RuntimeError(f"Signature verification failed for {final_apk}: {v_res.get('output')}")

    return final_apk


def build_obb_files() -> List[Path]:
    """Generates the OBB test vectors for canary_obb_version."""
    obb_outputs = []

    # Control: APK v150, OBB v100
    ctrl_obb = BUILD_DIR / "main.100.com.apkrevive.canary.obbversion.control.obb"
    with zipfile.ZipFile(ctrl_obb, "w") as zf:
        zf.writestr("assets/data.bin", b"OBB_CONTROL_PAYLOAD_V100\n")
    obb_outputs.append(ctrl_obb)

    # Failing: APK v100, OBB v200
    fail_obb = BUILD_DIR / "main.200.com.apkrevive.canary.obbversion.failing.obb"
    with zipfile.ZipFile(fail_obb, "w") as zf:
        zf.writestr("assets/data.bin", b"OBB_FAILING_PAYLOAD_V200_AHEAD_OF_APK\n")
    obb_outputs.append(fail_obb)

    return obb_outputs


def build_all() -> Dict[str, Any]:
    """Builds all 16 canaries and 2 OBB files."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    tmp_dir = BUILD_DIR / "tmp_build"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building ApkRevive v3.3 Canary Suite into {BUILD_DIR}...")
    print(f"[*] Compiling Java sources with javac & d8...")
    classes_dex = compile_java_classes(tmp_dir)

    built_apks = []
    for defn in CANARY_DEFINITIONS:
        cid = defn["id"]
        var = defn["variant"]
        print(f"  -> Building {cid} [{var}]...")
        apk_path = build_canary_apk(defn, classes_dex, tmp_dir)
        built_apks.append(str(apk_path))

    print(f"[*] Generating OBB expansion files...")
    obbs = build_obb_files()
    for obb in obbs:
        print(f"  -> Created OBB: {obb.name}")

    # Clean up temporary build artifacts
    shutil.rmtree(tmp_dir, ignore_errors=True)

    summary = {
        "apks": [os.path.basename(p) for p in built_apks],
        "obbs": [p.name for p in obbs],
        "count": len(built_apks),
    }
    print(f"[+] Successfully built {len(built_apks)} signed canary APKs and {len(obbs)} OBB files.")
    return summary


if __name__ == "__main__":
    res = build_all()
    sys.exit(0 if res["count"] == 16 else 1)
