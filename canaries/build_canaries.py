#!/usr/bin/env python3
"""
build_canaries.py - Pure-Python synthetic canary APK generator for ApkRevive.
Generates >= 16 synthetic canary APKs in canaries/build/ testing individual
runtime vectors and edge cases across modern Android environments.
"""

import argparse
import os
from pathlib import Path
import struct
import sys
import tempfile
import zipfile

from typing import Optional, List, Dict

from apkrevive.core.align import align_apk
from apkrevive.core.axml import AxmlNode, AxmlSurgeon

CANARIES_DIR = Path(__file__).resolve().parent
BUILD_DIR = CANARIES_DIR / "build"


def make_synthetic_elf(align: int = 16384, machine: int = 183) -> bytes:
    """Builds a minimal synthetic 64-bit ELF binary with 2 PT_LOAD segments."""
    endian = "<"
    ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    header = struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        3, machine, 1, 0x1000, 64, 0, 0, 64, 56, 2, 64, 0, 0
    )
    elf_hdr = ident + header

    ph0 = struct.pack(f"{endian}IIQQQQQQ", 1, 5, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, align)
    ph1 = struct.pack(f"{endian}IIQQQQQQ", 1, 6, align, align, align, 0x1000, 0x1000, align)

    data = bytearray(elf_hdr + ph0 + ph1)
    required_len = align + 0x1000
    if len(data) < required_len:
        data.extend(b"\x00" * (required_len - len(data)))
    return bytes(data)


def build_manifest(
    package_name: str,
    target_sdk: int,
    min_sdk: int,
    version_code: int = 1,
    has_code: bool = True,
    resizeable_activity: bool = True,
    uses_libraries: Optional[List[str]] = None,
    meta_data: Optional[Dict[str, str]] = None,
    extract_native_libs: bool = True,
    request_legacy_external_storage: bool = False,
) -> bytes:
    root = AxmlNode(tag="manifest")
    root.set_attr("package", package_name, ns="")
    root.set_attr("versionCode", version_code)

    uses_sdk = AxmlNode(tag="uses-sdk")
    uses_sdk.set_attr("minSdkVersion", min_sdk)
    uses_sdk.set_attr("targetSdkVersion", target_sdk)
    root.children.append(uses_sdk)

    app = AxmlNode(tag="application")
    app.set_attr("hasCode", has_code)
    app.set_attr("resizeableActivity", resizeable_activity)
    app.set_attr("extractNativeLibs", extract_native_libs)
    if request_legacy_external_storage:
        app.set_attr("requestLegacyExternalStorage", True)

    if uses_libraries:
        for lib_name in uses_libraries:
            lib_node = AxmlNode(tag="uses-library")
            lib_node.set_attr("name", lib_name)
            lib_node.set_attr("required", False)
            app.children.append(lib_node)

    if meta_data:
        for k, v in meta_data.items():
            md = AxmlNode(tag="meta-data")
            md.set_attr("name", k)
            md.set_attr("value", v)
            app.children.append(md)

    root.children.append(app)
    return AxmlSurgeon.serialize(root)


CANARY_SPECS = [
    # 1. Install Floor pair
    {
        "filename": "canary_install_floor_control.apk",
        "package": "com.apkrevive.canary.installfloor.control",
        "target_sdk": 24,
        "min_sdk": 24,
        "version_code": 100,
    },
    {
        "filename": "canary_install_floor_failing.apk",
        "package": "com.apkrevive.canary.installfloor.failing",
        "target_sdk": 22,
        "min_sdk": 14,
    },
    # 2. Apache HTTP pair
    {
        "filename": "canary_apache_http_control.apk",
        "package": "com.apkrevive.canary.apachehttp.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "uses_libraries": ["org.apache.http.legacy"],
        "dex_tokens": [b"Lorg/apache/http/client/HttpClient;"],
    },
    {
        "filename": "canary_apache_http_failing.apk",
        "package": "com.apkrevive.canary.apachehttp.failing",
        "target_sdk": 28,
        "min_sdk": 21,
        "dex_tokens": [b"Lorg/apache/http/client/HttpClient;"],
    },
    # 3. 16KB Page Size pair (arm64-v8a)
    {
        "filename": "canary_page_size_control.apk",
        "package": "com.apkrevive.canary.pagesize.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "elf_files": {"lib/arm64-v8a/libnative.so": (16384, 183)},
        "align_zip": True,
    },
    {
        "filename": "canary_page_size_failing.apk",
        "package": "com.apkrevive.canary.pagesize.failing",
        "target_sdk": 28,
        "min_sdk": 21,
        "elf_files": {"lib/arm64-v8a/libnative.so": (4096, 183)},
        "align_zip": False,
    },
    # 4. HasCode pair
    {
        "filename": "canary_has_code_control.apk",
        "package": "com.apkrevive.canary.hascode.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "has_code": True,
    },
    {
        "filename": "canary_has_code_failing.apk",
        "package": "com.apkrevive.canary.hascode.failing",
        "target_sdk": 22,
        "min_sdk": 15,
        "has_code": False,
    },
    # 5. Physics Tick (60Hz) pair
    {
        "filename": "canary_physics_tick_control.apk",
        "package": "com.apkrevive.canary.physicstick.control",
        "target_sdk": 28,
        "min_sdk": 21,
    },
    {
        "filename": "canary_physics_tick_failing.apk",
        "package": "com.apkrevive.canary.physicstick.failing",
        "target_sdk": 22,
        "min_sdk": 15,
        "meta_data": {"apkrevive.fixed_physics": "true"},
    },
    # 6. Aspect Ratio pair
    {
        "filename": "canary_aspect_ratio_control.apk",
        "package": "com.apkrevive.canary.aspectratio.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "resizeable_activity": True,
    },
    {
        "filename": "canary_aspect_ratio_failing.apk",
        "package": "com.apkrevive.canary.aspectratio.failing",
        "target_sdk": 22,
        "min_sdk": 15,
        "resizeable_activity": False,
        "meta_data": {"android.max_aspect": "1.778"},
    },
    # 7. Bionic Greylist pair
    {
        "filename": "canary_bionic_greylist_control.apk",
        "package": "com.apkrevive.canary.bionicgreylist.control",
        "target_sdk": 22,
        "min_sdk": 15,
    },
    {
        "filename": "canary_bionic_greylist_failing.apk",
        "package": "com.apkrevive.canary.bionicgreylist.failing",
        "target_sdk": 26,
        "min_sdk": 21,
    },
    # 8. OBB Version pair
    {
        "filename": "canary_obb_version_control.apk",
        "package": "com.apkrevive.canary.obbversion.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "version_code": 100,
        "extra_files": {"main.100.com.apkrevive.canary.obbversion.control.obb": b"OBB_100"},
    },
    {
        "filename": "canary_obb_version_failing.apk",
        "package": "com.apkrevive.canary.obbversion.failing",
        "target_sdk": 22,
        "min_sdk": 15,
        "version_code": 100,
        "extra_files": {"main.200.com.apkrevive.canary.obbversion.failing.obb": b"OBB_200"},
    },
    # 9. 16KB Page Size pair (x86_64)
    {
        "filename": "canary_page_size_x86_64_control.apk",
        "package": "com.apkrevive.canary.pagesize.x86_64.control",
        "target_sdk": 28,
        "min_sdk": 21,
        "elf_files": {"lib/x86_64/libnative.so": (16384, 62)},
        "align_zip": True,
    },
    {
        "filename": "canary_page_size_x86_64_failing.apk",
        "package": "com.apkrevive.canary.pagesize.x86_64.failing",
        "target_sdk": 28,
        "min_sdk": 21,
        "elf_files": {"lib/x86_64/libnative.so": (4096, 62)},
        "align_zip": False,
    },
]


def build_canary_apk(spec: dict, out_path: Path) -> None:
    manifest_bytes = build_manifest(
        package_name=spec["package"],
        target_sdk=spec["target_sdk"],
        min_sdk=spec["min_sdk"],
        version_code=spec.get("version_code", 1),
        has_code=spec.get("has_code", True),
        resizeable_activity=spec.get("resizeable_activity", True),
        uses_libraries=spec.get("uses_libraries"),
        meta_data=spec.get("meta_data"),
        extract_native_libs=spec.get("extract_native_libs", True),
        request_legacy_external_storage=spec.get("request_legacy_external_storage", False),
    )

    dex_bytes = bytearray(b"dex\n035\x00" + b"\x00" * 128)
    if "dex_tokens" in spec:
        for token in spec["dex_tokens"]:
            dex_bytes.extend(token)
            dex_bytes.extend(b"\x00")

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_f:
        tmp_path = tmp_f.name

    try:
        with zipfile.ZipFile(tmp_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest_bytes)
            zf.writestr("classes.dex", bytes(dex_bytes))

            if "elf_files" in spec:
                for so_path, (align_val, machine_val) in spec["elf_files"].items():
                    so_bytes = make_synthetic_elf(align=align_val, machine=machine_val)
                    zinfo = zipfile.ZipInfo(so_path)
                    zinfo.compress_type = zipfile.ZIP_STORED if spec.get("align_zip") else zipfile.ZIP_DEFLATED
                    zf.writestr(zinfo, so_bytes)

            if "extra_files" in spec:
                for extra_name, extra_content in spec["extra_files"].items():
                    zf.writestr(extra_name, extra_content)

        if spec.get("align_zip"):
            align_apk(tmp_path, str(out_path))
        else:
            with open(tmp_path, "rb") as fin, open(out_path, "wb") as fout:
                fout.write(fin.read())
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def main(force: bool = False) -> int:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    script_mtime = os.path.getmtime(__file__)

    # Idempotency check: if all canaries exist and are newer than this script, skip
    all_exist = all((BUILD_DIR / str(s["filename"])).exists() for s in CANARY_SPECS)
    if all_exist and not force:
        all_newer = all((BUILD_DIR / str(s["filename"])).stat().st_mtime >= script_mtime for s in CANARY_SPECS)
        if all_newer:
            print(f"[CACHED] All {len(CANARY_SPECS)} canary APKs up to date in {BUILD_DIR}")
            return 0

    print(f"[*] Building {len(CANARY_SPECS)} synthetic canary APKs in {BUILD_DIR}...")
    for spec in CANARY_SPECS:
        out_path = BUILD_DIR / str(spec["filename"])
        build_canary_apk(spec, out_path)
        print(f"  [+] Built {spec['filename']} ({out_path.stat().st_size} bytes)")

    print(f"[OK] Successfully built {len(CANARY_SPECS)} canary APKs.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build synthetic canary APKs")
    parser.add_argument("--force", action="store_true", help="Force rebuild all canaries")
    args = parser.parse_args()
    sys.exit(main(force=args.force))
