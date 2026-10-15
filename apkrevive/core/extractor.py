"""
extractor.py - Automated APK metadata extraction for ApkRevive modernizer pipeline.
Extracts package info, SDK levels, DEX library references, native ABIs, and ELF alignments.
"""

import os
import re
import struct
import zipfile
from typing import Optional, List, Set

from apkrevive.core.models import ApkMetadata
from apkrevive.core.axml import AxmlSurgeon, AxmlAttribute
from apkrevive.core.elf import inspect_apk_elf_details

PUBLIC_SYSTEM_LIBRARIES = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
    "libandroid.so", "libjnigraphics.so", "libEGL.so", "libGLESv1_CM.so",
    "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libOpenMAXAL.so",
    "libvulkan.so", "libmediandk.so", "libaaudio.so"
}

HIDDEN_FRAMEWORK_APIS = [
    "android/os/SystemProperties",
    "android.os.SystemProperties",
    "android/app/ActivityThread",
    "android.app.ActivityThread",
    "com/android/internal/",
    "com.android.internal.",
    "android/view/WindowManagerGlobal",
    "android.view.WindowManagerGlobal",
    "android/content/pm/IPackageManager",
]

SCOPED_STORAGE_TOKENS = [
    b"Android/data/",
    b"Android/obb/",
    b"Environment.getExternalStorageDirectory",
    b"getExternalStorageDirectory",
    b"getObbDir",
    b"getObbDirs",
]

LEGACY_TLS_TOKENS = [
    (b"SSLv3", "SSLv3"),
    (b"TLSv1\x00", "TLSv1"),
    (b"TLSv1.0", "TLSv1.0"),
    (b"TLSv1.1", "TLSv1.1"),
    (b"SSLSocketFactory", "SSLSocketFactory"),
    (b"TrustAll", "TrustAll"),
]


def _attr_to_int(attr: Optional[AxmlAttribute], default: int = 1) -> int:
    if attr is None:
        return default
    val = attr.get_value()
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val.strip(), 0)
        except ValueError:
            return default
    return default


def _attr_to_bool(attr: Optional[AxmlAttribute], default: bool = True) -> bool:
    if attr is None:
        return default
    val = attr.get_value()
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() not in ("false", "0")
    return default


def get_elf_needed(so_bytes: bytes) -> List[str]:
    """Extracts DT_NEEDED entries from a 64-bit ELF shared library."""
    if len(so_bytes) < 64 or not so_bytes.startswith(b"\x7fELF"):
        return []
    if so_bytes[4] != 2:  # Must be 64-bit ELF
        return []
    endian = "<" if so_bytes[5] == 1 else ">"
    e_phoff = struct.unpack_from(f"{endian}Q", so_bytes, 0x20)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", so_bytes, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", so_bytes, 0x38)[0]
    dyn_off = None
    dyn_sz = None
    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + 56 > len(so_bytes):
            break
        p_type = struct.unpack_from(f"{endian}I", so_bytes, off)[0]
        if p_type == 2:  # PT_DYNAMIC
            dyn_off = struct.unpack_from(f"{endian}Q", so_bytes, off + 8)[0]
            dyn_sz = struct.unpack_from(f"{endian}Q", so_bytes, off + 32)[0]
            break
    if dyn_off is None or dyn_sz is None:
        return []

    needed_offsets: List[int] = []
    strtab_off = None
    curr = dyn_off
    while curr < dyn_off + dyn_sz:
        if curr + 16 > len(so_bytes):
            break
        tag, val = struct.unpack_from(f"{endian}QQ", so_bytes, curr)
        if tag == 0:
            break
        elif tag == 1:
            needed_offsets.append(val)
        elif tag == 5:
            strtab_off = val
        curr += 16

    needed: List[str] = []
    if strtab_off is not None:
        for noff in needed_offsets:
            p = strtab_off + noff
            if p < len(so_bytes):
                end = so_bytes.find(b"\x00", p)
                if end != -1:
                    needed.append(so_bytes[p:end].decode("utf-8", errors="replace"))
    return needed


def inspect_apk(apk_path: str) -> ApkMetadata:
    """
    Inspects an APK file on disk and extracts a populated ApkMetadata dataclass instance.
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    size_bytes = os.path.getsize(apk_path)
    package_name = ""
    version_code = 1
    min_sdk = 1
    target_sdk = 1
    has_code = True
    has_apache_library_decl = False
    is_non_resizeable = False
    has_fixed_physics = False
    is_split_apk = False

    permissions: List[str] = []
    uses_cleartext_traffic: Optional[bool] = None
    has_network_security_config = False
    accesses_scoped_storage_paths = False
    has_cleartext_http = False
    has_obb = False
    hidden_api_reflections: List[str] = []
    legacy_tls_protocols: List[str] = []

    abis_set: Set[str] = set()
    dex_has_apache_http = False
    bundled_sos: Set[str] = set()
    needed_libs: Set[str] = set()

    with zipfile.ZipFile(apk_path, "r") as zf:
        namelist = zf.namelist()

        # 1. Parse AndroidManifest.xml
        if "AndroidManifest.xml" in namelist:
            manifest_data = zf.read("AndroidManifest.xml")
            try:
                root = AxmlSurgeon.parse(manifest_data)

                # Check for split APK
                if root.get_attr("split") is not None or root.get_attr("configForSplit") is not None:
                    is_split_apk = True

                # Package name
                pkg_attr = root.get_attr("package")
                if pkg_attr:
                    val = pkg_attr.get_value()
                    package_name = str(val if val is not None else (pkg_attr.raw_value or ""))

                # Version code
                vc_attr = root.get_attr("versionCode")
                if vc_attr:
                    version_code = _attr_to_int(vc_attr, default=1)

                # SDK versions from <uses-sdk>
                uses_sdk = root.find_child("uses-sdk")
                if uses_sdk:
                    min_attr = uses_sdk.get_attr("minSdkVersion")
                    min_sdk = _attr_to_int(min_attr, default=1) if min_attr else 1

                    target_attr = uses_sdk.get_attr("targetSdkVersion")
                    if target_attr and target_attr.get_value() is not None:
                        target_sdk = _attr_to_int(target_attr, default=min_sdk)
                    else:
                        target_sdk = min_sdk
                else:
                    min_sdk = 1
                    target_sdk = 1

                # Extract <uses-permission> elements from root
                for ch in root.children:
                    if ch.tag in ("uses-permission", "android:uses-permission"):
                        name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                        if name_attr:
                            val = name_attr.get_value()
                            val_str = str(val if val is not None else (name_attr.raw_value or "")).strip()
                            if val_str and val_str not in permissions:
                                permissions.append(val_str)

                # Application attributes & child elements
                app_node = root.find_child("application")
                if app_node:
                    hc_attr = app_node.get_attr("hasCode")
                    has_code = _attr_to_bool(hc_attr, default=True)

                    resiz_attr = app_node.get_attr("resizeableActivity")
                    if resiz_attr is not None:
                        is_non_resizeable = not _attr_to_bool(resiz_attr, default=True)

                    # usesCleartextTraffic
                    uct_attr = app_node.get_attr("usesCleartextTraffic") or app_node.get_attr("android:usesCleartextTraffic")
                    if uct_attr is not None:
                        uses_cleartext_traffic = _attr_to_bool(uct_attr, default=True)

                    # networkSecurityConfig
                    nsc_attr = app_node.get_attr("networkSecurityConfig") or app_node.get_attr("android:networkSecurityConfig")
                    if nsc_attr is not None:
                        has_network_security_config = True

                    # Check for permissions or uses-library / meta-data inside application
                    for ch in app_node.children:
                        if ch.tag in ("uses-permission", "android:uses-permission"):
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr:
                                val = name_attr.get_value()
                                val_str = str(val if val is not None else (name_attr.raw_value or "")).strip()
                                if val_str and val_str not in permissions:
                                    permissions.append(val_str)

                        if ch.tag == "uses-library":
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr:
                                val = name_attr.get_value()
                                raw = name_attr.raw_value
                                if val == "org.apache.http.legacy" or raw == "org.apache.http.legacy":
                                    has_apache_library_decl = True

                        if ch.tag == "meta-data":
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr and name_attr.get_value() == "apkrevive.enable_60hz_lock":
                                val_attr = ch.get_attr("value")
                                if val_attr and not _attr_to_bool(val_attr, default=True):
                                    has_fixed_physics = True

            except Exception:
                pass

        # 2. Scan classes*.dex for Apache HTTP, hidden API reflection, scoped storage, cleartext HTTP, legacy TLS
        for name in namelist:
            if re.fullmatch(r"classes\d*\.dex", name):
                try:
                    dex_bytes = zf.read(name)
                    # Apache HTTP
                    if (
                        b"org/apache/http/" in dex_bytes
                        or b"Lorg/apache/http/" in dex_bytes
                        or b"org.apache.http." in dex_bytes
                    ):
                        dex_has_apache_http = True

                    # Hidden API reflection
                    for api in HIDDEN_FRAMEWORK_APIS:
                        if api.encode("utf-8") in dex_bytes:
                            if api not in hidden_api_reflections:
                                hidden_api_reflections.append(api)

                    # Scoped storage & OBB paths
                    for token in SCOPED_STORAGE_TOKENS:
                        if token in dex_bytes:
                            accesses_scoped_storage_paths = True
                            break

                    # Cleartext HTTP (ignore XML namespaces)
                    for m in re.finditer(rb"http://[^\s\"'<>\x00]+", dex_bytes):
                        url = m.group(0)
                        if (
                            url.startswith(b"http://schemas.android.com")
                            or url.startswith(b"http://www.w3.org")
                            or url.startswith(b"http://xmlpull.org")
                            or url.startswith(b"http://xml.org")
                        ):
                            continue
                        has_cleartext_http = True
                        break

                    # Legacy TLS
                    for token_bytes, token_name in LEGACY_TLS_TOKENS:
                        if token_bytes in dex_bytes:
                            if token_name not in legacy_tls_protocols:
                                legacy_tls_protocols.append(token_name)

                except Exception:
                    pass

        # 3. Scan lib/<abi>/ for native ABIs and track bundled .so files
        for name in namelist:
            if name.startswith("lib/"):
                parts = name.split("/")
                if len(parts) >= 3 and parts[1]:
                    abis_set.add(parts[1])
                elif len(parts) == 2 and parts[1] and name.endswith("/"):
                    abis_set.add(parts[1].rstrip("/"))
            if name.endswith(".so"):
                bundled_sos.add(os.path.basename(name))

        # Scan 64-bit native libraries for private system library references
        for name in namelist:
            if name.endswith(".so") and (name.startswith("lib/arm64-v8a/") or name.startswith("lib/x86_64/")):
                try:
                    so_bytes = zf.read(name)
                    for lib in get_elf_needed(so_bytes):
                        if lib not in bundled_sos and lib not in PUBLIC_SYSTEM_LIBRARIES:
                            needed_libs.add(lib)
                except Exception:
                    pass

        # 4. Container scan: Check if namelist has any .obb files or references
        for name in namelist:
            name_lower = name.lower()
            if name_lower.endswith(".obb") or "/obb/" in name_lower or name_lower.startswith("obb/"):
                has_obb = True
                break

    # 5. Inspect 64-bit ELF load alignment and layout validity
    elf_load_align_64bit, has_invalid_elf_layout = inspect_apk_elf_details(apk_path)

    # 6. Determine uses_apache_http: True if referenced in DEX and NOT declared in uses-library
    uses_apache_http = bool(dex_has_apache_http and not has_apache_library_decl)

    return ApkMetadata(
        package_name=package_name,
        target_sdk=target_sdk,
        min_sdk=min_sdk,
        version_code=version_code,
        abis=sorted(list(abis_set)),
        elf_load_align_64bit=elf_load_align_64bit,
        has_invalid_elf_layout=has_invalid_elf_layout,
        is_split_apk=is_split_apk,
        private_libs=sorted(list(needed_libs)),
        uses_apache_http=uses_apache_http,
        has_code=has_code,
        is_non_resizeable=is_non_resizeable,
        has_fixed_physics=has_fixed_physics,
        size_bytes=size_bytes,
        permissions=permissions,
        uses_cleartext_traffic=uses_cleartext_traffic,
        has_network_security_config=has_network_security_config,
        legacy_tls_protocols=sorted(list(set(legacy_tls_protocols))),
        has_cleartext_http=has_cleartext_http,
        hidden_api_reflections=sorted(list(set(hidden_api_reflections))),
        accesses_scoped_storage_paths=accesses_scoped_storage_paths,
        has_obb=has_obb,
    )
