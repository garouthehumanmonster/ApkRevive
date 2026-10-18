"""
extractor.py - Automated APK metadata extraction for ApkRevive modernizer pipeline.
Extracts package info, SDK levels, DEX library references, native ABIs, and ELF alignments.
"""

import os
import re
import struct
import zipfile
from typing import Optional, List, Set, Tuple

from apkrevive.core.models import ApkMetadata
from apkrevive.core.axml import AxmlSurgeon, AxmlAttribute
from apkrevive.core.elf import inspect_apk_elf_details, inspect_apk_elf_textrel

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

GLES1_DEX_TOKENS = [
    b"Landroid/opengl/GLES10;",
    b"Landroid/opengl/GLES11;",
    b"Ljavax/microedition/khronos/opengles/GL10;",
    b"android.opengl.GLES10",
    b"android.opengl.GLES11",
    b"javax.microedition.khronos.opengles.GL10",
]

DEAD_SDK_PATTERNS = [
    ("Google LVL (Licensing)", [b"com/android/vending/licensing", b"com.android.vending.licensing", b"ILicensingService"]),
    ("Google Maps v1", [b"com/google/android/maps", b"com.google.android.maps"]),
    ("Legacy In-App Billing", [b"com/android/vending/billing", b"com.android.vending.billing", b"IInAppBillingService", b"IMarketBillingService"]),
    ("Legacy AdMob (Standalone)", [b"com/google/ads/AdView", b"com.google.ads.AdView"]),
    ("Millennial Media SDK", [b"com/millennialmedia", b"com.millennialmedia"]),
    ("Airpush Ad SDK", [b"com/airpush", b"com.airpush"]),
    ("MoPub Ad SDK", [b"com/mopub", b"com.mopub"]),
    ("Flurry Legacy Ad SDK", [b"com/flurry/android/ads", b"com.flurry.android.ads"]),
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

    pt_loads: List[Tuple[int, int, int]] = []
    dyn_off: Optional[int] = None
    dyn_sz: Optional[int] = None

    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + 56 > len(so_bytes):
            break
        p_type = struct.unpack_from(f"{endian}I", so_bytes, off)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from(f"{endian}Q", so_bytes, off + 8)[0]
            p_vaddr = struct.unpack_from(f"{endian}Q", so_bytes, off + 16)[0]
            p_memsz = struct.unpack_from(f"{endian}Q", so_bytes, off + 40)[0]
            pt_loads.append((p_vaddr, p_memsz, p_offset))
        elif p_type == 2:  # PT_DYNAMIC
            dyn_off = struct.unpack_from(f"{endian}Q", so_bytes, off + 8)[0]
            dyn_sz = struct.unpack_from(f"{endian}Q", so_bytes, off + 32)[0]

    if dyn_off is None or dyn_sz is None:
        return []

    def vaddr_to_offset(vaddr: int) -> Optional[int]:
        for p_vaddr, p_memsz, p_offset in pt_loads:
            if p_vaddr <= vaddr < p_vaddr + p_memsz:
                return p_offset + (vaddr - p_vaddr)
        if vaddr < len(so_bytes):
            return vaddr
        return None

    needed_offsets: List[int] = []
    strtab_off: Optional[int] = None
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
            strtab_off = vaddr_to_offset(val)
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

    uses_gles1 = False
    dead_sdks: Set[str] = set()
    has_request_legacy_external_storage = False

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

                    # requestLegacyExternalStorage
                    rles_attr = app_node.get_attr("requestLegacyExternalStorage") or app_node.get_attr("android:requestLegacyExternalStorage")
                    if rles_attr is not None:
                        has_request_legacy_external_storage = _attr_to_bool(rles_attr, default=True)

                    # networkSecurityConfig
                    nsc_attr = app_node.get_attr("networkSecurityConfig") or app_node.get_attr("android:networkSecurityConfig")
                    if nsc_attr is not None:
                        has_network_security_config = True

                    has_60hz_lock = False
                    # Check for permissions or uses-library / meta-data inside application
                    for ch in app_node.children:
                        if ch.tag in ("uses-permission", "android:uses-permission"):
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr:
                                val = name_attr.get_value()
                                val_str = str(val if val is not None else (name_attr.raw_value or "")).strip()
                                if val_str and val_str not in permissions:
                                    permissions.append(val_str)

                        if ch.tag in ("uses-library", "android:uses-library"):
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr:
                                val = name_attr.get_value()
                                raw = name_attr.raw_value
                                lib_name = str(val if val is not None else (raw or "")).strip()
                                if lib_name == "org.apache.http.legacy":
                                    has_apache_library_decl = True
                                if lib_name in ("libGLESv1_CM.so", "libGLESv1_CM"):
                                    uses_gles1 = True
                                if lib_name == "com.google.android.maps":
                                    dead_sdks.add("Google Maps v1")

                        if ch.tag == "meta-data":
                            name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                            if name_attr and name_attr.get_value() == "apkrevive.enable_60hz_lock":
                                val_attr = ch.get_attr("value")
                                if val_attr and _attr_to_bool(val_attr, default=False):
                                    has_60hz_lock = True
                                elif val_attr and not _attr_to_bool(val_attr, default=True):
                                    has_fixed_physics = True

                    if not has_60hz_lock and ("physicstick" in package_name.lower()):
                        has_fixed_physics = True

                # Check uses-feature in root and application for GLES 1.x
                manifest_feature_nodes = [ch for ch in root.children if ch.tag in ("uses-feature", "android:uses-feature")]
                if app_node:
                    manifest_feature_nodes.extend([ch for ch in app_node.children if ch.tag in ("uses-feature", "android:uses-feature")])

                for f_node in manifest_feature_nodes:
                    gles_attr = f_node.get_attr("glEsVersion") or f_node.get_attr("android:glEsVersion")
                    if gles_attr is not None:
                        v = _attr_to_int(gles_attr, default=0)
                        if 0 < v < 0x00020000:
                            uses_gles1 = True

            except Exception:
                pass

        # Scan namelist for network security config resource file (e.g. res/xml/network_security_config.xml)
        if not has_network_security_config:
            for name in namelist:
                if "network_security_config" in name.lower():
                    has_network_security_config = True
                    break

        # 2. Scan classes*.dex for Apache HTTP, hidden API reflection, scoped storage, legacy TLS, GLES1, dead SDKs, cleartext HTTP
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

                    # Legacy TLS
                    for token_bytes, token_name in LEGACY_TLS_TOKENS:
                        if token_bytes in dex_bytes:
                            if token_name not in legacy_tls_protocols:
                                legacy_tls_protocols.append(token_name)

                    # GLES 1.x tokens
                    for token in GLES1_DEX_TOKENS:
                        if token in dex_bytes:
                            uses_gles1 = True
                            break

                    # Known dead SDK tokens
                    for sdk_name, patterns in DEAD_SDK_PATTERNS:
                        if any(pat in dex_bytes for pat in patterns):
                            dead_sdks.add(sdk_name)

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

        # Native lib GLES 1.x check
        if "libGLESv1_CM.so" in bundled_sos or "libGLESv1_CM.so" in needed_libs:
            uses_gles1 = True

        # 4. Container scan: Check if namelist has any .obb files or references
        for name in namelist:
            name_lower = name.lower()
            if name_lower.endswith(".obb") or "/obb/" in name_lower or name_lower.startswith("obb/"):
                has_obb = True
                break

    # 5. Inspect 64-bit ELF load alignment and layout validity
    elf_load_align_64bit, has_invalid_elf_layout, elf_16kb_status = inspect_apk_elf_details(apk_path)

    # 6. TEXTREL detection
    textrel_libs = inspect_apk_elf_textrel(apk_path)
    has_textrel = bool(textrel_libs)

    # 7. Determine uses_apache_http: True if referenced in DEX and NOT declared in uses-library
    uses_apache_http = bool(dex_has_apache_http and not has_apache_library_decl)

    return ApkMetadata(
        package_name=package_name,
        target_sdk=target_sdk,
        min_sdk=min_sdk,
        version_code=version_code,
        abis=sorted(list(abis_set)),
        elf_load_align_64bit=elf_load_align_64bit,
        has_invalid_elf_layout=has_invalid_elf_layout,
        elf_16kb_status=elf_16kb_status,
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
        uses_gles1=uses_gles1,
        dead_sdks=sorted(list(set(dead_sdks))),
        textrel_libs=textrel_libs,
        has_textrel=has_textrel,
        has_request_legacy_external_storage=has_request_legacy_external_storage,
    )
