"""
behavior_changes.py - Android Platform Behavior Changes table and resolution logic.
Authoritative mapping of (targetSdk, deviceApi) behavior changes across Android OS releases.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, List, Set, Dict, Any, Union
from apkrevive.core.models import ApkMetadata, DeviceProfile

PUBLIC_SYSTEM_LIBRARIES: Set[str] = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
    "libandroid.so", "libjnigraphics.so", "libEGL.so", "libGLESv1_CM.so",
    "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libOpenMAXAL.so",
    "libvulkan.so", "libmediandk.so", "libaaudio.so"
}

BIONIC_GREYLIST: Set[str] = {
    "libandroid_runtime.so",
    "libcutils.so",
    "libcrypto.so",
    "libssl.so"
}

TRANSFORM_RISK_LEVELS: Dict[str, str] = {
    "INJECT_USES_LIBRARY_APACHE_HTTP": "LOW",
    "SET_HAS_CODE_TRUE": "MEDIUM",
    "LOCK_60HZ_DISPLAY_MODE": "MEDIUM",
    "EXPAND_ASPECT_RATIO": "HIGH",
    "PAGE_SIZE_COMPAT": "HIGH",
}


@dataclass
class PlatformBehaviorChange:
    id: str
    title: str
    min_target_sdk: Optional[int] = None
    max_target_sdk: Optional[int] = None
    min_device_api: int = 1
    max_device_api: Optional[int] = None
    rule_type: str = "INFO"  # "TRANSFORM", "WARNING", "BLOCK", "INFO"
    action_or_signal: str = ""
    risk_level: str = "LOW"  # "LOW", "MEDIUM", "HIGH"
    doc_url: str = ""
    description: str = ""
    condition: Callable[[ApkMetadata, DeviceProfile], bool] = field(default=lambda apk, dev: True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "min_target_sdk": self.min_target_sdk,
            "max_target_sdk": self.max_target_sdk,
            "min_device_api": self.min_device_api,
            "max_device_api": self.max_device_api,
            "rule_type": self.rule_type,
            "action_or_signal": self.action_or_signal,
            "risk_level": self.risk_level,
            "doc_url": self.doc_url,
            "description": self.description,
        }


def _cond_cleartext_block(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return bool(
        (
            apk.target_sdk >= 28
            and dev.os_api_level >= 28
            and (apk.uses_cleartext_traffic is not True and not apk.has_network_security_config)
        )
        or apk.uses_cleartext_traffic is False
    )


def _cond_apache_http(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return apk.target_sdk >= 28 and dev.os_api_level >= 28 and apk.uses_apache_http


def _cond_scoped_storage(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    storage_perms = {
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    }
    return (
        apk.target_sdk >= 30
        and dev.os_api_level >= 30
        and any(p in storage_perms for p in apk.permissions)
    )


def _cond_raw_obb_data_path(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return dev.os_api_level >= 30 and (apk.accesses_scoped_storage_paths or apk.has_obb)


def _cond_16kb_page_size(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    has_64bit = bool(set(apk.abis).intersection({"arm64-v8a", "x86_64"}))
    unaligned_or_invalid = (
        (apk.elf_load_align_64bit is not None and apk.elf_load_align_64bit < 16384)
        or apk.has_invalid_elf_layout
    )
    return dev.os_api_level >= 35 and dev.page_size_bytes == 16384 and has_64bit and unaligned_or_invalid


def _cond_floor_34(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return dev.os_api_level == 34 and apk.target_sdk < 23


def _cond_floor_35(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return dev.os_api_level >= 35 and apk.target_sdk < 24


def _cond_bionic_isolation(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return (
        apk.target_sdk >= 24
        and dev.os_api_level >= 24
        and any(lib not in PUBLIC_SYSTEM_LIBRARIES for lib in apk.private_libs)
    )


def _cond_hidden_api(apk: ApkMetadata, dev: DeviceProfile) -> bool:
    return dev.os_api_level >= 28 and bool(apk.hidden_api_reflections)


BEHAVIOR_CHANGES: List[PlatformBehaviorChange] = [
    PlatformBehaviorChange(
        id="CLEARTEXT_HTTP_DEFAULT_BLOCK",
        title="Cleartext HTTP Default Block",
        min_target_sdk=28,
        max_target_sdk=None,
        min_device_api=28,
        max_device_api=None,
        rule_type="WARNING",
        action_or_signal="WARN_CLEARTEXT",
        risk_level="MEDIUM",
        doc_url="https://developer.android.com/about/versions/pie/android-9.0-changes-28#opt-out-cleartext",
        description="Android 9+ (API 28+) blocks cleartext HTTP by default for apps targeting API 28+ unless android:usesCleartextTraffic is true.",
        condition=_cond_cleartext_block,
    ),
    PlatformBehaviorChange(
        id="APACHE_HTTP_LEGACY_REMOVAL",
        title="Apache HTTP Legacy Removal",
        min_target_sdk=28,
        max_target_sdk=None,
        min_device_api=28,
        max_device_api=None,
        rule_type="TRANSFORM",
        action_or_signal="INJECT_USES_LIBRARY_APACHE_HTTP",
        risk_level="LOW",
        doc_url="https://developer.android.com/about/versions/pie/android-9.0-changes-28#apache-p",
        description="org.apache.http.legacy removed from bootclasspath on Android 9+ (API 28+) for apps targeting API 28+ without <uses-library>.",
        condition=_cond_apache_http,
    ),
    PlatformBehaviorChange(
        id="SCOPED_STORAGE_ENFORCEMENT",
        title="Scoped Storage Enforcement",
        min_target_sdk=30,
        max_target_sdk=None,
        min_device_api=30,
        max_device_api=None,
        rule_type="WARNING",
        action_or_signal="WARN_SCOPED_STORAGE_OBB",
        risk_level="HIGH",
        doc_url="https://developer.android.com/about/versions/11/privacy/storage",
        description="Android 11+ (API 30+) enforces Scoped Storage for apps targeting API 30+ requesting external storage permissions.",
        condition=_cond_scoped_storage,
    ),
    PlatformBehaviorChange(
        id="RAW_OBB_DATA_PATH_RESTRICTION",
        title="Raw OBB / Data Path Restriction",
        min_target_sdk=None,
        max_target_sdk=None,
        min_device_api=30,
        max_device_api=None,
        rule_type="WARNING",
        action_or_signal="WARN_SCOPED_STORAGE_OBB",
        risk_level="HIGH",
        doc_url="https://developer.android.com/about/versions/11/privacy/storage#raw-path-access",
        description="Android 11+ (API 30+) restricts raw filesystem access to Android/data and Android/obb directories.",
        condition=_cond_raw_obb_data_path,
    ),
    PlatformBehaviorChange(
        id="16KB_PAGE_SIZE_KERNEL",
        title="16KB Page Size Kernel Alignment Enforcement",
        min_target_sdk=None,
        max_target_sdk=None,
        min_device_api=35,
        max_device_api=None,
        rule_type="BLOCK",
        action_or_signal="INCOMPATIBLE_PAGE_SIZE",
        risk_level="HIGH",
        doc_url="https://developer.android.com/guide/practices/page-sizes",
        description="16KB kernel requires 16KB segment alignment and congruent ELF layout for 64-bit native libraries.",
        condition=_cond_16kb_page_size,
    ),
    PlatformBehaviorChange(
        id="TARGET_SDK_INSTALL_FLOOR_API34",
        title="Target SDK Minimum Install Floor API 34",
        min_target_sdk=None,
        max_target_sdk=None,
        min_device_api=34,
        max_device_api=34,
        rule_type="BLOCK",
        action_or_signal="BYPASS_LOW_TARGET_SDK_BLOCK",
        risk_level="LOW",
        doc_url="https://developer.android.com/about/versions/14/behavior-changes-all#minimum-target-api-level",
        description="Android 14 (API 34) blocks direct installation of apps targeting SDK < 23.",
        condition=_cond_floor_34,
    ),
    PlatformBehaviorChange(
        id="TARGET_SDK_INSTALL_FLOOR_API35",
        title="Target SDK Minimum Install Floor API 35+",
        min_target_sdk=None,
        max_target_sdk=None,
        min_device_api=35,
        max_device_api=None,
        rule_type="BLOCK",
        action_or_signal="BYPASS_LOW_TARGET_SDK_BLOCK",
        risk_level="LOW",
        doc_url="https://developer.android.com/about/versions/15/behavior-changes-all#minimum-target-api-level",
        description="Android 15+ (API 35+) blocks direct installation of apps targeting SDK < 24.",
        condition=_cond_floor_35,
    ),
    PlatformBehaviorChange(
        id="BIONIC_NAMESPACE_ISOLATION",
        title="Bionic Linker Namespace Isolation",
        min_target_sdk=24,
        max_target_sdk=None,
        min_device_api=24,
        max_device_api=None,
        rule_type="BLOCK",
        action_or_signal="UNRESOLVABLE_SYSTEM_LIBRARY",
        risk_level="HIGH",
        doc_url="https://developer.android.com/about/versions/nougat/android-7.0-changes#ndk",
        description="Android 7.0+ (API 24+) prevents loading non-public private platform libraries for apps targeting API 24+.",
        condition=_cond_bionic_isolation,
    ),
    PlatformBehaviorChange(
        id="HIDDEN_API_REFLECTION_RESTRICTION",
        title="Hidden API Reflection Restriction",
        min_target_sdk=None,
        max_target_sdk=None,
        min_device_api=28,
        max_device_api=None,
        rule_type="WARNING",
        action_or_signal="WARN_HIDDEN_API_REFLECTION",
        risk_level="MEDIUM",
        doc_url="https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces",
        description="Android 9+ (API 28+) restricts access to non-SDK interfaces via reflection.",
        condition=_cond_hidden_api,
    ),
]


def get_applicable_behavior_changes(
    apk: ApkMetadata, device: DeviceProfile
) -> List[PlatformBehaviorChange]:
    """
    Evaluates and returns all platform behavior changes that apply to the given
    APK metadata running on the specified device profile.
    """
    applicable: List[PlatformBehaviorChange] = []
    for change in BEHAVIOR_CHANGES:
        if change.min_target_sdk is not None and apk.target_sdk < change.min_target_sdk:
            continue
        if change.max_target_sdk is not None and apk.target_sdk > change.max_target_sdk:
            continue
        if device.os_api_level < change.min_device_api:
            continue
        if change.max_device_api is not None and device.os_api_level > change.max_device_api:
            continue
        if not change.condition(apk, device):
            continue
        applicable.append(change)
    return applicable


def is_page_size_compat_verified(results_dir: Optional[Union[str, Path]] = None) -> bool:
    """
    Scans results/*.json (defaulting to the repository's results/ directory or Path.cwd() / "results").
    Looks for any result dictionary with:
      - pass_fail == "PASS"
      - kernel_page_size == 16384
      - Android 16 / API 36 environment (e.g. 36 in android_build or device_model or environment, or os_api_level == 36).
    Returns True if such a PASS result exists, False otherwise.
    """
    if results_dir is not None:
        target_dir = Path(results_dir)
    else:
        repo_results = Path(__file__).resolve().parent.parent.parent / "results"
        if repo_results.is_dir():
            target_dir = repo_results
        else:
            target_dir = Path.cwd() / "results"

    if not target_dir.is_dir():
        return False

    for json_file in sorted(target_dir.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        entries = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("pass_fail") != "PASS":
                continue

            try:
                page_size = int(entry.get("kernel_page_size", 0))
            except (ValueError, TypeError):
                page_size = 0
            if page_size != 16384:
                continue

            api_level = None
            for key in ("os_api_level", "api_level", "device_api"):
                val = entry.get(key)
                if val is not None:
                    try:
                        api_level = int(val)
                        break
                    except (ValueError, TypeError):
                        pass

            is_api_36 = (
                api_level == 36
                or "36" in str(entry.get("android_build", ""))
                or "36" in str(entry.get("device_model", ""))
                or "36" in str(entry.get("environment", ""))
            )
            if is_api_36:
                return True

    return False

