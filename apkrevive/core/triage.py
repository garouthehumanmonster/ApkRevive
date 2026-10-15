"""
triage.py - Authoritative Triage Engine for ApkRevive.
Adheres strictly to platform behavior table, verified test vectors, and bionic linker rules.
"""

from typing import Dict, Any, List
from apkrevive.core.models import Verdict, TriageSignal, DeviceProfile, ApkMetadata
from apkrevive.core.behavior_changes import (
    PUBLIC_SYSTEM_LIBRARIES,
    BIONIC_GREYLIST,
    get_applicable_behavior_changes,
)

DEPRECATED_PERMISSIONS = {
    "android.permission.WRITE_EXTERNAL_STORAGE": "Use MediaStore API or Storage Access Framework (SAF).",
    "android.permission.READ_PHONE_STATE": "Restricted hardware ID access; use Android ID or app-generated UUID.",
    "android.permission.GET_TASKS": "Deprecated in API 21; use ActivityManager.getRunningAppProcesses().",
    "android.permission.PROCESS_OUTGOING_CALLS": "Deprecated in API 29; use CallScreeningService.",
    "android.permission.USE_FINGERPRINT": "Deprecated in API 28; use androidx.biometric.BiometricPrompt.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Restricted overlay permission; requires user grant via Settings.",
}


def evaluate_triage(apk_meta: ApkMetadata, device_profile: DeviceProfile) -> Dict[str, Any]:
    if isinstance(apk_meta, dict):
        apk_meta = ApkMetadata.from_dict(apk_meta)
    if isinstance(device_profile, dict):
        device_profile = DeviceProfile.from_dict(device_profile)

    apk = apk_meta.to_dict()
    device = device_profile.to_dict()

    target_sdk = apk.get("target_sdk", 1)
    apk_abis = set(apk.get("abis", []))
    private_libs = apk.get("private_libs", [])
    has_code = apk.get("has_code", True)
    is_non_resizeable = apk.get("is_non_resizeable", False)
    has_fixed_physics = apk.get("has_fixed_physics", False)
    has_self_sig_check = apk.get("has_self_sig_check", False)
    has_drm = apk.get("has_drm", False)
    apk_size = apk.get("size_bytes", 10_000_000)

    device_sdk = device.get("os_api_level", 35)
    device_floor = device.get("install_floor", 24)
    device_abis = set(device.get("supported_abis", ["arm64-v8a"]))
    device_is_widescreen = device.get("is_widescreen", True)
    device_is_high_refresh = device.get("is_high_refresh", False)

    reasons: List[str] = []
    warnings: List[str] = []
    required_transforms: List[str] = []

    # Query applicable platform behavior changes
    applicable_changes = get_applicable_behavior_changes(apk_meta, device_profile)
    applicable_ids = {c.id for c in applicable_changes}

    # 0. Split APK Check
    if apk.get("is_split_apk"):
        return {
            "verdict": Verdict.RED.value,
            "reason": TriageSignal.SPLIT_APK_UNSUPPORTED.value,
            "details": "Split APKs cannot be modernized independently. Modernize the base APK.",
            "warnings": warnings,
            "required_transforms": []
        }

    # 1. Device ABI Check (with Warning 1: 32-bit-only app on 64-bit-only device)
    if apk_abis:
        matching_abis = apk_abis.intersection(device_abis)
        if not matching_abis:
            is_apk_32bit = apk_abis.issubset({"armeabi-v7a", "armeabi", "x86", "mips"})
            is_device_64bit = device_abis.issubset({"arm64-v8a", "x86_64"})
            if is_apk_32bit and is_device_64bit:
                warnings.append(
                    f"WARN_32BIT_ONLY_ON_64BIT: Application bundles only 32-bit native libraries ({sorted(list(apk_abis))}), "
                    f"but target device supports only 64-bit ABIs ({sorted(list(device_abis))}). Remediation: Recompile native "
                    f"libraries with 64-bit support (arm64-v8a), provide a 32-bit translation layer (such as "
                    f"Houdini/libndk_translation), or run on a device/emulator supporting 32-bit execution."
                )
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.INCOMPATIBLE_DEVICE_ABI.value,
                "details": f"APK ABIs {sorted(list(apk_abis))} do not match device ABIs {sorted(list(device_abis))}",
                "warnings": warnings,
                "required_transforms": []
            }

    # Additional Triage Warnings with Remediation Guidance
    permissions = apk.get("permissions", [])

    # Warning 2: Scoped Storage & OBB on Android 11+
    # Only emitted if SCOPED_STORAGE_ENFORCEMENT (targetSdk >= 30 on API 30+)
    # or RAW_OBB_DATA_PATH_RESTRICTION (accessing raw Android/data, Android/obb or has OBB) applies.
    if "SCOPED_STORAGE_ENFORCEMENT" in applicable_ids or "RAW_OBB_DATA_PATH_RESTRICTION" in applicable_ids:
        warnings.append(
            "WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions or accesses external storage/OBB "
            "paths on Android 11+ (API 30+). Android 11 enforces Scoped Storage and strictly restricts raw filesystem access "
            "to Android/data and Android/obb even with legacy storage flags. Remediation: Adopt Storage Access Framework (SAF) / "
            "MediaStore API, access app-specific files via context.getExternalFilesDirs() / context.getObbDirs(), or deliver "
            "OBB files via standard app expansion / Play Asset Delivery."
        )

    # Warning 3: Hidden-API reflection
    if "HIDDEN_API_REFLECTION_RESTRICTION" in applicable_ids:
        hidden_matches = sorted(list(set(apk.get("hidden_api_reflections", []))))
        warnings.append(
            f"WARN_HIDDEN_API_REFLECTION: Non-SDK / hidden Android API reflection detected ({hidden_matches}). "
            f"Restricted on Android 9+ (API 28+). Remediation: Replace non-SDK reflection with public AndroidX/Jetpack APIs, "
            f"or inject runtime reflection bypass shims (e.g. HiddenApiBypass / VMRuntime exemptions) during Application initialization."
        )

    # Warning 4: Cleartext HTTP & Legacy TLS
    uses_cleartext = apk.get("uses_cleartext_traffic")
    has_nsc = bool(apk.get("has_network_security_config", False))
    legacy_tls = apk.get("legacy_tls_protocols", [])

    should_warn_cleartext = (
        (target_sdk >= 28 and device_sdk >= 28 and (uses_cleartext is False or (uses_cleartext is None and not has_nsc)))
        or (uses_cleartext is False)
    )
    if should_warn_cleartext:
        warnings.append(
            "WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on Android 9+ (API 28+) for applications "
            "targeting API 28+ or declaring android:usesCleartextTraffic=\"false\". Remediation: Enforce HTTPS "
            "using TLS 1.2+, declare android:usesCleartextTraffic=\"true\" in AndroidManifest.xml if unencrypted "
            "HTTP is strictly required, or supply a res/xml/network_security_config.xml."
        )

    if legacy_tls:
        warnings.append(
            f"WARN_LEGACY_TLS: Deprecated TLS protocol references ({sorted(list(set(legacy_tls)))}) detected. "
            "Android 10+ deprecates TLS 1.0 and TLS 1.1; SSLv3 is unsupported. Remediation: Modernize network stack "
            "to negotiate TLS 1.2 and TLS 1.3 exclusively."
        )

    # Warning 5: Deprecated permissions
    found_deprecated = sorted(list(set(p for p in permissions if p in DEPRECATED_PERMISSIONS)))
    if found_deprecated:
        remediations_text = "; ".join(f"{p}: {DEPRECATED_PERMISSIONS[p]}" for p in found_deprecated)
        warnings.append(
            f"WARN_DEPRECATED_PERMISSIONS: Deprecated or restricted permissions detected: {found_deprecated}. "
            f"Remediation: {remediations_text}"
        )

    # 2. Private System Libraries & Bionic Greylist Check
    if private_libs:
        blocked_libs = []
        for lib in private_libs:
            if lib in PUBLIC_SYSTEM_LIBRARIES:
                continue
            if "BIONIC_NAMESPACE_ISOLATION" not in applicable_ids and lib in BIONIC_GREYLIST:
                continue
            blocked_libs.append(lib)

        if blocked_libs:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY.value,
                "details": f"Blocked private platform libraries: {blocked_libs} (targetSdk={target_sdk})",
                "warnings": warnings,
                "required_transforms": []
            }

    # 3. 16KB Page Size Segment Alignment Check
    if "16KB_PAGE_SIZE_KERNEL" in applicable_ids:
        if device_sdk < 36:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.INCOMPATIBLE_PAGE_SIZE.value,
                "details": f"64-bit ELF has invalid or <16KB segment alignment on 16KB kernel (OS API={device_sdk} < 36)",
                "warnings": warnings,
                "required_transforms": []
            }
        else:
            required_transforms.append("PAGE_SIZE_COMPAT")
            reasons.append(TriageSignal.NEEDS_PAGE_SIZE_COMPAT_ANDROID16.value)

    # 4. Modification Requirements Analysis
    if "APACHE_HTTP_LEGACY_REMOVAL" in applicable_ids:
        required_transforms.append("INJECT_USES_LIBRARY_APACHE_HTTP")
        reasons.append(TriageSignal.NEEDS_APACHE_HTTP_LEGACY.value)

    if not has_code and ("PAGE_SIZE_COMPAT" in required_transforms or has_fixed_physics or is_non_resizeable):
        required_transforms.append("SET_HAS_CODE_TRUE")
        reasons.append(TriageSignal.NEEDS_HAS_CODE_FLAG.value)

    if is_non_resizeable and device_is_widescreen:
        required_transforms.append("EXPAND_ASPECT_RATIO")
        reasons.append(TriageSignal.NEEDS_PILLARBOX_FIX.value)

    if has_fixed_physics and device_is_high_refresh:
        required_transforms.append("LOCK_60HZ_DISPLAY_MODE")
        reasons.append(TriageSignal.NEEDS_REFRESH_RATE_FIX.value)

    if has_drm:
        warnings.append("DRM_DETECTED (Informational: unmodified install will not bypass license)")
    if apk.get("static_removed_apis"):
        warnings.append(f"STATIC_REMOVED_APIS_REFERENCED: {apk.get('static_removed_apis')}")

    # 5. Evaluate Verdict Class
    if required_transforms:
        if apk_size > 2 * 1024 * 1024 * 1024:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.EXCEEDS_2GB_LIMIT_FOR_REPACKING.value,
                "details": f"Archive size {apk_size} exceeds 2GB container repacker limit",
                "warnings": warnings,
                "required_transforms": required_transforms
            }

        if has_self_sig_check:
            return {
                "verdict": Verdict.NEEDS_USER_INPUT.value,
                "reason": TriageSignal.SIGNATURE_VERIFICATION_DETECTED.value,
                "details": "APK contains self-signature checks; re-signing will alter signature fingerprint",
                "warnings": warnings,
                "required_transforms": required_transforms
            }

        return {
            "verdict": Verdict.YELLOW.value,
            "reason": TriageSignal.MODIFICATION_REQUIRED.value,
            "details": f"Requires transforms: {required_transforms}",
            "warnings": warnings,
            "required_transforms": required_transforms
        }

    # 6. Unmodified Path (Green)
    is_blocked_by_floor = (
        "TARGET_SDK_INSTALL_FLOOR_API34" in applicable_ids
        or "TARGET_SDK_INSTALL_FLOOR_API35" in applicable_ids
        or target_sdk < device_floor
    )
    install_method = "BYPASS_LOW_TARGET_SDK_BLOCK" if is_blocked_by_floor else "DIRECT_INSTALL"
    return {
        "verdict": Verdict.GREEN.value,
        "reason": TriageSignal.RUNNABLE_UNMODIFIED.value,
        "install_method": install_method,
        "details": f"No transforms needed. Install method: {install_method} (targetSdk={target_sdk}, floor={device_floor})",
        "warnings": warnings,
        "required_transforms": []
    }
