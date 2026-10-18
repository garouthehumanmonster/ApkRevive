"""
triage.py - Authoritative Triage Engine for ApkRevive.
Adheres strictly to platform behavior table, verified test vectors, and bionic linker rules.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from apkrevive.core.models import Verdict, TriageSignal, DeviceProfile, ApkMetadata
from apkrevive.core.behavior_changes import (
    PUBLIC_SYSTEM_LIBRARIES,
    BIONIC_GREYLIST,
    TRANSFORM_RISK_LEVELS,
    get_applicable_behavior_changes,
    is_page_size_compat_verified,
)

DEPRECATED_PERMISSIONS = {
    "android.permission.WRITE_EXTERNAL_STORAGE": "Use MediaStore API or Storage Access Framework (SAF).",
    "android.permission.READ_PHONE_STATE": "Restricted hardware ID access; use Android ID or app-generated UUID.",
    "android.permission.GET_TASKS": "Deprecated in API 21; use ActivityManager.getRunningAppProcesses().",
    "android.permission.PROCESS_OUTGOING_CALLS": "Deprecated in API 29; use CallScreeningService.",
    "android.permission.USE_FINGERPRINT": "Deprecated in API 28; use androidx.biometric.BiometricPrompt.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Restricted overlay permission; requires user grant via Settings.",
}


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ACCESS_MEDIA_LOCATION",
}


def evaluate_triage(
    apk_meta: ApkMetadata,
    device_profile: DeviceProfile,
    results_dir: Optional[Union[str, Path]] = None,
    bump_target_sdk: Optional[int] = None,
) -> Dict[str, Any]:
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
            "required_transforms": [],
            "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
            "page_size_compat_verified": True,
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
                "required_transforms": [],
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
                "page_size_compat_verified": True,
            }

    # Additional Triage Warnings with Remediation Guidance
    permissions = apk.get("permissions", [])

    # Warning 1: Hidden-API reflection
    if (apk.get("hidden_api_reflections") and device_sdk >= 28) or "HIDDEN_API_REFLECTION_RESTRICTION" in applicable_ids:
        hidden_matches = sorted(list(set(apk.get("hidden_api_reflections", []))))
        warnings.append(
            f"WARN_HIDDEN_API_REFLECTION: Non-SDK / hidden Android API reflection detected ({hidden_matches}). "
            f"Restricted on Android 9+ (API 28+). Remediation: Replace non-SDK reflection with public AndroidX/Jetpack APIs, "
            f"or inject runtime reflection bypass shims (e.g. HiddenApiBypass / VMRuntime exemptions) during Application initialization."
        )

    # Warning 2: GLES 1.x Deprecation
    if apk.get("uses_gles1"):
        warnings.append(
            "WARN_GLES1_DEPRECATED: Application depends on legacy OpenGL ES 1.x APIs or libraries (libGLESv1_CM). "
            "Modern Android devices and 64-bit environments deprecate GLES 1.x in favor of GLES 2.0/3.x or Vulkan. "
            "Remediation: Migrate rendering pipeline to OpenGL ES 2.0+ / Vulkan, or bundle a software GLES 1.x translation layer."
        )

    # Warning 3: Known-Dead SDKs
    if apk.get("dead_sdks"):
        dead_matches = sorted(list(set(apk.get("dead_sdks", []))))
        warnings.append(
            f"WARN_DEAD_SDKS: Defunct or sunset legacy SDKs detected ({dead_matches}). "
            f"These services (e.g., Google LVL, Maps v1, legacy In-App Billing, obsolete ad SDKs) are no longer functional or supported. "
            f"Remediation: Remove obsolete SDK dependencies, migrate to Google Play Billing Library v6+, Google Maps Android API v2, "
            f"or modern ad provider SDKs."
        )

    # Warning 4: TEXTREL Native Libs
    if apk.get("has_textrel") or apk.get("textrel_libs"):
        textrel_names = sorted(list(set(apk.get("textrel_libs", []))))
        lib_str = f" ({textrel_names})" if textrel_names else ""
        warnings.append(
            f"WARN_TEXTREL: Native library containing text relocations (DT_TEXTREL) detected{lib_str}. "
            f"Android 6.0+ (API 23+) dynamic linker refuses to load binaries with text relocations for security (W^X memory policy). "
            f"Remediation: Recompile native code with -fPIC to eliminate text relocations."
        )

    # Warning 5: Cleartext HTTP & Legacy TLS
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

    # Warning 6: Scoped Storage & OBB on Android 11+
    has_storage_perms = any(p in {"android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE"} for p in permissions)
    is_scoped_storage_risk = (
        "SCOPED_STORAGE_ENFORCEMENT" in applicable_ids
        or "RAW_OBB_DATA_PATH_RESTRICTION" in applicable_ids
        or (target_sdk >= 30 and device_sdk >= 30 and (has_storage_perms or apk.get("has_request_legacy_external_storage")))
        or (device_sdk >= 30 and (apk.get("accesses_scoped_storage_paths") or apk.get("has_obb")))
    )
    if is_scoped_storage_risk:
        warnings.append(
            "WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions, declares legacy storage request, "
            "or accesses external storage/OBB paths on Android 11+ (API 30+). Android 11 enforces Scoped Storage and strictly restricts "
            "raw filesystem access to Android/data and Android/obb even with legacy storage flags. Remediation: Adopt Storage Access Framework (SAF) / "
            "MediaStore API, access app-specific files via context.getExternalFilesDirs() / context.getObbDirs(), or deliver "
            "OBB files via standard app expansion / Play Asset Delivery."
        )

    # Deprecated permissions
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
                "required_transforms": [],
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
                "page_size_compat_verified": True,
            }

    # 3. 16KB Page Size Segment Alignment Check
    elf_16kb_status = apk.get("elf_16kb_status")
    has_invalid_elf = bool(apk.get("has_invalid_elf_layout", False))

    if "16KB_PAGE_SIZE_KERNEL" in applicable_ids or (device.get("page_size_bytes") == 16384 and (elf_16kb_status == "UNSAFE" or has_invalid_elf)):
        if elf_16kb_status == "UNSAFE" or has_invalid_elf:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.INCOMPATIBLE_PAGE_SIZE.value,
                "details": "64-bit ELF has invalid or <16KB segment alignment: fake header patch with colliding 16KB pages cannot run safely on 16KB kernel",
                "warnings": warnings,
                "required_transforms": [],
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
                "page_size_compat_verified": True,
            }

        if device_sdk < 36:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.INCOMPATIBLE_PAGE_SIZE.value,
                "details": f"64-bit ELF has invalid or <16KB segment alignment on 16KB kernel (OS API={device_sdk} < 36)",
                "warnings": warnings,
                "required_transforms": [],
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
                "page_size_compat_verified": True,
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

    effective_target_sdk = bump_target_sdk if bump_target_sdk is not None else target_sdk

    if bump_target_sdk is not None and bump_target_sdk >= 23:
        dangerous_matches = sorted(list(set(
            p for p in permissions
            if p in DANGEROUS_PERMISSIONS or f"android.permission.{p}" in DANGEROUS_PERMISSIONS
        )))
        if dangerous_matches:
            warnings.append(
                f"WARN_RUNTIME_PERMISSIONS_ON_BUMP: targetSdkVersion bumped to {bump_target_sdk} (>= 23). "
                f"The APK requests dangerous permissions ({dangerous_matches}) which become runtime permissions. "
                f"Functionality requiring these permissions may fail unless granted at runtime or via settings/adb."
            )

    if bump_target_sdk is not None and bump_target_sdk != target_sdk:
        required_transforms.append("BUMP_TARGET_SDK")
        reasons.append(TriageSignal.MODIFICATION_REQUIRED.value)

    if bump_target_sdk is not None:
        is_blocked_by_floor = effective_target_sdk < device_floor
    else:
        is_blocked_by_floor = (
            "TARGET_SDK_INSTALL_FLOOR_API34" in applicable_ids
            or "TARGET_SDK_INSTALL_FLOOR_API35" in applicable_ids
            or effective_target_sdk < device_floor
        )
    install_method = "BYPASS_LOW_TARGET_SDK_BLOCK" if is_blocked_by_floor else "DIRECT_INSTALL"

    # 5. Evaluate Verdict Class
    if required_transforms:
        res: Dict[str, Any]
        if apk_size > 2 * 1024 * 1024 * 1024:
            res = {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.EXCEEDS_2GB_LIMIT_FOR_REPACKING.value,
                "install_method": install_method,
                "details": f"Archive size {apk_size} exceeds 2GB container repacker limit",
                "warnings": warnings,
                "required_transforms": required_transforms,
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
            }
        elif has_self_sig_check:
            res = {
                "verdict": Verdict.NEEDS_USER_INPUT.value,
                "reason": TriageSignal.SIGNATURE_VERIFICATION_DETECTED.value,
                "install_method": install_method,
                "details": "APK contains self-signature checks; re-signing will alter signature fingerprint",
                "warnings": warnings,
                "required_transforms": required_transforms,
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
            }
        else:
            res = {
                "verdict": Verdict.YELLOW.value,
                "reason": TriageSignal.MODIFICATION_REQUIRED.value,
                "install_method": install_method,
                "details": f"Requires transforms: {required_transforms}",
                "warnings": warnings,
                "required_transforms": required_transforms,
                "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
            }

        if "PAGE_SIZE_COMPAT" in required_transforms:
            verified = is_page_size_compat_verified(results_dir)
            res["page_size_compat_verified"] = verified
            if not verified:
                res["verdict_display"] = f"{res['verdict']} (UNVERIFIED)"
                unverified_suffix = " (UNVERIFIED: pageSizeCompat mode is unverified; no API 36 16KB device result in results/)"
                curr_details = str(res.get("details", ""))
                res["details"] = (curr_details + unverified_suffix) if curr_details else unverified_suffix.strip()
        else:
            res["page_size_compat_verified"] = True

        return res

    # 6. Unmodified Path (Green)
    is_blocked_by_floor = (
        "TARGET_SDK_INSTALL_FLOOR_API34" in applicable_ids
        or "TARGET_SDK_INSTALL_FLOOR_API35" in applicable_ids
        or effective_target_sdk < device_floor
    )
    install_method = "BYPASS_LOW_TARGET_SDK_BLOCK" if is_blocked_by_floor else "DIRECT_INSTALL"
    return {
        "verdict": Verdict.GREEN.value,
        "reason": TriageSignal.RUNNABLE_UNMODIFIED.value,
        "install_method": install_method,
        "details": f"No transforms needed. Install method: {install_method} (targetSdk={effective_target_sdk}, floor={device_floor})",
        "warnings": warnings,
        "required_transforms": [],
        "transform_risks": {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in required_transforms},
        "page_size_compat_verified": True,
    }
