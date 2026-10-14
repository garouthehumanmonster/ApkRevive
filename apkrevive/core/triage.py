"""
triage.py - Authoritative Triage Engine for ApkRevive v3.3.
Adheres strictly to the 16 verified test vectors and bionic linker rules.
"""

from typing import Dict, Any, List
from apkrevive.core.models import Verdict, TriageSignal, DeviceProfile, ApkMetadata


BIONIC_GREYLIST = {
    "libandroid_runtime.so",
    "libcutils.so",
    "libcrypto.so",
    "libssl.so"
}

PUBLIC_SYSTEM_LIBRARIES = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
    "libandroid.so", "libjnigraphics.so", "libEGL.so", "libGLESv1_CM.so",
    "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libOpenMAXAL.so",
    "libvulkan.so", "libmediandk.so", "libaaudio.so"
}


def evaluate_triage(apk_meta: ApkMetadata, device_profile: DeviceProfile) -> Dict[str, Any]:
    apk = apk_meta.to_dict()
    device = device_profile.to_dict()

    target_sdk = apk.get("target_sdk", 1)
    apk_abis = set(apk.get("abis", []))
    elf_load_align = apk.get("elf_load_align_64bit")
    private_libs = apk.get("private_libs", [])
    uses_apache_http = apk.get("uses_apache_http", False)
    has_code = apk.get("has_code", True)
    is_non_resizeable = apk.get("is_non_resizeable", False)
    has_fixed_physics = apk.get("has_fixed_physics", False)
    has_self_sig_check = apk.get("has_self_sig_check", False)
    has_drm = apk.get("has_drm", False)
    apk_size = apk.get("size_bytes", 10_000_000)

    device_sdk = device.get("os_api_level", 35)
    device_floor = device.get("install_floor", 24)
    device_abis = set(device.get("supported_abis", ["arm64-v8a"]))
    device_page_size = device.get("page_size_bytes", 16384)
    device_is_widescreen = device.get("is_widescreen", True)
    device_is_high_refresh = device.get("is_high_refresh", False)

    reasons: List[str] = []
    warnings: List[str] = []
    required_transforms: List[str] = []

    # 1. Device ABI Check
    if apk_abis:
        matching_abis = apk_abis.intersection(device_abis)
        if not matching_abis:
            return {
                "verdict": Verdict.RED.value,
                "reason": TriageSignal.INCOMPATIBLE_DEVICE_ABI.value,
                "details": f"APK ABIs {sorted(list(apk_abis))} do not match device ABIs {sorted(list(device_abis))}",
                "warnings": warnings,
                "required_transforms": []
            }

    # 2. Private System Libraries & Bionic Greylist Check
    if private_libs:
        blocked_libs = []
        for lib in private_libs:
            if lib in PUBLIC_SYSTEM_LIBRARIES:
                continue
            if target_sdk < 24 and lib in BIONIC_GREYLIST:
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
    has_64bit_native = bool(apk_abis.intersection({"arm64-v8a", "x86_64"}))
    if device_page_size == 16384 and has_64bit_native:
        if elf_load_align is not None and elf_load_align < 16384:
            if device_sdk < 36:
                return {
                    "verdict": Verdict.RED.value,
                    "reason": TriageSignal.INCOMPATIBLE_PAGE_SIZE.value,
                    "details": f"64-bit ELF has PT_LOAD p_align={elf_load_align} (< 16384) on 16KB kernel (OS API={device_sdk} < 36)",
                    "warnings": warnings,
                    "required_transforms": []
                }
            else:
                required_transforms.append("PAGE_SIZE_COMPAT")
                reasons.append(TriageSignal.NEEDS_PAGE_SIZE_COMPAT_ANDROID16.value)

    # 4. Modification Requirements Analysis
    if target_sdk == 28 and uses_apache_http:
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
    install_method = "DIRECT_INSTALL" if target_sdk >= device_floor else "BYPASS_LOW_TARGET_SDK_BLOCK"
    return {
        "verdict": Verdict.GREEN.value,
        "reason": TriageSignal.RUNNABLE_UNMODIFIED.value,
        "install_method": install_method,
        "details": f"No transforms needed. Install method: {install_method} (targetSdk={target_sdk}, floor={device_floor})",
        "warnings": warnings,
        "required_transforms": []
    }
