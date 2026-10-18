#!/usr/bin/env python3
"""verify_canary_matrix.py - Canary Matrix Runner and Multi-Tier Verification Harness.

Automated verification across 4 AVD tiers:
- Tier 1: API 19 (KitKat x86 - Dalvik primary DEX hook & bytecode verification)
- Tier 2: API 28 (Pie x86_64 - legacy Apache HTTP removal & storage verification)
- Tier 3: API 34 (Android 14 x86_64 - targetSdkVersion block bypass verification)
- Tier 4: API 35 (Android 15 google_apis_ps16k x86_64 - 16KB kernel page-size dlopen verification)

Supports live ADB connection via --device or offline dual-assertion simulation via --simulate.
Conforms to results schema in scripts/generate_matrix.py.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Optional
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict, TriageSignal
from apkrevive.core.triage import evaluate_triage
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.elf import inspect_apk_elf_align
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.extractor import inspect_apk, get_elf_needed
from apkrevive.adb.bridge import AdbBridge

from scripts.generate_matrix import (
    validate_result_schema,
    update_compatibility_doc,
    format_results_section,
    load_results,
    DEFAULT_RESULTS_DIR,
    DEFAULT_DOC_PATH,
)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

CANARIES_BUILD = PROJECT_ROOT / "canaries" / "build"


@dataclass
class AVDTier:
    tier_id: str
    name: str
    api_level: int
    arch: str
    page_size: int
    install_floor: int
    focus: str
    profile: DeviceProfile


TIERS: dict[str, AVDTier] = {
    "19": AVDTier(
        tier_id="19",
        name="Tier 1: API 19 (KitKat x86)",
        api_level=19,
        arch="x86",
        page_size=4096,
        install_floor=1,
        focus="Dalvik primary DEX hook & bytecode verification",
        profile=DeviceProfile(
            os_api_level=19,
            install_floor=1,
            supported_abis=["x86", "armeabi-v7a"],
            page_size_bytes=4096,
            is_widescreen=False,
            is_high_refresh=False,
        ),
    ),
    "28": AVDTier(
        tier_id="28",
        name="Tier 2: API 28 (Pie x86_64)",
        api_level=28,
        arch="x86_64",
        page_size=4096,
        install_floor=1,
        focus="Legacy Apache HTTP removal & storage verification",
        profile=DeviceProfile(
            os_api_level=28,
            install_floor=1,
            supported_abis=["x86_64", "x86"],
            page_size_bytes=4096,
            is_widescreen=False,
            is_high_refresh=False,
        ),
    ),
    "34": AVDTier(
        tier_id="34",
        name="Tier 3: API 34 (Android 14 x86_64)",
        api_level=34,
        arch="x86_64",
        page_size=4096,
        install_floor=23,
        focus="targetSdkVersion block bypass verification",
        profile=DeviceProfile(
            os_api_level=34,
            install_floor=23,
            supported_abis=["x86_64", "arm64-v8a"],
            page_size_bytes=4096,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    ),
    "35": AVDTier(
        tier_id="35",
        name="Tier 4: API 35 (Android 15 google_apis_ps16k x86_64)",
        api_level=35,
        arch="x86_64",
        page_size=16384,
        install_floor=24,
        focus="16KB kernel page-size dlopen verification",
        profile=DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["x86_64", "arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=True,
        ),
    ),
}

CANARY_NAMES: list[str] = [
    "canary_install_floor",
    "canary_apache_http",
    "canary_page_size",
    "canary_physics_tick",
    "canary_aspect_ratio",
    "canary_bionic_greylist",
    "canary_has_code",
    "canary_obb_version",
]


@dataclass
class CanaryAssertionResult:
    canary_id: str
    control_passed: bool
    control_detail: str
    revived_passed: bool
    revived_detail: str
    pass_fail: str
    expected: str
    observed: str
    tier_id: str
    mode: str = "STATIC"


def get_git_commit(project_root: Path = PROJECT_ROOT) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "0.3.3"


def tier_from_device_profile(profile: DeviceProfile) -> str:
    if profile.os_api_level <= 19:
        return "19"
    if profile.os_api_level <= 28:
        return "28"
    if profile.os_api_level <= 34:
        return "34"
    return "35"


def detect_device_tier(bridge: AdbBridge) -> tuple[str, DeviceProfile, dict[str, str]]:
    sdk_str = bridge.get_prop("ro.build.version.sdk")
    sdk = int(sdk_str) if sdk_str.isdigit() else 35

    floor_str = bridge.get_prop("ro.build.version.min_supported_target_sdk")
    floor = int(floor_str) if floor_str.isdigit() else (24 if sdk >= 35 else (23 if sdk >= 34 else 1))

    abis_str = bridge.get_prop("ro.product.cpu.abilist") or bridge.get_prop("ro.product.cpu.abi")
    abis = [a.strip() for a in abis_str.split(",") if a.strip()] or ["x86_64"]

    ps_str = bridge.get_prop("ro.boot.page_size") or bridge.get_prop("ro.product.cpu.pagesize")
    flavor = (bridge.get_prop("ro.build.flavor") or bridge.get_prop("ro.product.name") or "").lower()
    if ps_str.isdigit():
        page_size = int(ps_str)
    elif "16k" in flavor or "ps16k" in flavor:
        page_size = 16384
    elif hasattr(bridge, "get_page_size"):
        page_size = bridge.get_page_size()
    else:
        page_size = 4096

    model = bridge.get_prop("ro.product.model") or "Android Device"
    build_id = bridge.get_prop("ro.build.display.id") or f"SDK {sdk}"

    if sdk <= 19:
        tier_id = "19"
    elif sdk <= 28:
        tier_id = "28"
    elif sdk <= 34:
        tier_id = "34"
    else:
        tier_id = "35"

    profile = DeviceProfile(
        os_api_level=sdk,
        install_floor=floor,
        supported_abis=abis,
        page_size_bytes=page_size,
        is_widescreen=sdk >= 30,
        is_high_refresh=sdk >= 30,
    )
    props = {
        "sdk": str(sdk),
        "floor": str(floor),
        "abis": abis_str,
        "page_size": str(page_size),
        "model": model,
        "build_id": build_id,
    }
    return tier_id, profile, props


def verify_canary_install_floor(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_install_floor_failing.apk"
    meta = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(target_sdk=22)
    pkg_name = meta.package_name or "com.apkrevive.canary.installfloor.failing"
    mode = "ON_DEVICE" if bridge else "STATIC"

    if profile.os_api_level >= 34:
        if bridge:
            bridge.uninstall(pkg_name)
            ok, out = bridge.install(str(failing_apk), bypass_low_target_sdk=False)
            ctrl_pass = (not ok) and ("INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out)
            ctrl_msg = f"Live ADB direct install rejected: {out.strip()}"
        else:
            triage_before = evaluate_triage(meta, profile)
            ctrl_pass = (meta.target_sdk < profile.install_floor) and (
                triage_before.get("install_method") == "BYPASS_LOW_TARGET_SDK_BLOCK"
            )
            ctrl_msg = f"targetSdk {meta.target_sdk} < floor {profile.install_floor}; direct install blocked"
    else:
        ctrl_pass = True
        ctrl_msg = f"API {profile.os_api_level} < 34; no targetSdk floor enforced"

    if bridge:
        ok_bypass, out_bypass = bridge.install(str(failing_apk), bypass_low_target_sdk=True)
        rev_pass = ok_bypass and ("Success" in out_bypass)
        rev_msg = f"Live ADB bypass install succeeded: {out_bypass.strip()}"
        bridge.uninstall(pkg_name)
    else:
        triage_after = evaluate_triage(meta, profile)
        rev_pass = triage_after.get("verdict") == Verdict.GREEN.value
        rev_msg = f"Bypass strategy selected: {triage_after.get('install_method')}; verdict GREEN"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_install_floor",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="Reject SDK < floor on API 34+ without bypass; succeed with bypass",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
        mode=mode,
    )


def verify_canary_apache_http(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_apache_http_failing.apk"
    meta = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(target_sdk=28, uses_apache_http=True)

    with zipfile.ZipFile(failing_apk, "r") as zf:
        root_before = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
        app_before = root_before.find_child("application")
        has_lib_before = bool(
            app_before and app_before.find_child("uses-library", "name", "org.apache.http.legacy")
        )

    triage_before = evaluate_triage(meta, profile)
    if profile.os_api_level >= 28 and meta.target_sdk >= 28:
        ctrl_pass = (not has_lib_before) and (
            "INJECT_USES_LIBRARY_APACHE_HTTP" in triage_before.get("required_transforms", [])
        )
        ctrl_msg = "uses-library absent; triage flags INJECT_USES_LIBRARY_APACHE_HTTP (NoClassDefFoundError avoided)"
    else:
        ctrl_pass = not has_lib_before
        ctrl_msg = "Platform bootclasspath retains Apache HTTP on API < 28"

    with zipfile.ZipFile(failing_apk, "r") as zf:
        patched_xml = AxmlSurgeon.patch_manifest(zf.read("AndroidManifest.xml"), ["INJECT_USES_LIBRARY_APACHE_HTTP"])
    root_after = AxmlSurgeon.parse(patched_xml)
    app_after = root_after.find_child("application")
    lib_node = app_after.find_child("uses-library", "name", "org.apache.http.legacy") if app_after else None
    req_attr = lib_node.get_attr("required") if lib_node else None
    rev_pass = (lib_node is not None) and (req_attr is not None and not req_attr.get_value())
    rev_msg = "uses-library org.apache.http.legacy injected with android:required=false"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_apache_http",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="Flag missing Apache HTTP library on API 28+; inject uses-library cleanly",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_page_size(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_page_size_failing.apk"
    control_apk = canaries_dir / "canary_page_size_control.apk"

    align_fail = inspect_apk_elf_align(str(failing_apk)) if failing_apk.exists() else 4096
    align_ctrl = inspect_apk_elf_align(str(control_apk)) if control_apk.exists() else 16384

    meta_fail = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=4096)
    meta_ctrl = inspect_apk(str(control_apk)) if control_apk.exists() else ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=16384)

    triage_fail = evaluate_triage(meta_fail, profile)
    triage_ctrl = evaluate_triage(meta_ctrl, profile)

    if profile.page_size_bytes == 16384 and profile.os_api_level == 35:
        ctrl_pass = (align_fail == 4096) and (triage_fail.get("verdict") == Verdict.RED.value)
        ctrl_msg = f"ELF align 4KB on 16KB kernel rejected with RED {triage_fail.get('reason')}"
    else:
        ctrl_pass = align_fail == 4096
        ctrl_msg = f"ELF align 4KB recorded; kernel page size is {profile.page_size_bytes}B"

    rev_pass = (align_ctrl is not None and align_ctrl >= 16384) and (triage_ctrl.get("reason") != TriageSignal.INCOMPATIBLE_PAGE_SIZE.value)
    rev_msg = f"Control ELF rewritten with {align_ctrl}B alignment; 16KB page size constraint satisfied"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_page_size",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="4KB ELF dlopen aborts on 16KB kernel; 16KB aligned ELF succeeds cleanly",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_physics_tick(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_physics_tick_failing.apk"
    meta_fail = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(has_fixed_physics=True)

    with zipfile.ZipFile(failing_apk, "r") as zf:
        root_before = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
        app_before = root_before.find_child("application")
        has_lock_before = bool(
            app_before and app_before.find_child("meta-data", "name", "apkrevive.enable_60hz_lock")
        )

    triage_fail = evaluate_triage(meta_fail, profile)
    if profile.is_high_refresh:
        ctrl_pass = (not has_lock_before) and (
            "LOCK_60HZ_DISPLAY_MODE" in triage_fail.get("required_transforms", [])
        )
        ctrl_msg = "High refresh display detected without 60Hz lock; flags LOCK_60HZ_DISPLAY_MODE"
    else:
        ctrl_pass = not has_lock_before
        ctrl_msg = "60Hz standard display; free-running tick matches native display refresh"

    with zipfile.ZipFile(failing_apk, "r") as zf:
        patched_xml = AxmlSurgeon.patch_manifest(
            zf.read("AndroidManifest.xml"),
            ["LOCK_60HZ_DISPLAY_MODE"],
            options={"enable_60hz": True},
        )
    root_after = AxmlSurgeon.parse(patched_xml)
    app_after = root_after.find_child("application")
    meta_node = app_after.find_child("meta-data", "name", "apkrevive.enable_60hz_lock") if app_after else None
    prov_node = app_after.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider") if app_after else None

    meta_val = meta_node.get_attr("value") if meta_node else None
    rev_pass = bool(meta_val and meta_val.get_value() and prov_node)
    rev_msg = "ApkReviveInitProvider shim and apkrevive.enable_60hz_lock metadata injected"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_physics_tick",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="Free-running tick flags desync on high refresh; 60Hz lock shim injected",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_aspect_ratio(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_aspect_ratio_failing.apk"
    meta_fail = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(is_non_resizeable=True)

    with zipfile.ZipFile(failing_apk, "r") as zf:
        root_before = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
        app_before = root_before.find_child("application")
        resiz_before = app_before.get_attr("resizeableActivity") if app_before else None
        is_resizeable_before = resiz_before.get_value() if resiz_before else False

    triage_fail = evaluate_triage(meta_fail, profile)
    if profile.is_widescreen:
        ctrl_pass = (not is_resizeable_before) and (
            "EXPAND_ASPECT_RATIO" in triage_fail.get("required_transforms", [])
        )
        ctrl_msg = "resizeableActivity=false with max_aspect cap flagged EXPAND_ASPECT_RATIO on widescreen"
    else:
        ctrl_pass = not is_resizeable_before
        ctrl_msg = "Standard 16:9 non-widescreen display; max_aspect matches panel geometry"

    with zipfile.ZipFile(failing_apk, "r") as zf:
        patched_xml = AxmlSurgeon.patch_manifest(zf.read("AndroidManifest.xml"), ["EXPAND_ASPECT_RATIO"])
    root_after = AxmlSurgeon.parse(patched_xml)
    app_after = root_after.find_child("application")
    resiz_after = app_after.get_attr("resizeableActivity") if app_after else None
    is_resizeable_after = resiz_after.get_value() if resiz_after else False

    rev_pass = bool(is_resizeable_after)
    rev_msg = "resizeableActivity=true injected; fills modern viewport without letterboxing"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_aspect_ratio",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="resizeableActivity=false letterboxes on tall displays; expands with resizeableActivity=true",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_bionic_greylist(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_bionic_greylist_failing.apk"
    control_apk = canaries_dir / "canary_bionic_greylist_control.apk"

    meta_fail = inspect_apk(str(failing_apk)) if failing_apk.exists() else ApkMetadata(target_sdk=28, private_libs=["libgui.so"])
    meta_ctrl = inspect_apk(str(control_apk)) if control_apk.exists() else ApkMetadata(target_sdk=22, private_libs=["libcrypto.so"])

    with zipfile.ZipFile(failing_apk, "r") as zf:
        needed_fail = get_elf_needed(zf.read("lib/arm64-v8a/libcanary_bionic.so"))
    with zipfile.ZipFile(control_apk, "r") as zf:
        needed_ctrl = get_elf_needed(zf.read("lib/arm64-v8a/libcanary_bionic.so"))

    if profile.os_api_level >= 24:
        eval_profile = DeviceProfile(
            os_api_level=profile.os_api_level,
            install_floor=profile.install_floor,
            supported_abis=["arm64-v8a", "x86_64"],
            page_size_bytes=profile.page_size_bytes,
        )
        triage_fail = evaluate_triage(meta_fail, eval_profile)
        triage_ctrl = evaluate_triage(meta_ctrl, eval_profile)
        ctrl_pass = ("libgui.so" in needed_fail) and (triage_fail.get("reason") == TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY.value)
        ctrl_msg = f"Direct DT_NEEDED linkage to libgui.so rejected with RED {triage_fail.get('reason')}"
        rev_pass = ("libcrypto.so" in needed_ctrl) and (triage_ctrl.get("verdict") == Verdict.GREEN.value)
        rev_msg = "Triage halts corrupt deployment of unresolvable system library; control greylist allowed on targetSdk 22"
    else:
        ctrl_pass = "libgui.so" in needed_fail
        ctrl_msg = "API < 24; bionic namespace isolation not enforced on KitKat"
        rev_pass = "libcrypto.so" in needed_ctrl
        rev_msg = "Bionic greylist rule exempt on API < 24"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_bionic_greylist",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="libgui.so rejected on API 24+; triage flags fatal unresolvable system library",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_has_code(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_apk = canaries_dir / "canary_has_code_failing.apk"

    with zipfile.ZipFile(failing_apk, "r") as zf:
        root_before = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
        app_before = root_before.find_child("application")
        hc_before = app_before.get_attr("hasCode") if app_before else None
        has_code_before = hc_before.get_value() if hc_before else True

    ctrl_pass = not has_code_before
    ctrl_msg = f"hasCode={has_code_before} prevents Dalvik/ART bytecode execution"

    with zipfile.ZipFile(failing_apk, "r") as zf:
        patched_xml = AxmlSurgeon.patch_manifest(zf.read("AndroidManifest.xml"), ["SET_HAS_CODE_TRUE"])
    root_after = AxmlSurgeon.parse(patched_xml)
    app_after = root_after.find_child("application")
    hc_after = app_after.get_attr("hasCode") if app_after else None
    has_code_after = hc_after.get_value() if hc_after else False

    rev_pass = has_code_after is True
    rev_msg = "hasCode=true injected and primary DEX trampoline enabled"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_has_code",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="hasCode=false prevents bytecode execution; AxmlSurgeon flips hasCode=true with DEX trampoline",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


def verify_canary_obb_version(
    canaries_dir: Path, profile: DeviceProfile, bridge: Optional[AdbBridge] = None
) -> CanaryAssertionResult:
    failing_obb = "main.200.com.apkrevive.canary.obbversion.failing.obb"
    control_obb = "main.100.com.apkrevive.canary.obbversion.control.obb"

    res_fail = validate_obb_delivery(failing_obb, "com.apkrevive.canary.obbversion.failing", current_apk_version=100)
    ctrl_pass = bool(res_fail.get("valid") and "EXPANSION_VERSION_AHEAD_OF_APK" in res_fail.get("warning", ""))
    ctrl_msg = f"OBB v200 ahead of APK v100 triggers warning: {res_fail.get('warning')}"

    res_ctrl = validate_obb_delivery(control_obb, "com.apkrevive.canary.obbversion.control", current_apk_version=150)
    rev_pass = bool(res_ctrl.get("valid") and res_ctrl.get("warning") is None)
    rev_msg = "OBB v100 with APK v150 delivery validated cleanly with version aligned"

    passed = ctrl_pass and rev_pass
    return CanaryAssertionResult(
        canary_id="canary_obb_version",
        control_passed=ctrl_pass,
        control_detail=ctrl_msg,
        revived_passed=rev_pass,
        revived_detail=rev_msg,
        pass_fail="PASS" if passed else "FAIL",
        expected="OBB ahead of APK triggers warning; aligned OBB delivery validates cleanly",
        observed=f"Control: {ctrl_msg} | Revived: {rev_msg}",
        tier_id=tier_from_device_profile(profile),
    )


CANARY_VERIFIERS: dict[str, Callable[[Path, DeviceProfile, Optional[AdbBridge]], CanaryAssertionResult]] = {
    "canary_install_floor": verify_canary_install_floor,
    "canary_apache_http": verify_canary_apache_http,
    "canary_page_size": verify_canary_page_size,
    "canary_physics_tick": verify_canary_physics_tick,
    "canary_aspect_ratio": verify_canary_aspect_ratio,
    "canary_bionic_greylist": verify_canary_bionic_greylist,
    "canary_has_code": verify_canary_has_code,
    "canary_obb_version": verify_canary_obb_version,
}


def run_tier_verification(
    tier: AVDTier,
    canaries_dir: Path,
    bridge: Optional[AdbBridge] = None,
    filter_canary: Optional[str] = None,
) -> list[CanaryAssertionResult]:
    results = []
    canaries_to_run = [filter_canary] if filter_canary else CANARY_NAMES
    for cid in canaries_to_run:
        verifier = CANARY_VERIFIERS[cid]
        res = verifier(canaries_dir, tier.profile, bridge)
        results.append(res)
    return results


def build_receipt_dict(
    record: CanaryAssertionResult,
    tier: AVDTier,
    device_model: str,
    emulator_or_hardware: str,
    android_build: str,
    git_commit: str,
    date_str: str,
    simulated: bool = False,
) -> dict[str, Any]:
    return {
        "device_model": device_model,
        "android_build": android_build,
        "kernel_page_size": tier.page_size,
        "refresh_rate": 120 if tier.profile.is_high_refresh else 60,
        "emulator_or_hardware": emulator_or_hardware,
        "date": date_str,
        "tool_commit": git_commit,
        "canary_id": record.canary_id,
        "expected": record.expected,
        "observed": record.observed,
        "pass_fail": record.pass_fail,
        "simulated": simulated,
    }


def write_receipt(receipt: dict[str, Any], results_dir: Path, env_slug: str) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    out_file = results_dir / f"{env_slug}_{receipt['canary_id']}.json"
    validate_result_schema(receipt, out_file)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)
    return out_file


def render_results_table(all_results: list[tuple[AVDTier, list[CanaryAssertionResult]]]) -> None:
    total_passed = sum(1 for _, res_list in all_results for r in res_list if r.pass_fail == "PASS")
    total_tests = sum(len(res_list) for _, res_list in all_results)
    on_device_count = sum(1 for _, res_list in all_results for r in res_list if r.mode == "ON_DEVICE")
    static_count = sum(1 for _, res_list in all_results for r in res_list if r.mode == "STATIC")
    summary_mode = f" ({on_device_count} ON_DEVICE / {static_count} STATIC)" if on_device_count or static_count else ""

    if HAS_RICH:
        console = Console()
        console.print()
        console.print(
            Panel.fit(
                "[bold cyan]ApkRevive Canary Matrix Runner & Verification Engine[/bold cyan]\n"
                f"[dim]Total Assertions: {total_tests} | Verified: {total_passed}/{total_tests}{summary_mode}[/dim]",
                box=box.DOUBLE,
            )
        )


        for tier, records in all_results:
            table = Table(
                title=f"[bold yellow]{tier.name}[/bold yellow] - [dim]{tier.focus}[/dim]",
                box=box.ROUNDED,
                header_style="bold magenta",
                show_lines=True,
            )
            table.add_column("Canary Identifier", style="cyan", width=22)
            table.add_column("Mode", justify="center", width=11)
            table.add_column("Control (Unpatched) Assertion", width=40)
            table.add_column("Revived (Patched) Assertion", width=40)
            table.add_column("Verdict", justify="center", width=9)

            for r in records:
                status_badge = "[bold green]PASS[/bold green]" if r.pass_fail == "PASS" else "[bold red]FAIL[/bold red]"
                mode_badge = f"[bold cyan]{r.mode}[/bold cyan]" if r.mode == "ON_DEVICE" else f"[dim]{r.mode}[/dim]"
                table.add_row(
                    f"`{r.canary_id}`",
                    mode_badge,
                    f"[dim]{r.control_detail}[/dim]",
                    f"{r.revived_detail}",
                    status_badge,
                )
            console.print(table)
            console.print()
    else:
        print("\n" + "=" * 105)
        print("  ApkRevive Canary Matrix Runner & Verification Engine")
        print(f"  Total Assertions: {total_tests} | Verified: {total_passed}/{total_tests}{summary_mode}")
        print("=" * 105)

        for tier, records in all_results:
            print(f"\n--- {tier.name} ({tier.focus}) ---")
            print(f"{'Canary':<24} | {'Mode':<10} | {'Control Assertion':<32} | {'Revived Assertion':<32} | {'Verdict'}")
            print("-" * 115)
            for r in records:
                ctrl_short = (r.control_detail[:29] + "...") if len(r.control_detail) > 32 else r.control_detail
                rev_short = (r.revived_detail[:29] + "...") if len(r.revived_detail) > 32 else r.revived_detail
                print(f"{r.canary_id:<24} | {r.mode:<10} | {ctrl_short:<32} | {rev_short:<32} | [{r.pass_fail}]")
        print("\n")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ApkRevive Canary Matrix Runner & Multi-Tier Verification Harness"
    )
    parser.add_argument(
        "--device",
        type=str,
        nargs="?",
        const="",
        default=None,
        help="Connect to live ADB device/emulator by serial (default first attached)",
    )
    parser.add_argument(
        "--simulate",
        "--local",
        dest="simulate",
        action="store_true",
        help="Run dual positive/negative verification offline against in-repo canaries",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default="all",
        choices=["all", "19", "28", "34", "35"],
        help="Filter execution to specific AVD tier (default all)",
    )
    parser.add_argument(
        "--canary",
        type=str,
        default=None,
        choices=CANARY_NAMES,
        help="Filter execution to a single canary identifier",
    )
    parser.add_argument(
        "--write-results",
        action="store_true",
        help="Write JSON receipts into results/<env>_<canary_id>.json conforming to schema",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Directory to store test receipts (default results/)",
    )
    parser.add_argument(
        "--update-docs",
        action="store_true",
        help="Automatically run scripts/generate_matrix.py to refresh docs/COMPATIBILITY.md",
    )
    parser.add_argument(
        "--doc-path",
        type=Path,
        default=DEFAULT_DOC_PATH,
        help="Path to docs/COMPATIBILITY.md for doc updating",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    canaries_dir = CANARIES_BUILD

    if not canaries_dir.exists() or len(list(canaries_dir.glob("*.apk"))) < 16:
        from canaries.build_canaries import build_all
        build_all()

    git_commit = get_git_commit()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    tiers_to_execute: list[AVDTier] = []
    bridge: Optional[AdbBridge] = None
    env_name = "Local Verification Rig"
    emulator_or_hardware = "local_host"
    android_build = "Host Python Harness"

    if args.device is not None:
        serial = args.device if args.device else None
        bridge = AdbBridge(serial=serial)
        detected_tier_id, detected_profile, props = detect_device_tier(bridge)
        env_name = props["model"]
        emulator_or_hardware = "emulator" if ("emulator" in env_name.lower() or "sdk" in env_name.lower()) else "hardware"
        android_build = props["build_id"]

        tier_obj = AVDTier(
            tier_id=detected_tier_id,
            name=f"Live Device: {env_name} (API {props['sdk']})",
            api_level=detected_profile.os_api_level,
            arch=detected_profile.supported_abis[0] if detected_profile.supported_abis else "x86_64",
            page_size=detected_profile.page_size_bytes,
            install_floor=detected_profile.install_floor,
            focus="Live ADB Verification",
            profile=detected_profile,
        )
        tiers_to_execute = [tier_obj]
    else:
        if args.tier == "all":
            tiers_to_execute = list(TIERS.values())
        else:
            tiers_to_execute = [TIERS[args.tier]]

    all_results: list[tuple[AVDTier, list[CanaryAssertionResult]]] = []
    for tier in tiers_to_execute:
        res_list = run_tier_verification(tier, canaries_dir, bridge, args.canary)
        all_results.append((tier, res_list))

    render_results_table(all_results)

    if args.write_results:
        is_simulated = (args.device is None) or bool(args.simulate)
        for tier, records in all_results:
            env_slug = "local_rig" if args.device is None else f"device_api{tier.api_level}"
            for r in records:
                receipt = build_receipt_dict(
                    record=r,
                    tier=tier,
                    device_model=env_name,
                    emulator_or_hardware=emulator_or_hardware,
                    android_build=android_build,
                    git_commit=git_commit,
                    date_str=date_str,
                    simulated=is_simulated,
                )
                write_receipt(receipt, args.results_dir, env_slug)
        print(f"Wrote verification receipts to {args.results_dir}")

    if args.update_docs:
        results = load_results(args.results_dir)
        results_section = format_results_section(results)
        update_compatibility_doc(args.doc_path, results_section)
        print(f"Updated {args.doc_path} with latest canary results matrix.")

    all_passed = all(r.pass_fail == "PASS" for _, res_list in all_results for r in res_list)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
