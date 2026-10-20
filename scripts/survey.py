#!/usr/bin/env python3
"""
scripts/survey.py - Compatibility Survey Runner across Android versions.

Runs real legacy APKs from survey manifest against an attached Android emulator/device:
1. Direct install (adb install -r)
2. Bypass install (adb install -r --bypass-low-target-sdk-block)
3. Revive then install with -g
4. Liveness check & screenshot
5. Systematic failure classification into standardized categories.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.adb.bridge import find_adb
from scripts.make_receipt import create_receipt

FAILURE_CATEGORIES = (
    "ABI",
    "GREYLIST",
    "GLES1",
    "DEAD_SDK",
    "CRASH",
    "INSTALL_FLOOR_BLOCKED",
    "NONE",
    "OTHER",
)


def classify_failure(
    text: str = "",
    *,
    is_alive: bool = False,
    has_crash: bool = False,
    is_success: bool = False,
) -> str:
    """
    Classifies install, revive, or runtime failure into standard survey categories:
    - 'ABI': INSTALL_FAILED_NO_MATCHING_ABIS or 32-bit native on 64-bit device
    - 'GREYLIST': bionic namespace restriction, private platform lib dlopen failure
    - 'GLES1': legacy OpenGL ES 1.x deprecation/crash
    - 'DEAD_SDK': crash on sunset/dead SDKs (com.google.android.maps, old billing, etc.)
    - 'CRASH': runtime exception/SIGSEGV in filtered crash buffer
    - 'INSTALL_FLOOR_BLOCKED': INSTALL_FAILED_DEPRECATED_SDK_VERSION
    - 'NONE': alive and running with no crash
    - 'OTHER': other failure
    """
    s = text or ""

    # 1. Install floor blocked
    if (
        "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in s
        or "DEPRECATED_SDK_VERSION" in s
        or "lower than the minimum allowed version" in s
        or "TARGET_SDK_INSTALL_FLOOR" in s
    ):
        return "INSTALL_FLOOR_BLOCKED"

    # 2. ABI incompatibility
    if (
        "INSTALL_FAILED_NO_MATCHING_ABIS" in s
        or "INSTALL_FAILED_CPU_ABI_INCOMPATIBLE" in s
        or "NO_MATCHING_ABIS" in s
        or "32-bit native on 64-bit" in s
        or "32-bit instead of 64-bit" in s
        or "unsupported ELF class: 1" in s
        or "32-bit ABI not supported" in s
        or "INCOMPATIBLE_DEVICE_ABI" in s
        or "WARN_32BIT_ONLY_ON_64BIT" in s
    ):
        return "ABI"

    # 3. Bionic Greylist / private platform libraries
    if (
        "bionic namespace" in s
        or "namespace restriction" in s
        or "is not accessible for the namespace" in s
        or "libandroid_runtime.so" in s
        or "libjavacore.so" in s
        or "libnativehelper.so" in s
        or "libmedia.so" in s
        or "libart.so" in s
        or "UNRESOLVABLE_SYSTEM_LIBRARY" in s
        or "BIONIC_GREYLIST" in s
    ):
        return "GREYLIST"

    # 4. Legacy GLES 1.x
    if (
        "libGLESv1_CM.so" in s
        or "libGLESv1" in s
        or "GLES1" in s
        or "GLESv1" in s
        or "OpenGL ES 1" in s
        or "context creation fail" in s
        or "eglCreateContext failed" in s
        or "WARN_GLES1_DEPRECATED" in s
    ):
        return "GLES1"

    # 5. Dead / Sunset SDKs
    if (
        "com.google.android.maps" in s
        or "com/google/android/maps" in s
        or "IInAppBillingService" in s
        or "com.android.vending.billing" in s
        or "com/android/vending/billing" in s
        or "WARN_DEAD_SDKS" in s
        or "dead sdk" in s.lower()
        or "sunset sdk" in s.lower()
        or "org.apache.http" in s
        or "org/apache/http" in s
    ):
        return "DEAD_SDK"

    # 6. Runtime Crash
    if (
        has_crash
        or "FATAL EXCEPTION" in s
        or "AndroidRuntime: FATAL" in s
        or "SIGSEGV" in s
        or "SIGBUS" in s
        or "SIGABRT" in s
        or "signal 11" in s
        or "signal 6" in s
        or "backtrace:" in s
        or "Process crashed" in s
    ):
        return "CRASH"

    # 7. Clean run
    if is_alive and not has_crash:
        return "NONE"
    if is_success and not s:
        return "NONE"
    if "Success" in s and not has_crash:
        return "NONE"

    # 8. Unclassified failure
    return "OTHER"


def load_manifest(manifest_path: Union[str, Path]) -> List[Dict[str, Any]]:
    path = Path(manifest_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        packages = data.get("packages") or data.get("apks") or []
    elif isinstance(data, list):
        packages = data
    else:
        raise ValueError("Invalid survey manifest structure")
    return packages


def get_attached_device(adb: str, serial: Optional[str] = None) -> Optional[str]:
    wait_cmd = [adb]
    if serial:
        wait_cmd.extend(["-s", serial])
    wait_cmd.append("wait-for-device")
    try:
        subprocess.run(wait_cmd, capture_output=True, timeout=15)
    except Exception:
        pass

    cmd = [adb, "devices"]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    devices: List[str] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    if not devices:
        return None
    if serial:
        return serial if serial in devices else None
    return devices[0]


def get_device_info(adb: str, serial: Optional[str] = None) -> Dict[str, str]:
    prefix = [adb]
    if serial:
        prefix.extend(["-s", serial])

    def run_prop(prop: str) -> str:
        cmd = prefix + ["shell", "getprop", prop]
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
            )
            return res.stdout.strip()
        except Exception:
            return ""

    model = run_prop("ro.product.model") or run_prop("ro.product.name") or "unknown_model"
    sdk = run_prop("ro.build.version.sdk") or "0"
    release = run_prop("ro.build.version.release") or "unknown"
    build_id = run_prop("ro.build.id") or "unknown"
    abi = run_prop("ro.product.cpu.abi") or "unknown"

    page_size = "4096"
    try:
        p_res = subprocess.run(
            prefix + ["shell", "getconf", "PAGE_SIZE"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        p_out = p_res.stdout.strip()
        if p_out.isdigit():
            page_size = p_out
    except Exception:
        pass

    return {
        "model": model,
        "sdk": sdk,
        "release": release,
        "build_id": build_id,
        "abi": abi,
        "page_size": page_size,
    }


def run_command(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return {
            "exit_code": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "exit_code": -1,
            "stdout": (e.stdout or "").strip() if isinstance(e.stdout, str) else "",
            "stderr": (e.stderr or "").strip() if isinstance(e.stderr, str) else "",
            "timed_out": True,
        }


def poll_liveness_and_activity(
    adb_prefix: List[str],
    pkg: str,
    max_wait_seconds: float = 8.0,
    interval: float = 1.0,
) -> Tuple[bool, str, str, bool, bool]:
    perm_indicators = ("GrantPermissionsActivity", "ReviewPermissionsActivity", "permissioncontroller")
    deadline = time.time() + max_wait_seconds
    pid = ""
    is_alive = False
    last_resumed = ""
    is_top = False
    is_perm_blocked = False

    while time.time() < deadline:
        time.sleep(interval)
        if not is_alive:
            pid_res = run_command(adb_prefix + ["shell", "pidof", pkg], timeout=5)
            cand_pid = pid_res["stdout"].strip()
            if cand_pid:
                pid = cand_pid
                is_alive = True

        dumpsys_res = run_command(
            adb_prefix + ["shell", "dumpsys", "activity", "activities"], timeout=10
        )
        resumed_match = ""
        for line in dumpsys_res["stdout"].splitlines():
            stripped = line.strip()
            if any(k in stripped for k in ("topResumedActivity=", "mResumedActivity:", "ResumedActivity:")):
                resumed_match = stripped
                break

        if not resumed_match:
            win_res = run_command(adb_prefix + ["shell", "dumpsys", "window", "displays"], timeout=10)
            for line in win_res["stdout"].splitlines():
                stripped = line.strip()
                if "mCurrentFocus=" in stripped or "mFocusedApp=" in stripped:
                    resumed_match = stripped
                    break

        if resumed_match:
            last_resumed = resumed_match
            if any(ind in resumed_match for ind in perm_indicators):
                is_perm_blocked = True
                is_top = False
                break
            if pkg in resumed_match:
                is_top = True

    # Fallback ps check if alive was not confirmed by pidof
    if (is_top or is_perm_blocked) and not is_alive:
        pid_res = run_command(adb_prefix + ["shell", "pidof", pkg], timeout=5)
        cand_pid = pid_res["stdout"].strip()
        if cand_pid:
            pid = cand_pid
            is_alive = True
        else:
            ps_res = run_command(adb_prefix + ["shell", "ps", "-A"], timeout=5)
            for line in ps_res["stdout"].splitlines():
                if pkg in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        pid = parts[1]
                        is_alive = True
                        break

    return is_alive, pid, last_resumed, is_top, is_perm_blocked


def run_apk_survey(
    entry: Dict[str, Any],
    adb: str,
    serial: str,
    dev_info: Dict[str, str],
    manifest_dir: Path,
    screenshots_dir: Path,
    temp_out_dir: Path,
    bump_target_sdk: int = 24,
    extra_flags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    adb_prefix = [adb, "-s", serial]
    pkg = entry.get("package_name") or entry.get("package") or entry.get("id") or "unknown.pkg"
    apk_name = entry.get("apk_name") or entry.get("filename") or f"{pkg}.apk"

    # Search for APK candidate path
    candidate_paths = [
        manifest_dir / "apks" / apk_name,
        manifest_dir / apk_name,
        REPO_ROOT / "tests" / "corpus" / "apks" / apk_name,
        REPO_ROOT / "canaries" / "build" / apk_name,
    ]
    apk_path: Optional[Path] = None
    for p in candidate_paths:
        if p.exists():
            apk_path = p
            break

    target_sdk = entry.get("target_sdk", 0)
    dev_sdk = int(dev_info.get("sdk", 0))

    temp_out_dir.mkdir(parents=True, exist_ok=True)
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    if not apk_path:
        return {
            "package_name": pkg,
            "apk_name": apk_name,
            "target_sdk": target_sdk,
            "abis": entry.get("abis", []),
            "status": "SKIPPED_MISSING_APK",
            "overall_failure_category": "OTHER",
        }

    # Step 1: Direct Install
    run_command(adb_prefix + ["uninstall", pkg])
    direct_cmd = adb_prefix + ["install", "-r", str(apk_path)]
    direct_res = run_command(direct_cmd, timeout=90)
    direct_output = (direct_res["stdout"] + "\n" + direct_res["stderr"]).strip()
    direct_success = (direct_res["exit_code"] == 0) and ("Success" in direct_res["stdout"])
    direct_failure_category = classify_failure(direct_output, is_success=direct_success)
    run_command(adb_prefix + ["uninstall", pkg])

    # Step 2: Bypass Install
    bypass_cmd = adb_prefix + ["install", "-r", "--bypass-low-target-sdk-block", str(apk_path)]
    bypass_res = run_command(bypass_cmd, timeout=90)
    bypass_output = (bypass_res["stdout"] + "\n" + bypass_res["stderr"]).strip()
    bypass_success = (bypass_res["exit_code"] == 0) and ("Success" in bypass_res["stdout"])
    bypass_failure_category = classify_failure(bypass_output, is_success=bypass_success)
    run_command(adb_prefix + ["uninstall", pkg])

    # Step 3: Revive then install with -g
    revived_apk = temp_out_dir / f"revived_{apk_name}"
    if revived_apk.exists():
        try:
            revived_apk.unlink()
        except OSError:
            pass

    revive_cmd = [
        sys.executable,
        "-m",
        "apkrevive.cli",
        "revive",
        str(apk_path),
        "--output",
        str(revived_apk),
        "--json",
    ]
    if bump_target_sdk is not None:
        revive_cmd.extend(["--bump-target-sdk", str(bump_target_sdk)])
    if dev_info.get("sdk"):
        revive_cmd.extend(["--device-api", str(dev_info["sdk"])])
    if dev_info.get("page_size"):
        revive_cmd.extend(["--page-size", str(dev_info["page_size"])])
    if extra_flags:
        revive_cmd.extend(extra_flags)

    rev_res = run_command(revive_cmd, timeout=120)
    rev_output = (rev_res["stdout"] + "\n" + rev_res["stderr"]).strip()
    output_apk_exists = revived_apk.exists()

    verdict = "UNKNOWN"
    required_transforms: List[str] = []
    try:
        start_idx = rev_res["stdout"].find("{")
        end_idx = rev_res["stdout"].rfind("}")
        if start_idx != -1 and end_idx != -1:
            parsed = json.loads(rev_res["stdout"][start_idx : end_idx + 1])
            verdict = parsed.get("verdict", "UNKNOWN")
            required_transforms = parsed.get("required_transforms", [])
    except Exception:
        if rev_res["exit_code"] == 0:
            verdict = "GREEN"
        elif rev_res["exit_code"] == 2:
            verdict = "YELLOW"
        elif rev_res["exit_code"] == 1:
            verdict = "RED"

    revive_success = output_apk_exists
    revive_failure_category = classify_failure(rev_output, is_success=revive_success)

    revive_install_success = False
    revive_install_output = ""
    revive_install_exit_code = -1
    revive_install_failure_category = revive_failure_category

    liveness_status = "SKIPPED"
    liveness_cat = revive_failure_category
    liveness_pid: Optional[str] = None
    liveness_top_activity: Optional[str] = None
    liveness_crash_log: Optional[str] = None
    screenshot_file: Optional[str] = None

    if revive_success:
        run_command(adb_prefix + ["logcat", "-c", "-b", "crash"])
        run_command(adb_prefix + ["uninstall", pkg])

        rev_install_cmd = adb_prefix + ["install", "-r", "-g"]
        # Add bypass flag if targetSdk was not bumped (or remains < 24 on API 34+)
        if (bump_target_sdk == -1 or (bump_target_sdk is not None and bump_target_sdk < 24) or target_sdk < 24) and dev_sdk >= 34:
            rev_install_cmd.append("--bypass-low-target-sdk-block")
        rev_install_cmd.append(str(revived_apk))

        rev_inst_res = run_command(rev_install_cmd, timeout=90)
        revive_install_exit_code = rev_inst_res["exit_code"]
        revive_install_output = (rev_inst_res["stdout"] + "\n" + rev_inst_res["stderr"]).strip()
        revive_install_success = (rev_inst_res["exit_code"] == 0) and ("Success" in rev_inst_res["stdout"])
        revive_install_failure_category = classify_failure(revive_install_output, is_success=revive_install_success)

        # Step 4: If revived install succeeded, launch & verify liveness
        if revive_install_success:
            launch_cmd = adb_prefix + [
                "shell",
                "monkey",
                "-p",
                pkg,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
            run_command(launch_cmd, timeout=30)

            is_alive, pid, top_act, is_top, _ = poll_liveness_and_activity(
                adb_prefix, pkg, max_wait_seconds=8.0, interval=1.0
            )
            liveness_pid = pid
            liveness_top_activity = top_act

            # Check crash buffer
            crash_res = run_command(adb_prefix + ["logcat", "-d", "-b", "crash"], timeout=10)
            crash_log = crash_res["stdout"].strip()
            has_crash = False
            if crash_log:
                pkg_match = pkg in crash_log
                pid_match = bool(
                    pid
                    and (
                        (f"pid {pid}" in crash_log)
                        or (f"{pid}:" in crash_log)
                        or (f"PID: {pid}" in crash_log)
                    )
                )
                if pkg_match or pid_match:
                    has_crash = True
                    liveness_crash_log = crash_log

            # Screenshot
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshots_dir / f"{pkg}.png"
            try:
                with open(screenshot_path, "wb") as f_img:
                    subprocess.run(
                        adb_prefix + ["exec-out", "screencap", "-p"],
                        stdout=f_img,
                        timeout=15,
                    )
                screenshot_file = str(screenshot_path)
            except Exception:
                screenshot_file = None

            # Uninstall
            run_command(adb_prefix + ["uninstall", pkg])

            if is_alive and not has_crash:
                liveness_status = "ALIVE"
                liveness_cat = "NONE"
            elif has_crash:
                liveness_status = "CRASH"
                liveness_cat = classify_failure(crash_log, has_crash=True)
            else:
                liveness_status = "DEAD"
                liveness_cat = classify_failure("process terminated without crash log", is_alive=False)

    # Step 5: Overall failure classification
    if liveness_status == "ALIVE":
        overall_failure_category = "NONE"
    elif liveness_status in ("CRASH", "DEAD"):
        overall_failure_category = liveness_cat
    elif not revive_install_success and revive_success:
        overall_failure_category = revive_install_failure_category
    elif not revive_success:
        overall_failure_category = revive_failure_category
    else:
        overall_failure_category = "OTHER"

    return {
        "package_name": pkg,
        "apk_name": apk_name,
        "target_sdk": target_sdk,
        "abis": entry.get("abis", []),
        "direct_install": {
            "exit_code": direct_res["exit_code"],
            "output": direct_output,
            "success": direct_success,
            "failure_category": direct_failure_category,
        },
        "bypass_install": {
            "exit_code": bypass_res["exit_code"],
            "output": bypass_output,
            "success": bypass_success,
            "failure_category": bypass_failure_category,
        },
        "revive": {
            "exit_code": rev_res["exit_code"],
            "verdict": verdict,
            "required_transforms": required_transforms,
            "output": rev_output,
            "success": revive_success,
            "failure_category": revive_failure_category,
        },
        "revive_install": {
            "exit_code": revive_install_exit_code,
            "output": revive_install_output,
            "success": revive_install_success,
            "failure_category": revive_install_failure_category,
        },
        "liveness": {
            "status": liveness_status,
            "pid": liveness_pid,
            "top_activity": liveness_top_activity,
            "crash_log": liveness_crash_log,
            "screenshot": screenshot_file,
            "failure_category": liveness_cat,
        },
        "overall_failure_category": overall_failure_category,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ApkRevive legacy compatibility survey across Android devices/emulators."
    )
    parser.add_argument("--adb", help="Explicit ADB path (fallback to find_adb())")
    parser.add_argument("--device", "-s", help="Device serial")
    parser.add_argument(
        "--manifest",
        default="tests/corpus/survey.json",
        help="Path to survey manifest JSON (default: tests/corpus/survey.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output results JSON path (default: results/survey/survey_<device_model>_api<sdk>_<abi>.json)",
    )
    parser.add_argument(
        "--receipt-dir",
        default="receipts",
        help="Receipts directory (default: receipts)",
    )
    parser.add_argument(
        "--screenshots-dir",
        help="Screenshots dir (default: build/survey_runs/<model>_api<sdk>)",
    )
    parser.add_argument(
        "--bump-target-sdk",
        type=int,
        default=24,
        help="Target SDK bump (default: 24, -1 to disable)",
    )
    parser.add_argument(
        "--flags",
        default=None,
        help="Extra flags for revive",
    )
    parser.add_argument(
        "--max-apks",
        type=int,
        default=None,
        help="Limit number of APKs processed",
    )
    parser.add_argument(
        "--package",
        help="Run only for a single package",
    )
    return parser


def parse_survey_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    normalized: List[str] = []
    i = 0
    known_flags = (
        "--adb",
        "--device",
        "-s",
        "--manifest",
        "--output",
        "-o",
        "--receipt-dir",
        "--screenshots-dir",
        "--bump-target-sdk",
        "--flags",
        "--max-apks",
        "--package",
    )
    while i < len(raw_args):
        if raw_args[i] == "--flags" and i + 1 < len(raw_args):
            flag_tokens: List[str] = [raw_args[i + 1]]
            i += 2
            while i < len(raw_args) and not any(
                raw_args[i] == f or raw_args[i].startswith(f + "=") for f in known_flags
            ):
                flag_tokens.append(raw_args[i])
                i += 1
            combined = " ".join(flag_tokens)
            normalized.append(f"--flags={combined}")
        else:
            normalized.append(raw_args[i])
            i += 1
    return parser.parse_args(normalized)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_survey_args(argv)

    adb = args.adb or find_adb()
    if not shutil.which(adb) and not Path(adb).exists():
        sys.stderr.write(f"ERROR: ADB not found at '{adb}'\n")
        return 1

    serial = get_attached_device(adb, args.device)
    if not serial:
        sys.stderr.write("ERROR: No attached Android device or emulator detected.\n")
        return 1

    dev_info = get_device_info(adb, serial)
    model = dev_info.get("model", "unknown")
    sdk = dev_info.get("sdk", "0")
    abi = dev_info.get("abi", "unknown")
    model_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", model).strip("_") or "device"

    # Default paths
    output_path = Path(args.output) if args.output else Path(f"results/survey/survey_{model_slug}_api{sdk}_{abi}.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    screenshots_dir = (
        Path(args.screenshots_dir)
        if args.screenshots_dir
        else Path(f"build/survey_runs/{model_slug}_api{sdk}")
    )
    receipt_dir = Path(args.receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    temp_out_dir = REPO_ROOT / "build" / "survey_temp"
    temp_out_dir.mkdir(parents=True, exist_ok=True)

    # Flatten flags
    extra_flags: List[str] = []
    if args.flags:
        for f in args.flags:
            extra_flags.extend(f.split())

    manifest_file = Path(args.manifest)
    packages = load_manifest(manifest_file)

    if args.package:
        packages = [
            p
            for p in packages
            if (p.get("package_name") == args.package or p.get("package") == args.package or p.get("id") == args.package)
        ]

    if args.max_apks is not None:
        packages = packages[: args.max_apks]

    print("=" * 80)
    print(f"SURVEY: {model} | API {sdk} | ABI {abi} | Device {serial}")
    print(f"PACKAGES: {len(packages)} | TARGET_SDK_BUMP: {args.bump_target_sdk}")
    print(f"OUTPUT: {output_path} | SCREENSHOTS: {screenshots_dir}")
    print("=" * 80)

    per_apk_records: List[Dict[str, Any]] = []

    for idx, entry in enumerate(packages, 1):
        pkg = entry.get("package_name") or entry.get("package") or entry.get("id")
        print(f"\n[{idx}/{len(packages)}] Processing {pkg}...")
        record = run_apk_survey(
            entry=entry,
            adb=adb,
            serial=serial,
            dev_info=dev_info,
            manifest_dir=manifest_file.parent,
            screenshots_dir=screenshots_dir,
            temp_out_dir=temp_out_dir,
            bump_target_sdk=args.bump_target_sdk,
            extra_flags=extra_flags,
        )
        per_apk_records.append(record)
        print(f"    Direct Install: {record.get('direct_install', {}).get('failure_category')}")
        print(f"    Bypass Install: {record.get('bypass_install', {}).get('failure_category')}")
        print(f"    Revive Verdict: {record.get('revive', {}).get('verdict')}")
        print(f"    Revive Install: {record.get('revive_install', {}).get('failure_category')}")
        print(f"    Liveness: {record.get('liveness', {}).get('status')}")
        print(f"    Overall Category: {record.get('overall_failure_category')}")

    total_apks = len(per_apk_records)
    direct_success = sum(1 for r in per_apk_records if r.get("direct_install", {}).get("success"))
    bypass_success = sum(1 for r in per_apk_records if r.get("bypass_install", {}).get("success"))
    revive_success = sum(1 for r in per_apk_records if r.get("revive", {}).get("success"))
    revive_install_success = sum(1 for r in per_apk_records if r.get("revive_install", {}).get("success"))

    alive_count = sum(1 for r in per_apk_records if r.get("liveness", {}).get("status") == "ALIVE")
    crash_count = sum(1 for r in per_apk_records if r.get("liveness", {}).get("status") == "CRASH")
    dead_count = sum(1 for r in per_apk_records if r.get("liveness", {}).get("status") == "DEAD")
    skipped_count = sum(1 for r in per_apk_records if r.get("liveness", {}).get("status") == "SKIPPED")

    failure_category_counts: Dict[str, int] = {cat: 0 for cat in FAILURE_CATEGORIES}
    for r in per_apk_records:
        cat = r.get("overall_failure_category", "OTHER")
        if cat in failure_category_counts:
            failure_category_counts[cat] += 1
        else:
            failure_category_counts["OTHER"] += 1

    # Emit structured receipt
    receipt = create_receipt(
        model=dev_info.get("model"),
        api=int(sdk) if sdk.isdigit() else 35,
        abi=dev_info.get("abi"),
        page_size=int(dev_info.get("page_size", "16384")) if dev_info.get("page_size", "").isdigit() else 16384,
        device=serial,
        script="scripts/survey.py",
        adb_path=adb,
    )
    receipt_path = receipt_dir / f"receipt_survey_{model_slug}_api{sdk}_{abi}.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"\n[+] Receipt written to {receipt_path}")

    # Build report
    report: Dict[str, Any] = {
        "device_info": dev_info,
        "total_apks": total_apks,
        "direct_install_stats": {
            "total": total_apks,
            "success": direct_success,
            "failed": total_apks - direct_success,
        },
        "bypass_install_stats": {
            "total": total_apks,
            "success": bypass_success,
            "failed": total_apks - bypass_success,
        },
        "revive_install_stats": {
            "total": total_apks,
            "revive_success": revive_success,
            "install_success": revive_install_success,
            "failed": total_apks - revive_install_success,
        },
        "liveness_stats": {
            "total": total_apks,
            "alive": alive_count,
            "crash": crash_count,
            "dead": dead_count,
            "skipped": skipped_count,
        },
        "failure_category_counts": failure_category_counts,
        "per_apk_records": per_apk_records,
        "results": per_apk_records,
        "receipt_file": str(receipt_path),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Survey results written to {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
