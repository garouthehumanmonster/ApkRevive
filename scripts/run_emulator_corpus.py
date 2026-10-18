#!/usr/bin/env python3
"""
scripts/run_emulator_corpus.py - Run revived corpus APKs on an attached emulator/device.

Verifies install, launch, 8-second liveness check, and crash logcat.
Takes ADB path from ANDROID_HOME / ANDROID_SDK_ROOT / PATH / LOCALAPPDATA.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.adb.bridge import find_adb


def get_attached_device(adb: str, serial: Optional[str] = None) -> Optional[str]:
    cmd = [adb, "devices"]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
    devices = []
    for line in lines[1:]:
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
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return res.stdout.strip()

    model = run_prop("ro.product.model") or run_prop("ro.product.name")
    sdk = run_prop("ro.build.version.sdk")
    release = run_prop("ro.build.version.release")
    build_id = run_prop("ro.build.id")
    abi = run_prop("ro.product.cpu.abi")
    page_size_cmd = prefix + ["shell", "getconf", "PAGE_SIZE"]
    p_res = subprocess.run(page_size_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    page_size = p_res.stdout.strip() or "4096"

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


def run_corpus_on_device(
    adb_path: Optional[str] = None,
    device_serial: Optional[str] = None,
    bump_target_sdk: Optional[int] = 24,
    use_bypass: bool = False,
    extra_flags: Optional[List[str]] = None,
    filter_pkg: Optional[str] = None,
    manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    adb = adb_path or find_adb()
    if not shutil.which(adb) and not Path(adb).exists():
        raise FileNotFoundError(f"ADB not found at '{adb}'")

    serial = get_attached_device(adb, device_serial)
    if not serial:
        raise RuntimeError("No attached Android device or emulator detected.")

    dev_info = get_device_info(adb, serial)
    print("=" * 80)
    print(f"DEVICE: {dev_info['model']} | API {dev_info['sdk']} (Android {dev_info['release']})")
    print(f"ABI: {dev_info['abi']} | PAGE_SIZE: {dev_info['page_size']} bytes | SERIAL: {serial}")
    print("=" * 80)

    adb_prefix = [adb, "-s", serial]

    manifest_file = manifest_path or (REPO_ROOT / "tests" / "corpus" / "corpus.json")
    with open(manifest_file, "r", encoding="utf-8") as f:
        raw_corpus = json.load(f)
    corpus = raw_corpus.get("packages", raw_corpus) if isinstance(raw_corpus, dict) else raw_corpus

    apks_dir = REPO_ROOT / "tests" / "corpus" / "apks"
    out_dir = REPO_ROOT / "tests" / "corpus" / "emulator_test"
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []

    for entry in corpus:
        pkg = entry.get("package") or entry.get("package_name")
        filename = entry.get("filename") or entry.get("apk_name")
        if not pkg or not filename:
            continue
        if filter_pkg and filter_pkg != pkg:
            continue

        apk_path = apks_dir / filename
        if not apk_path.exists():
            print(f"[SKIP] APK not found: {apk_path}")
            continue

        print("\n" + "-" * 70)
        print(f"PACKAGE: {pkg} ({filename}) - targetSdk: {entry.get('target_sdk')}")
        print("-" * 70)

        revived_apk = out_dir / f"revived_{filename}"
        if revived_apk.exists():
            try:
                revived_apk.unlink()
            except OSError:
                pass

        # Step 1: Revive
        revive_cmd = [
            sys.executable,
            "-m",
            "apkrevive.cli",
            "revive",
            str(apk_path),
            "--output",
            str(revived_apk),
        ]
        if bump_target_sdk is not None:
            revive_cmd.extend(["--bump-target-sdk", str(bump_target_sdk)])
        if extra_flags:
            revive_cmd.extend(extra_flags)

        print(f"[1] Reviving: {' '.join(revive_cmd)}")
        rev_res = run_command(revive_cmd, timeout=120)
        output_apk_exists = revived_apk.exists()
        if rev_res["exit_code"] == 1:
            triage_verdict = "RED"
            revive_status = "FAIL (RED)"
        elif rev_res["exit_code"] == 2:
            triage_verdict = "YELLOW"
            revive_status = "WARN (YELLOW)"
        else:
            triage_verdict = "GREEN"
            revive_status = "PASS"

        if not output_apk_exists:
            print(f"    Revive did not produce output APK (exit {rev_res['exit_code']}, verdict {triage_verdict}): {rev_res['stderr'] or rev_res['stdout']}")
            results.append({
                "package": pkg,
                "filename": filename,
                "target_sdk": entry.get("target_sdk"),
                "revive_cmd": " ".join(revive_cmd),
                "revive_status": revive_status,
                "triage_verdict": triage_verdict,
                "revive_exit_code": rev_res["exit_code"],
                "output_apk_exists": False,
                "revive_output": rev_res["stdout"] + "\n" + rev_res["stderr"],
                "install_status": "SKIPPED",
                "launch_status": "SKIPPED",
                "liveness_status": "SKIPPED",
            })
            continue
        print(f"    Revived successfully -> {revived_apk.name} (verdict {triage_verdict}, exit {rev_res['exit_code']})")

        # Step 2: Clear crash logcat and uninstall any existing test build
        run_command(adb_prefix + ["logcat", "-c", "-b", "crash"])
        run_command(adb_prefix + ["uninstall", pkg])

        # Step 3: Install
        install_args = adb_prefix + ["install", "-r"]
        if use_bypass:
            install_args.append("--bypass-low-target-sdk-block")
        install_args.append(str(revived_apk))

        install_cmd_str = " ".join(install_args)
        print(f"[2] Install command: {install_cmd_str}")
        inst_res = run_command(install_args, timeout=90)
        install_success = (inst_res["exit_code"] == 0) and ("Success" in inst_res["stdout"])
        print(f"    Install exit {inst_res['exit_code']} | Result: {'PASS' if install_success else 'FAIL'}")
        if inst_res["stdout"]:
            print(f"    stdout: {inst_res['stdout']}")
        if inst_res["stderr"]:
            print(f"    stderr: {inst_res['stderr']}")

        if not install_success:
            results.append({
                "package": pkg,
                "filename": filename,
                "target_sdk": entry.get("target_sdk"),
                "revive_cmd": " ".join(revive_cmd),
                "revive_status": revive_status,
                "triage_verdict": triage_verdict,
                "revive_exit_code": rev_res["exit_code"],
                "output_apk_exists": output_apk_exists,
                "install_cmd": install_cmd_str,
                "install_status": "FAIL",
                "install_exit_code": inst_res["exit_code"],
                "install_stdout": inst_res["stdout"],
                "install_stderr": inst_res["stderr"],
                "launch_status": "SKIPPED",
                "liveness_status": "SKIPPED",
            })
            continue

        # Step 4: Launch via monkey
        launch_cmd = adb_prefix + [
            "shell",
            "monkey",
            "-p",
            pkg,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]
        launch_cmd_str = " ".join(launch_cmd)
        print(f"[3] Launch command: {launch_cmd_str}")
        launch_res = run_command(launch_cmd, timeout=30)
        launch_ok = (launch_res["exit_code"] == 0) and ("Events injected: 1" in launch_res["stdout"])
        print(f"    Launch exit {launch_res['exit_code']} | Result: {'PASS' if launch_ok else 'WARN/FAIL'}")

        # Step 5: Liveness check: sleep 8s, check pidof and top resumed activity
        print("[4] Liveness check: sleeping 8s...")
        time.sleep(8)

        pid_res = run_command(adb_prefix + ["shell", "pidof", pkg], timeout=10)
        pid = pid_res["stdout"].strip()
        is_alive = bool(pid)

        dumpsys_res = run_command(
            adb_prefix + ["shell", "dumpsys", "activity", "activities"],
            timeout=15,
        )
        resumed_match = ""
        for line in dumpsys_res["stdout"].splitlines():
            stripped = line.strip()
            if any(k in stripped for k in ("topResumedActivity=", "mResumedActivity:", "ResumedActivity:")):
                resumed_match = stripped
                break
        is_top = bool(resumed_match and pkg in resumed_match)
        print(f"    Liveness pid: '{pid}' (alive={is_alive}) | Top Activity: '{resumed_match}' (is_top={is_top})")

        # Capture screenshot to docs/device_runs/<pkg>.png
        screenshots_dir = REPO_ROOT / "docs" / "device_runs"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshots_dir / f"{pkg}.png"
        try:
            with open(screenshot_path, "wb") as f_img:
                subprocess.run(adb_prefix + ["exec-out", "screencap", "-p"], stdout=f_img, timeout=15)
            print(f"    Screenshot saved -> docs/device_runs/{pkg}.png")
        except Exception as e:
            print(f"    Screenshot capture failed: {e}")

        # Step 6: Crash check
        crash_res = run_command(adb_prefix + ["logcat", "-d", "-b", "crash"], timeout=10)
        crash_log = crash_res["stdout"].strip()
        has_crash = bool(crash_log)
        if has_crash:
            print(f"    CRASH DETECTED:\n{crash_log}")
        else:
            print("    No crashes recorded in crash buffer.")

        results.append({
            "package": pkg,
            "filename": filename,
            "target_sdk": entry.get("target_sdk"),
            "revive_cmd": " ".join(revive_cmd),
            "revive_status": revive_status,
            "triage_verdict": triage_verdict,
            "revive_exit_code": rev_res["exit_code"],
            "output_apk_exists": output_apk_exists,
            "install_cmd": install_cmd_str,
            "install_status": "PASS" if install_success else "FAIL",
            "install_exit_code": inst_res["exit_code"],
            "install_stdout": inst_res["stdout"],
            "install_stderr": inst_res["stderr"],
            "launch_cmd": launch_cmd_str,
            "launch_status": "PASS" if launch_ok else "FAIL",
            "launch_stdout": launch_res["stdout"],
            "liveness_status": "PASS" if is_alive else "DEAD",
            "pid": pid,
            "resumed_activity": resumed_match,
            "top_activity": is_top,
            "crash_detected": has_crash,
            "crash_log": crash_log,
        })

    report = {
        "device_info": dev_info,
        "date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "results": results,
    }

    report_path = out_dir / "corpus_emulator_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 80)
    print(f"COMPLETED CORPUS RUN. Report saved to: {report_path}")
    print("=" * 80)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run revived corpus APKs on an Android emulator or device.")
    parser.add_argument("--adb", help="Explicit path to adb binary.")
    parser.add_argument("--device", "-s", help="Specific device serial.")
    parser.add_argument("--bump-target-sdk", type=int, default=24, help="Target SDK to bump to (default: 24). Set -1 for none.")
    parser.add_argument("--bypass", action="store_true", help="Pass --bypass-low-target-sdk-block to adb install.")
    parser.add_argument("--flags", default="", help="Extra flags string to pass to apkrevive revive (e.g. '--enable-60hz --enable-cutout').")
    parser.add_argument("--package", help="Only run for a specific package.")
    parser.add_argument("--manifest", type=Path, help="Custom corpus manifest JSON path.")

    args = parser.parse_args()
    bump_sdk = None if args.bump_target_sdk == -1 else args.bump_target_sdk
    import shlex
    extra_flags = shlex.split(args.flags) if args.flags else None

    try:
        run_corpus_on_device(
            adb_path=args.adb,
            device_serial=args.device,
            bump_target_sdk=bump_sdk,
            use_bypass=args.bypass,
            extra_flags=extra_flags,
            filter_pkg=args.package,
            manifest_path=args.manifest,
        )
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
