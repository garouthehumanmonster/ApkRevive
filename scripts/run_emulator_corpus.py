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
    devices = []
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


def poll_liveness_and_activity(
    adb_prefix: List[str],
    pkg: str,
    max_wait_seconds: float = 6.0,
    interval: float = 1.0,
) -> tuple[bool, str, str, bool, bool]:
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

        dumpsys_res = run_command(adb_prefix + ["shell", "dumpsys", "activity", "activities"], timeout=10)
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

    # Ensure PID is resolved if app reached foreground or permission interception
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


def run_corpus_on_device(
    adb_path: Optional[str] = None,
    device_serial: Optional[str] = None,
    bump_target_sdk: Optional[int] = 24,
    use_bypass: bool = False,
    grant_permissions: bool = False,
    extra_flags: Optional[List[str]] = None,
    filter_pkg: Optional[str] = None,
    manifest_path: Optional[Path] = None,
    update_docs: bool = False,
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
        revive_cmd.extend([
            "--device-api", str(dev_info["sdk"]),
            "--page-size", str(dev_info["page_size"]),
        ])
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
                "notes": None,
                "second_pass_status": None,
                "second_pass_pid": None,
                "second_pass_top_activity": None,
            })
            continue
        print(f"    Revived successfully -> {revived_apk.name} (verdict {triage_verdict}, exit {rev_res['exit_code']})")

        # Step 2: Clear crash logcat and uninstall any existing test build
        run_command(adb_prefix + ["logcat", "-c", "-b", "crash"])
        run_command(adb_prefix + ["uninstall", pkg])

        # Step 3: Install
        install_args = adb_prefix + ["install", "-r"]
        if grant_permissions:
            install_args.append("-g")
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
                "notes": None,
                "second_pass_status": None,
                "second_pass_pid": None,
                "second_pass_top_activity": None,
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

        # Step 5: Liveness check: poll up to 8s for pid and top resumed activity/window
        print("[4] Liveness check: polling up to 8s for liveness & top activity...")
        is_alive, pid, resumed_match, is_top, is_perm_blocked = poll_liveness_and_activity(
            adb_prefix, pkg, max_wait_seconds=8.0, interval=1.0
        )
        print(f"    Liveness pid: '{pid}' (alive={is_alive}) | Top Activity: '{resumed_match}' (is_top={is_top})")

        # Capture screenshot to build/device_runs/<pkg>.png by default
        screenshots_dir = REPO_ROOT / "build" / "device_runs"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshots_dir / f"{pkg}.png"
        screenshot_record = f"build/device_runs/{pkg}.png"
        try:
            with open(screenshot_path, "wb") as f_img:
                subprocess.run(adb_prefix + ["exec-out", "screencap", "-p"], stdout=f_img, timeout=15)
            print(f"    Screenshot saved -> build/device_runs/{pkg}.png")
            if update_docs:
                docs_dir = REPO_ROOT / "docs" / "device_runs"
                docs_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(screenshot_path, docs_dir / f"{pkg}.png")
                print(f"    Screenshot copied -> docs/device_runs/{pkg}.png")
        except Exception as e:
            print(f"    Screenshot capture failed: {e}")

        # Step 6: Crash check for Pass 1
        crash_res = run_command(adb_prefix + ["logcat", "-d", "-b", "crash"], timeout=10)
        crash_log = crash_res["stdout"].strip()
        has_crash = False
        if crash_log:
            pkg_match = pkg in crash_log
            pid_match = bool(pid and ((f"pid {pid}" in crash_log) or (f"{pid}:" in crash_log) or (f"PID: {pid}" in crash_log)))
            if pkg_match or pid_match:
                has_crash = True
                print(f"    CRASH DETECTED:\n{crash_log}")
            else:
                print(f"    Crash buffer non-empty, but crash log is from an unrelated system process (neither '{pkg}' nor PID matched). Ignoring.")
                crash_log = ""
        else:
            print("    No crashes recorded in crash buffer.")

        if is_alive and not has_crash:
            liveness_status = "ALIVE"
        elif has_crash:
            liveness_status = "CRASH"
        else:
            liveness_status = "DEAD"

        notes = {
            "top_window": resumed_match,
            "is_top": is_top,
            "is_perm_blocked": is_perm_blocked,
            "screenshot": screenshot_record,
        }

        # Step 7: Pass 2 (-g)
        # Always execute pass-2 with -g when install succeeded
        print("    Executing Pass 2 (-g: auto-grant runtime permissions)...")
        run_command(adb_prefix + ["uninstall", pkg])

        second_install_args = adb_prefix + ["install", "-r", "-g"]
        if use_bypass:
            second_install_args.append("--bypass-low-target-sdk-block")
        second_install_args.append(str(revived_apk))
        second_inst_res = run_command(second_install_args, timeout=90)
        second_inst_success = (second_inst_res["exit_code"] == 0) and ("Success" in second_inst_res["stdout"])
        print(f"    Second pass install exit {second_inst_res['exit_code']} | Result: {'PASS' if second_inst_success else 'FAIL'}")

        if second_inst_success:
            second_launch_res = run_command(launch_cmd, timeout=30)
            second_launch_ok = (second_launch_res["exit_code"] == 0) and ("Events injected: 1" in second_launch_res["stdout"])
            print(f"    Second pass launch exit {second_launch_res['exit_code']} | Result: {'PASS' if second_launch_ok else 'WARN/FAIL'}")

            s_alive, s_pid, s_resumed, s_is_top, _ = poll_liveness_and_activity(
                adb_prefix, pkg, max_wait_seconds=8.0, interval=1.0
            )
            second_pass_status = "PASS" if (s_alive and s_is_top) else ("ALIVE" if s_alive else "DEAD")
            second_pass_pid = s_pid
            second_pass_top_activity = s_resumed
            print(f"    Second pass finished with status '{second_pass_status}' (pid: '{s_pid}', top: '{s_resumed}', is_top={s_is_top})")
        else:
            second_pass_status = "INSTALL_FAIL"
            second_pass_pid = None
            second_pass_top_activity = None

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
            "liveness_status": liveness_status,
            "pid": pid,
            "resumed_activity": resumed_match,
            "top_activity": is_top,
            "notes": notes,
            "second_pass_status": second_pass_status,
            "second_pass_pid": second_pass_pid,
            "second_pass_top_activity": second_pass_top_activity,
            "crash_detected": has_crash,
            "crash_log": crash_log,
        })

        # Step 7: Post-test cleanup: uninstall package
        run_command(adb_prefix + ["uninstall", pkg])

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
    parser.add_argument(
        "--grant-permissions",
        "-g",
        action="store_true",
        help="Pass -g to adb install on first pass to automatically grant runtime permissions.",
    )
    parser.add_argument("--flags", default="", help="Extra flags string to pass to apkrevive revive (e.g. '--enable-60hz --enable-cutout').")
    parser.add_argument("--package", help="Only run for a specific package.")
    parser.add_argument("--manifest", type=Path, help="Custom corpus manifest JSON path.")
    parser.add_argument("--update-docs", action="store_true", help="Copy runner screenshots to docs/device_runs/.")

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
            grant_permissions=args.grant_permissions,
            extra_flags=extra_flags,
            filter_pkg=args.package,
            manifest_path=args.manifest,
            update_docs=args.update_docs,
        )
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
