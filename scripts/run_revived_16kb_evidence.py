#!/usr/bin/env python3
"""
Run revived APK evidence experiments on API 37 16KB emulator.
"""

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apkrevive.adb.bridge import find_adb


def run_adb(adb: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = [adb, "-s", "emulator-5554"] + args
    print(f"\n$ {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.stdout.strip():
        print("STDOUT:\n" + res.stdout.strip())
    if res.stderr.strip():
        print("STDERR:\n" + res.stderr.strip())
    print(f"EXIT CODE: {res.returncode}")
    return res


def main() -> None:
    adb = find_adb()
    if not adb:
        print("ADB not found!")
        sys.exit(1)

    print("Waiting for device...")
    subprocess.run([adb, "wait-for-device"])

    targets = [
        {
            "pkg": "atm.starun.game",
            "apk": REPO_ROOT / "tests" / "corpus" / "emulator_test" / "revived_atm.starun.game_121.apk",
        },
        {
            "pkg": "atm.rocketguardian",
            "apk": REPO_ROOT / "tests" / "corpus" / "emulator_test" / "revived_atm.rocketguardian_1.apk",
        },
    ]

    for item in targets:
        pkg = item["pkg"]
        apk = item["apk"]
        print("\n=======================================================")
        print(f"REVIVED TEST: {pkg} (REVIVED APK)")
        print(f"APK Path: {apk}")
        print("=======================================================")

        # 0. Clean uninstall first
        print("\n--- FRESH UNINSTALL ---")
        run_adb(adb, ["uninstall", pkg])

        # 1. Clear logcat
        run_adb(adb, ["logcat", "-c"])

        # 2. Install revived APK with -g
        inst_res = run_adb(adb, ["install", "-r", "-g", str(apk)])
        if inst_res.returncode != 0:
            print(f"INSTALL FAILED for {pkg} (exit code {inst_res.returncode})!")
            continue

        # 3. Launch via monkey
        run_adb(adb, ["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])

        # 4. Sleep 8 seconds for liveness check
        print("Sleeping 8 seconds for liveness check...")
        time.sleep(8)

        # 5. Check pid
        print("\n--- PIDOF ---")
        run_adb(adb, ["shell", "pidof", pkg])

        # 6. Check top resumed activity
        print("\n--- TOP RESUMED ACTIVITY ---")
        filter_act = [adb, "-s", "emulator-5554", "shell", "dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'"]
        print(f"$ {' '.join(filter_act)}")
        res_act = subprocess.run(filter_act, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if res_act.stdout.strip():
            print("STDOUT:\n" + res_act.stdout.strip())
        else:
            print("(no matching resumed activity lines)")

        # 7. Check crash buffer
        print("\n--- CRASH BUFFER ---")
        run_adb(adb, ["logcat", "-d", "-b", "crash"])

        # 8. Filter logcat for NativeLibraryHelper | page size | dlopen | UnsatisfiedLink
        print("\n--- LOGCAT FILTER: NativeLibraryHelper | page size | dlopen | UnsatisfiedLink ---")
        filter_cmd = [adb, "-s", "emulator-5554", "shell", "logcat -d | grep -iE 'NativeLibraryHelper|page size|dlopen|UnsatisfiedLink'"]
        print(f"$ {' '.join(filter_cmd)}")
        res_filter = subprocess.run(filter_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if res_filter.stdout.strip():
            print("STDOUT:\n" + res_filter.stdout.strip())
        else:
            print("(no matching log lines)")

        # 9. Clean uninstall
        print("\n--- CLEANUP UNINSTALL ---")
        run_adb(adb, ["uninstall", pkg])


if __name__ == "__main__":
    main()
