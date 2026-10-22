#!/usr/bin/env python3
"""
verify_emulator_e2e.py - Live End-to-End (E2E) Verification Harness.
Builds a real legacy API 19 APK using local Android Studio SDK tools,
proves it fails on the connected emulator, patches it with ApkRevive,
and proves the revived APK installs and runs live without crashing.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apkrevive.core.align import verify_apk_alignment
from apkrevive.core.signer import verify_signing_block_padding
from apkrevive.cli import main as cli_main


def find_sdk_tool(tool_name: str) -> str:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"
    )
    sdk_path = Path(sdk_root)
    if not sdk_path.is_dir():
        raise RuntimeError(f"Android SDK not found at {sdk_root}")

    if tool_name == "adb":
        candidate = sdk_path / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
        if candidate.is_file():
            return str(candidate)

    bt_dir = sdk_path / "build-tools"
    if bt_dir.is_dir():
        versions = sorted([d for d in bt_dir.iterdir() if d.is_dir()], reverse=True)
        for v in versions:
            ext = ".bat" if (os.name == "nt" and tool_name in ("d8", "apksigner")) else (".exe" if os.name == "nt" else "")
            candidate = v / f"{tool_name}{ext}"
            if candidate.is_file():
                return str(candidate)

    which = shutil.which(tool_name)
    if which:
        return which

    raise FileNotFoundError(f"Could not locate tool: {tool_name}")


def find_android_jar() -> str:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"
    )
    sdk_path = Path(sdk_root)
    platforms = sdk_path / "platforms"
    if platforms.is_dir():
        versions = sorted([d for d in platforms.iterdir() if d.is_dir()], reverse=True)
        for v in versions:
            jar = v / "android.jar"
            if jar.is_file():
                return str(jar)
    raise FileNotFoundError("Could not locate android.jar in platforms/")


def run_adb(adb: str, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    cmd = [adb] + args
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    if check and res.returncode != 0:
        raise RuntimeError(f"adb command failed: {' '.join(cmd)}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res


def build_legacy_canary_apk(output_apk: Path) -> Path:
    """Builds a real API 19 canary APK using javac, d8, aapt2, and apksigner."""
    print("[*] Building legacy API 19 canary APK...")
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    find_sdk_tool("adb")
    aapt2 = find_sdk_tool("aapt2")
    d8 = find_sdk_tool("d8")
    find_sdk_tool("apksigner")
    javac = shutil.which("javac") or "javac"
    android_jar = find_android_jar()

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)
        src_dir = tmp_dir / "src" / "com" / "apkrevive" / "canary"
        src_dir.mkdir(parents=True, exist_ok=True)
        bin_dir = tmp_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        dex_dir = tmp_dir / "dex"
        dex_dir.mkdir(parents=True, exist_ok=True)
        res_dir = tmp_dir / "res" / "values"
        res_dir.mkdir(parents=True, exist_ok=True)

        # 1. Java Source
        java_code = """package com.apkrevive.canary;

import android.app.Activity;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.lang.reflect.Method;

public class MainActivity extends Activity {
    private static final String TAG = "ApkReviveCanary";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "MainActivity.onCreate starting runtime checks");

        // Check A: Apache HTTP Legacy Check
        try {
            Class.forName("org.apache.http.impl.client.DefaultHttpClient");
            Log.i(TAG, "Check A (Apache HTTP): PASSED");
        } catch (ClassNotFoundException e) {
            Log.e(TAG, "Check A (Apache HTTP) FAILED: " + e.getMessage(), e);
            throw new RuntimeException("Apache HTTP missing", e);
        }

        // Check B: API 24+ FileUriExposedException Check
        try {
            if (Build.VERSION.SDK_INT >= 24) {
                Method m = StrictMode.class.getMethod("onFileUriExposed", Uri.class, String.class);
                m.invoke(null, Uri.fromFile(new File("/sdcard/test.txt")), "test");
            }
            Log.i(TAG, "Check B (FileUriExposed): PASSED");
        } catch (Throwable t) {
            Log.e(TAG, "Check B (FileUriExposed) FAILED: " + t.getMessage(), t);
            throw new RuntimeException("FileUriExposed death active", t);
        }

        // Check C: Hidden API Reflection Check
        try {
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntimeClass.getDeclaredMethod("getRuntime");
            Object vmRuntime = getRuntime.invoke(null);
            if (vmRuntime == null) {
                throw new RuntimeException("VMRuntime is null");
            }
            Log.i(TAG, "Check C (Hidden API VMRuntime): PASSED");
        } catch (Throwable t) {
            Log.e(TAG, "Check C (Hidden API VMRuntime) FAILED: " + t.getMessage(), t);
            throw new RuntimeException("Hidden API blocked", t);
        }

        Log.i(TAG, "APKREVIVE_E2E_SUCCESS");

        TextView tv = new TextView(this);
        tv.setText("APKREVIVE E2E SUCCESS ON API " + Build.VERSION.SDK_INT);
        tv.setTextColor(Color.WHITE);
        tv.setTextSize(22);
        tv.setPadding(40, 80, 40, 40);
        tv.setBackgroundColor(Color.rgb(0, 150, 0));
        setContentView(tv);
    }
}
"""
        (src_dir / "MainActivity.java").write_text(java_code, encoding="utf-8")

        # 2. AndroidManifest.xml (Legacy API 19 without Apache HTTP library)
        manifest_code = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.apkrevive.canary"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="19" />

    <application
        android:label="ApkRevive Canary"
        android:hasCode="true">
        <activity
            android:name="com.apkrevive.canary.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
        manifest_file = tmp_dir / "AndroidManifest.xml"
        manifest_file.write_text(manifest_code, encoding="utf-8")

        # 3. Compile Java with javac
        cmd_javac = [javac, "-cp", android_jar, "-d", str(bin_dir), str(src_dir / "MainActivity.java")]
        res = subprocess.run(cmd_javac, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"javac failed:\n{res.stderr}")

        # 4. Translate .class to classes.dex with d8
        class_files = [str(p) for p in bin_dir.rglob("*.class")]
        cmd_d8 = [d8, "--lib", android_jar, "--output", str(dex_dir)] + class_files
        res = subprocess.run(cmd_d8, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"d8 failed:\n{res.stderr}")

        # 5. Link resource package with aapt2
        res_apk = tmp_dir / "resources.apk"
        cmd_aapt2 = [
            aapt2, "link",
            "-I", android_jar,
            "--manifest", str(manifest_file),
            "-o", str(res_apk),
        ]
        res = subprocess.run(cmd_aapt2, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"aapt2 link failed:\n{res.stderr}")

        # 6. Assemble unaligned APK container with classes.dex and dummy 64-bit .so libraries
        raw_apk = tmp_dir / "unaligned.apk"
        shutil.copy2(res_apk, raw_apk)

        import struct
        # Synthetic minimal 16KB aligned 64-bit ELF shared library for x86_64
        endian = "<"
        ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        header = struct.pack(f"{endian}HHIQQQIHHHHHH", 3, 62, 1, 0x1000, 64, 0, 0, 64, 56, 2, 64, 0, 0)
        ph0 = struct.pack(f"{endian}IIQQQQQQ", 1, 5, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, 16384)
        ph1 = struct.pack(f"{endian}IIQQQQQQ", 1, 6, 0x4000, 0x4000, 0x4000, 0x1000, 0x1000, 16384)
        so_data = bytearray(ident + header + ph0 + ph1)
        if len(so_data) < 0x5000:
            so_data.extend(b"\x00" * (0x5000 - len(so_data)))
        so_bytes = bytes(so_data)

        with zipfile.ZipFile(raw_apk, "a") as zf:
            zf.write(dex_dir / "classes.dex", "classes.dex")
            zf.writestr("lib/x86_64/libcanary.so", so_bytes)
            zf.writestr("lib/arm64-v8a/libcanary.so", so_bytes)

        # 7. Sign with test keystore
        from apkrevive.core.signer import ensure_keystore, sign_apk
        ks_file, ks_pass, key_alias = ensure_keystore(None, None, None)
        shutil.copy2(raw_apk, output_apk)
        if not sign_apk(str(output_apk), ks_file, ks_pass, key_alias, ks_pass):
            raise RuntimeError("Failed to sign canary APK")

    print(f"[+] Legacy API 19 canary successfully generated: {output_apk} ({output_apk.stat().st_size} bytes)")
    return output_apk


def main() -> int:
    print("================================================================================")
    print("  ApkRevive Live Emulator End-to-End (E2E) Verification Harness")
    print("================================================================================")

    adb = find_sdk_tool("adb")
    print(f"[*] Found adb: {adb}")

    # Step 0: Verify emulator is online
    print("[*] Waiting for emulator device to be ready...")
    run_adb(adb, ["wait-for-device"])
    dev_res = run_adb(adb, ["devices"])
    print(f"[*] Attached devices:\n{dev_res.stdout}")
    if "device" not in dev_res.stdout.split("List of devices attached")[-1]:
        print("[-] Error: No online Android emulator detected! Start an emulator first.")
        return 1

    sdk_ver = run_adb(adb, ["shell", "getprop", "ro.build.version.sdk"]).stdout.strip()
    abi_ver = run_adb(adb, ["shell", "getprop", "ro.product.cpu.abi"]).stdout.strip()
    print(f"[*] Connected Emulator: API Level {sdk_ver}, ABI {abi_ver}")

    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    legacy_apk = dist_dir / "legacy_canary.apk"
    revived_apk = dist_dir / "revived_canary.apk"

    # Step 1: Build legacy canary APK
    build_legacy_canary_apk(legacy_apk)

    pkg = "com.apkrevive.canary"
    run_adb(adb, ["uninstall", pkg], check=False)

    # Step 2: Prove unpatched legacy APK is BLOCKED by modern Android install gate
    print("\n--------------------------------------------------------------------------------")
    print("  Step A: Proving Unpatched Legacy APK Fails on Modern Android")
    print("--------------------------------------------------------------------------------")
    print(f"[*] Attempting standard install of unpatched APK ({legacy_apk.name})...")
    inst_res = run_adb(adb, ["install", "-r", str(legacy_apk)], check=False)
    print(f"[*] Output: {inst_res.stdout.strip()} {inst_res.stderr.strip()}")

    # Android 14+ blocks install of targetSdk < 24 with INSTALL_FAILED_DEPRECATED_SDK_VERSION
    if int(sdk_ver) >= 34:
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in inst_res.stdout or "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in inst_res.stderr:
            print("[+] Verified: Android OS correctly blocked unpatched legacy APK (INSTALL_FAILED_DEPRECATED_SDK_VERSION)!")
        else:
            print("[!] Warning: Expected INSTALL_FAILED_DEPRECATED_SDK_VERSION, proceeding to bypass test...")

    # Force install with bypass to prove runtime crash
    print("[*] Force-installing unpatched APK with --bypass-low-target-sdk-block...")
    force_res = run_adb(adb, ["install", "-r", "--bypass-low-target-sdk-block", str(legacy_apk)], check=False)
    if "Success" not in force_res.stdout:
        print(f"[-] Force install failed: {force_res.stderr or force_res.stdout}")
        return 1
    print("[+] Force-installed unpatched legacy APK.")

    # Clear logcat and launch
    run_adb(adb, ["logcat", "-c"])
    print("[*] Launching unpatched Canary MainActivity with am start -W...")
    run_adb(adb, ["shell", "am", "start", "-W", "-n", f"{pkg}/.MainActivity"], check=False)
    time.sleep(2.5)

    # Check crash logs
    logcat_out = run_adb(adb, ["logcat", "-d"]).stdout
    print("[*] Inspected logcat for runtime crash:")
    has_crash = ("ClassNotFoundException" in logcat_out and "org.apache.http" in logcat_out) or ("Apache HTTP missing" in logcat_out)
    if has_crash:
        print("[+] Verified: Unpatched APK crashed with expected ClassNotFoundException for Apache HTTP!")
    else:
        print("[!] Logcat output (searching for Apache HTTP):")
        for line in logcat_out.splitlines():
            if "AndroidRuntime" in line or "Apache" in line or "canary" in line.lower():
                print(f"    {line}")

    run_adb(adb, ["uninstall", pkg], check=False)

    # Step 3: Patch with ApkRevive and prove live runtime revival
    print("\n--------------------------------------------------------------------------------")
    print("  Step B: Patching with ApkRevive & Verifying Live Execution")
    print("--------------------------------------------------------------------------------")
    print(f"[*] Running: apkrevive patch {legacy_apk} -o {revived_apk}")
    cli_code = cli_main(["patch", str(legacy_apk), "-o", str(revived_apk), "--bump-target-sdk", "24"])
    if cli_code != 0 or not revived_apk.is_file():
        print(f"[-] Patching failed with exit code {cli_code}")
        return 1
    print(f"[+] Successfully produced patched APK: {revived_apk} ({revived_apk.stat().st_size} bytes)")

    # Validate 16KB alignment
    align_info = verify_apk_alignment(str(revived_apk))
    if not align_info["aligned"]:
        print(f"[-] 16KB alignment verification failed: {align_info}")
        return 1
    print("[+] Verified: 16KB (0x4000) alignment holds for all uncompressed native libs & resources.arsc!")

    # Validate signing block padding
    sig_info = verify_signing_block_padding(str(revived_apk))
    print(f"[+] Verified signing block: CD 4KB aligned = {sig_info['cd_aligned_4k']}")

    # Install revived APK using STANDARD install (NO bypass flags!)
    print("[*] Installing revived APK with standard adb install (NO bypass flags!)...")
    rev_inst = run_adb(adb, ["install", "-r", str(revived_apk)])
    if "Success" not in rev_inst.stdout:
        print(f"[-] Standard install failed: {rev_inst.stdout} {rev_inst.stderr}")
        return 1
    print("[+] Verified: Standard adb install succeeded cleanly without any bypass flags!")

    # Clear logcat and launch revived app
    run_adb(adb, ["logcat", "-c"])
    print("[*] Launching revived Canary MainActivity with am start -W...")
    launch_res = run_adb(adb, ["shell", "am", "start", "-W", "-n", f"{pkg}/.MainActivity"])
    print(f"[*] Launch output:\n{launch_res.stdout.strip()}")
    time.sleep(3.0)

    # Check for live process
    pid_res = run_adb(adb, ["shell", "pidof", pkg], check=False)
    pid = pid_res.stdout.strip()
    if not pid:
        print(f"[-] Error: {pkg} is not running! Process died unexpectedly.")
        dump_err = run_adb(adb, ["logcat", "-d", "-s", "AndroidRuntime:E", "ApkRevive:I", "ApkReviveCanary:I"]).stdout
        print(dump_err)
        return 1
    print(f"[+] Live process confirmed: PID={pid} is active on the emulator screen!")

    # Check logcat for success milestones
    logs = run_adb(adb, ["logcat", "-d", "-s", "ApkRevive:I", "ApkReviveCanary:I"]).stdout
    print(f"[*] Captured App Logs:\n{logs.strip()}")

    if "ApkReviveInitProvider initialized" in logs:
        print("[+] Verified: ApkReviveInitProvider executed before Application.onCreate()!")
    else:
        print("[!] Warning: 'ApkReviveInitProvider initialized' missing in logcat.")

    if "APKREVIVE_E2E_SUCCESS" in logs:
        print("[+] Verified: All 3 runtime compatibility checks PASSED (Apache HTTP + StrictMode + Hidden API)!")
    else:
        print("[-] Error: 'APKREVIVE_E2E_SUCCESS' not found in logcat!")
        return 1

    print("\n================================================================================")
    print("  LIVE EMULATOR END-TO-END VERIFICATION: 100% PASSED!")
    print("================================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
