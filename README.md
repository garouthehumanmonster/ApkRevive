# ApkRevive

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Android Target](https://img.shields.io/badge/Android%20API-3%20to%2028-brightgreen.svg)](https://developer.android.com)
[![Modern Host](https://img.shields.io/badge/Modern%20Host-API%2034--36%20(Android%2014--16)-orange.svg)](https://developer.android.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

A single-purpose, ruthless CLI tool for patching legacy Android APKs (API 3–28) to run on modern Android runtimes (Android 14–16 / API 34–36) with 16KB kernels, strict Bionic linker namespaces, and modern platform security restrictions.

Instead of merely reporting compatibility errors, ApkRevive directly patches binaries with runtime compatibility shims.

---

## Capabilities

1. **DEX Runtime Compatibility Shim (`ApkReviveInitProvider`):**
   - **Hidden API Unlock:** Bypasses non-SDK reflection restrictions (`dalvik.system.VMRuntime.setHiddenApiExemptions`) so legacy apps reflecting into internal APIs do not crash on Android 9+ (API 28+).
   - **StrictMode & NetworkOnMainThread Disabler:** Enforces `StrictMode.ThreadPolicy.LAX` and `StrictMode.VmPolicy.LAX`, and disables death on file URI exposure to prevent crashes from main-thread network calls and file URI sharing.
   - **Storage Exception Interceptor:** Global thread `UncaughtExceptionHandler` catches and suppresses fatal crashes from hardcoded `/sdcard/` paths, `FileUriExposedException`, and missing runtime permissions under Scoped Storage.

2. **Bionic Linker Patcher (`elf_surgeon.py`):**
   - Scans 64-bit and 32-bit ELF shared libraries (`.so`) for private Bionic platform libraries (`libcrypto.so`, `libssl.so`, `libcutils.so`, `libandroid_runtime.so`).
   - Renames private DT_NEEDED dependencies (e.g. `libcrypto.so` -> `libcrypto_legacy.so`) in dynamic string tables and bundles minimal 16KB-aligned fallback stub libraries into `lib/<abi>/`.

3. **In-Memory Binary AXML Surgeon:**
   - Injects `<uses-library android:name="org.apache.http.legacy" android:required="false" />` for API 28+ runtimes.
   - Sets `android:pageSizeCompat="enabled"` for Android 16 16KB-page compatibility.
   - Unlocks modern widescreen aspect ratios (`resizeableActivity="true"`) and sets `hasCode="true"`.

4. **16KB Alignment & V2/V3 Signing:**
   - 16KB boundary zipalignment for `.so` and `resources.arsc` using Android tag `0xD935`.
   - V2/V3 signing via `apksigner` or stdlib crypto.

---

## Installation

Requires Python 3.9+ and Android SDK build-tools (`apksigner`, `zipalign`) in your `PATH` (or uses built-in fallbacks).

```bash
git clone https://github.com/garouthehumanmonster/ApkRevive.git
cd ApkRevive
pip install -e .
```

To install development and testing dependencies:
```bash
pip install -e ".[dev]"
```

---

## CLI Usage

ApkRevive provides two primary commands:

### 1. `apkrevive inspect <apk>`
Scans an APK and outputs a concise terminal summary of actual fatal blockers.

```bash
apkrevive inspect legacy_game.apk
```

Output:
```
======================================================================
ApkRevive Inspection Report: legacy_game.apk
======================================================================
Package: com.retro.game
Version Code: 42
targetSdkVersion: 22 (minSdkVersion: 9)
ABIs: armeabi-v7a

FATAL BLOCKERS (1):
  [!] 32-bit only APK (armeabi-v7a): Incompatible with 64-bit-only devices

REMEDIABLE ISSUES (2):
  [*] Target SDK 22 is below Android 14+ install floor (23/24)
  [*] Missing org.apache.http.legacy library dependency

WARNINGS (1):
  [-] APK requests external storage; Scoped Storage on API 29+ may restrict access
======================================================================
```

Emits JSON with `--json`:
```bash
apkrevive inspect legacy_game.apk --json
```

### 2. `apkrevive patch <apk> -o <out.apk>`
Executes the binary mutation pipeline to remediate runtime crashes.

```bash
apkrevive patch legacy_game.apk -o revived_game.apk
```

Output:
```
======================================================================
ApkRevive Patch Report: legacy_game.apk -> revived_game.apk
======================================================================
Package: com.retro.game
Target SDK: 24 (bumped from 22 to meet install floor)

REMEDIATIONS APPLIED:
  [*] Injected org.apache.http.legacy into AndroidManifest.xml
  [*] Injected pageSizeCompat="enabled" into AndroidManifest.xml
  [*] Expanded aspect ratio and set resizeableActivity="true"
  [*] Injected ApkReviveInitProvider (Hidden API unlock, StrictMode LAX, storage crash guard)
  [*] Container aligned to 16KB boundaries (tag 0xD935)
  [*] APK signed with V2/V3 signature scheme

Output APK: revived_game.apk
Status: READY
======================================================================
```

Options:
- `-o, --output <path>`: Output patched APK path (required).
- `--device-api <api>`: Target Android API level (default: 35).
- `--bump-target-sdk <api>`: Bump `targetSdkVersion` to specified API level.
- `--ks <keystore>`: Path to custom signing keystore.
- `--ks-pass <pass>`: Keystore password.
- `--json`: Output report as JSON.
- `--force`: Force patching even when fatal blockers are detected.

---

## Testing

Run the test suite using pytest:

```bash
python -m pytest
```

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
