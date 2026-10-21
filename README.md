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
   - **Hidden API Unlock:** Bypasses non-SDK reflection restrictions (`dalvik.system.VMRuntime.setHiddenApiExemptions`) using meta-reflection so legacy apps reflecting into internal APIs do not crash on Android 9+ (API 28+).
   - **StrictMode & NetworkOnMainThread Disabler:** Disables death on file URI exposure (`StrictMode.disableDeathOnFileUriExposure()`) and sets `StrictMode.ThreadPolicy.LAX` and `StrictMode.VmPolicy.LAX` to prevent crashes from main-thread network calls and file URI sharing on API 24+.
   - **Deterministic, Tiny Bytecode:** 100% verified by `dex2oat` and compiled directly with `javac` and `d8` against modern Android SDKs. Injected cleanly into the next available multidex slot (`classes{max_N + 1}.dex`) with dynamic authority (`${packageName}.apkrevive.init`).

2. **16KB ELF & Bionic Linker Inspector (`elf_surgeon.py`):**
   - Audits 64-bit and 32-bit ELF shared libraries (`.so`) for 16KB (`0x4000`) page alignment and modulo congruence (`p_vaddr % 0x4000 == p_offset % 0x4000`).
   - Identifies private Bionic platform libraries (`libcrypto.so`, `libssl.so`, `libcutils.so`, `libandroid_runtime.so`, `libgui.so`) and reports truthful warnings without polluting binaries with fake stubs.

3. **In-Memory Binary AXML Surgeon:**
   - Injects `<uses-library android:name="org.apache.http.legacy" android:required="false" />` for API 28+ runtimes.
   - Sets `android:pageSizeCompat="enabled"` for Android 15/16 16KB-page compatibility.
   - Preserves `/sdcard/` storage access (`android:requestLegacyExternalStorage="true"`) and legacy `http://` traffic (`android:usesCleartextTraffic="true"`).
   - Enforces `android:exported="true"` on components with `<intent-filter>` for Android 12+ (API 31+) safety.
   - Unlocks modern widescreen aspect ratios (`resizeableActivity="true"`) and sets `hasCode="true"`.
   - Strips Google Play split-install locks (`isSplitRequired`, `splitTypes`).
   - Maintains strict ascending numerical resource-ID attribute order for `ResXMLTree` binary search compatibility.

4. **16KB Alignment & V2/V3 Signing:**
   - 16KB boundary zipalignment for `.so` and `resources.arsc` using Android tag `0xD935`.
   - V2/V3 signing via `apksigner` with 4KB-aligned APK Signing Block padding (Verity Padding Block `0x42726577`).

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
targetSdkVersion: 19 (minSdkVersion: 9)
ABIs: armeabi-v7a

FATAL BLOCKERS (1):
  [!] 32-bit only APK (armeabi-v7a): Incompatible with 64-bit-only devices

REMEDIABLE ISSUES (2):
  [*] Target SDK 19 is below Android 14+ install floor (23/24)
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
Target SDK: 24 (bumped from 19 to meet install floor)

REMEDIATIONS APPLIED:
  [*] Injected org.apache.http.legacy into AndroidManifest.xml
  [*] Injected pageSizeCompat="enabled" into AndroidManifest.xml
  [*] Enabled requestLegacyExternalStorage and usesCleartextTraffic
  [*] Expanded aspect ratio and set resizeableActivity="true"
  [*] Injected ApkReviveInitProvider into classes2.dex (Hidden API unlock + StrictMode LAX)
  [*] Container aligned to 16KB boundaries (tag 0xD935)
  [*] APK signed with V2/V3 signature scheme

Output APK: revived_game.apk
Status: READY
======================================================================
```

Options:
- `-o, --output <path>`: Output patched APK path (required).
- `--device-api <api>`: Target Android API level (default: 35).
- `--bump-target-sdk <api>`: Bump `targetSdkVersion` to specified API level (default: 24).
- `--ks <keystore>`: Path to custom signing keystore.
- `--ks-pass <pass>`: Keystore password.
- `--json`: Output report as JSON.
- `--force`: Force patching even when fatal blockers are detected.

---

## Verification

### Unit Test Suite
```bash
python -m pytest
```

### Live Emulator E2E Verification
Verifies end-to-end compatibility against a running Android Studio emulator (Android 14–16):
```bash
python scripts/verify_emulator_e2e.py
```

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
