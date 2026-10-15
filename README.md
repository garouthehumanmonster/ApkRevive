# ApkRevive v3.3

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Android Target](https://img.shields.io/badge/Android%20API-3%20to%2035+-brightgreen.svg)](https://developer.android.com)
[![Page Alignment](https://img.shields.io/badge/16KB%20Page%20Size-Supported-orange.svg)](https://developer.android.com/guide/practices/page-sizes)
[![Status](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

> [!WARNING]
> **Project Status: Alpha.** ApkRevive is an experimental tooling suite under active development. It is not intended for production deployments without independent verification.

**ApkRevive** is a legacy Android APK modernization pipeline and compatibility layer. It diagnoses, patches, and adapts legacy applications targeting Android API levels 3 through 28 (Android 1.5 Cupcake to Android 9 Pie) so they install, boot, and run reliably on modern Android runtimes (API 34–36+, Android 14/15/16 QPR) with 16KB page sizes, modern targetSdk install floors, strict bionic namespace isolation, and high-refresh displays.

---

## Architecture Overview

```mermaid
flowchart TD
    A["Raw Legacy APK (API 3-28)"] --> B["ApkInspector / Triage Engine"]
    B --> C{"Compatibility Verdict"}
    
    C -->|"GREEN"| D["Install Unmodified / Direct ADB Bypass"]
    C -->|"YELLOW"| E["Modernization Pipeline"]
    C -->|"RED"| F["Fatal Incompatibility (Report Diagnostics)"]
    
    E --> G["AXML Surgeon (Manifest Mutation)"]
    E --> H["Bytecode Shim Injection (ApkReviveInitProvider)"]
    E --> I["16KB ZipAligner & PageSizeCompat"]
    E --> J["V2/V3 APK Re-Signer"]
    
    G --> K["Modernized APK (.revived.apk)"]
    H --> K
    I --> K
    J --> K
    
    K --> L["On-Device Install (Shizuku Bridge / ADB)"]
```

---

## Key Capabilities

### 1. Authoritative Triage Engine
Evaluates legacy APK metadata against target device profiles to generate actionable **GREEN**, **YELLOW**, or **RED** verdicts:
- **ABI Verification:** Validates APK native libraries against target device CPU architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
- **16KB Page Size Audit:** Scans 64-bit ELF shared libraries (`.so`) for `p_align >= 16384` compliance required by Android 15+.
- **Bionic Linker Greylist Detection:** Catches private system library linkage (`libandroid_runtime.so`, `libcutils.so`, `libcrypto.so`, `libgui.so`) blocked by Android 7.0+ namespace isolation.
- **Install Floor Compliance:** Identifies targetSdk levels blocked by Android's `min_install_version` policy and selects the appropriate bypass method.

### 2. In-Memory AXML Surgeon
Mutates compiled Android binary XML (`AndroidManifest.xml`) directly in-place without decompiling resources or invoking heavyweight tools (`apktool`, `aapt`):
- Injects `<uses-library android:name="org.apache.http.legacy" android:required="false" />` for API 28+ runtimes.
- Sets `android:resizeableActivity="true"` and removes restrictive `android.max_aspect` metadata to unlock modern widescreen aspect ratios (18:9, 20:9, foldables).
- Forces `android:hasCode="true"` when injecting initialization shims into resource-only APKs.
- Injects metadata flags for runtime display controls.

### 3. Runtime Shim & Display Adaptation
Provides a zero-overhead content provider shim (`ApkReviveInitProvider` in `shim.dex`) that hooks application launch:
- **60Hz Display Mode Lock:** Fixes game physics and animations that decouple or run at hyperspeed on 90Hz/120Hz/144Hz displays due to fixed-delta game loops.
- **Display Cutout Layout:** Configures `LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES` to eliminate aggressive letterboxing around camera punches and notches.

### 4. 16KB Alignment & Zip Re-Packing
- Enforces strict 4-byte resource alignment and 16,384-byte (16KB) uncompressed alignment for native `.so` payloads within the APK ZIP container.
- For Android 16 (API 36+), enables the platform 16KB compatibility mode flag (`android:pageSizeCompat="enabled"`). *Note: Native ELF segment layout (`p_align`) is not rewritten.*
- Strips invalid legacy signature blocks (`META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.MF`) and signs with deterministic APK Signature Scheme v2/v3.

### 5. OBB Expansion Delivery Validator
- Validates Google Play Expansion File (OBB) naming patterns (`main.V.packageName.obb` / `patch.V.packageName.obb`).
- Detects version drift where expansion version codes lead or lag APK `versionCode`.

### 6. Shizuku-Powered Android Companion App (`apkrevive-android`)
- Native on-device companion app built with Jetpack Compose.
- Connects to Shizuku to install low-targetSdk packages without requiring a PC, root access, or terminal ADB.

---

## Project Structure

```
ApkRevive/
├── apkrevive/                  # Core Python Modernizer Engine & CLI
│   ├── adb/                    # ADB bridge and device install-floor probe
│   ├── core/                   # Triage, AXML surgeon, ELF parser, aligner, signer, OBB
│   ├── shim/                   # Precompiled bytecode shim (ApkReviveInitProvider)
│   └── cli.py                  # CLI entrypoint (`apkrevive`)
├── apkrevive-android/          # On-device companion app (Kotlin, Compose, Shizuku)
│   ├── app/src/main/           # Android app source & installer bridge
│   └── build.gradle.kts        # Gradle build configuration
├── canaries/                   # 8 pairs of control & failing verification canaries
│   ├── src/                    # C/Java sources and canary manifests
│   └── build_canaries.py       # Deterministic canary test harness
├── tests/                      # Full pytest/unittest test suite
├── pyproject.toml              # Python package metadata & dependencies
└── README.md
```

---

## Installation

### Prerequisites
- Python 3.9+
- Android SDK build-tools (for `zipalign` and `apksigner` in PATH, optional if using internal fallback)
- Android device with USB debugging (for ADB commands) or Shizuku installed (for on-device app)

### Install Python CLI
```bash
git clone https://github.com/garouthehumanmonster/ApkRevive.git
cd ApkRevive
pip install -e .
```

---

## CLI Usage & Sample Runs

### 1. Host Health Check (`apkrevive doctor`)
Verify local developer tools, SDK build-tools, ADB, and keystore health:
```bash
$ apkrevive doctor
ApkRevive Doctor Report
=======================
[PASS]   Python Version: Python 3.10.12 (>=3.9 required)
[PASS]   Java Development Kit: keytool at /usr/bin/keytool, javac at /usr/bin/javac
[PASS]   Android SDK: Found at /home/user/Android/Sdk
[PASS]   Build-Tools: apksigner at /home/user/Android/Sdk/build-tools/34.0.0/apksigner, zipalign at /home/user/Android/Sdk/build-tools/34.0.0/zipalign
[PASS]   Android Debug Bridge: ADB found at /usr/bin/adb
[PASS]   User Keystore Directory: /home/user/.apkrevive is ready
[PASS]   Shim DEX Integrity: Verified SHA256 (609b5dcbc8f657b046a73809afbd666cb6feb567497dc068733b57212286e590)

Overall Status: [PASS]
```

### 2. Triage an APK (`apkrevive triage`)
Inspect an APK and generate a compatibility report against target device specifications:
```bash
$ apkrevive triage sample_game.apk --device-api 35 --device-abis arm64-v8a --page-size 16384
ApkRevive Triage Report
=======================
Package Name: com.retro.spaceace
Target SDK: 22 (Floor: 24)
Verdict: YELLOW
Reason: MODIFICATION_REQUIRED
Install Method: BYPASS_LOW_TARGET_SDK_BLOCK
Required Transforms:
  - EXPAND_ASPECT_RATIO
  - INJECT_USES_LIBRARY_APACHE_HTTP
  - LOCK_60HZ_DISPLAY_MODE
Warnings:
  - WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions on Android 11+ (API 30+).
  - WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on API 28+.
Details: APK targetSdk 22 is below device install floor 24
```

With the global `--json` flag:
```json
{
  "package_name": "com.retro.spaceace",
  "target_sdk": 22,
  "verdict": "YELLOW",
  "reason": "MODIFICATION_REQUIRED",
  "install_method": "BYPASS_LOW_TARGET_SDK_BLOCK",
  "required_transforms": [
    "EXPAND_ASPECT_RATIO",
    "INJECT_USES_LIBRARY_APACHE_HTTP",
    "LOCK_60HZ_DISPLAY_MODE"
  ],
  "warnings": [
    "WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions on Android 11+ (API 30+).",
    "WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on API 28+."
  ],
  "details": "APK targetSdk 22 is below device install floor 24"
}
```

### 3. Dry-Run Modernization (`apkrevive revive --dry-run`)
Simulate transforms, inspection, and report generation without creating files or signing:
```bash
$ apkrevive revive sample_game.apk --dry-run --enable-60hz --enable-cutout
ApkRevive Patch Report (DRY RUN)
================================
Package Name: com.retro.spaceace
Target SDK: 22
Verdict: YELLOW
Reason: MODIFICATION_REQUIRED
Install Method: BYPASS_LOW_TARGET_SDK_BLOCK
Required Transforms:
  - EXPAND_ASPECT_RATIO
  - INJECT_USES_LIBRARY_APACHE_HTTP
  - LOCK_60HZ_DISPLAY_MODE
Output APK: [DRY RUN - No file written]
Warnings (2):
  - WARN_SCOPED_STORAGE_OBB: ...
  - WARN_CLEARTEXT: ...
Details: Dry run completed. No files modified.
```

### 4. Revive & Modernize an APK (`apkrevive revive`)
Apply binary manifest transforms, inject runtime shims, 16KB-align, and sign:
```bash
$ apkrevive revive sample_game.apk --output output/revived_game.apk --enable-60hz --enable-cutout
WARNING: APK signature has changed. Re-signing requires uninstalling the existing application on device, which will permanently delete all existing user data.
ApkRevive Patch Report
======================
Timestamp: 2026-10-15T07:34:12.829496
Package Name: com.retro.spaceace
Target SDK: 22
Verdict: YELLOW
Reason: MODIFICATION_REQUIRED
Install Method: BYPASS_LOW_TARGET_SDK_BLOCK
Required Transforms:
  - EXPAND_ASPECT_RATIO
  - INJECT_USES_LIBRARY_APACHE_HTTP
  - LOCK_60HZ_DISPLAY_MODE
Output APK: output/revived_game.apk
Warnings (2):
  - WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions on Android 11+ (API 30+).
  - WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on API 28+.
Details: Patched AXML manifest, injected ApkReviveInitProvider, aligned container to 16KB, signed with user keystore.
```

### 5. Probe Connected Device (`apkrevive probe`)
Detect the connected device's OS version, CPU architectures, page size, and enforce install floor via ADB:
```bash
$ apkrevive probe
{
  "sdk": 35,
  "floor": 24,
  "status": "CONFIRMED_VIA_PROP",
  "abis": ["arm64-v8a"],
  "page_size": 16384
}
```

### 6. Validate OBB Delivery (`apkrevive push-obb`)
Check whether an expansion file matches the target package and APK version:
```bash
$ apkrevive push-obb main.100.com.retro.spaceace.obb com.retro.spaceace --current-apk-version 100
```

---

## On-Device Companion App (`apkrevive-android`)

For rootless, PC-free installations on modern Android devices, ApkRevive includes a native companion app built with **Jetpack Compose** and **Shizuku**.

### Architecture & Permission Flow

```
┌────────────────────────────────────────────────────────┐
│           ApkRevive Android Companion UI               │
│  (Pick Revived APK ➔ Verify Target SDK ➔ One-Tap Install) │
└───────────────────────────┬────────────────────────────┘
                            │ Bind IPC
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Shizuku Service                      │
│        (Elevated ADB / Shell Identity AIDL)            │
└───────────────────────────┬────────────────────────────┘
                            │ pm install-create
                            │ -d --bypass-low-target-sdk-block
                            ▼
┌────────────────────────────────────────────────────────┐
│               Android Package Manager                  │
│             (Bypasses targetSdk 24 Floor)              │
└────────────────────────────────────────────────────────┘
```

### Companion App UI Workflow

```
+------------------------------------------+
|  ApkRevive Companion               [⚙]   |
+------------------------------------------+
|  Shizuku Status: [🟢 Connected (v13.5.4)]|
|                                          |
|  Select Package to Install:              |
|  [ 📁 /Download/spaceace.revived.apk   ] |
|                                          |
|  Package Details:                        |
|  • Name: com.retro.spaceace              |
|  • targetSdk: 22 (Bypass Required)       |
|  • 64-bit 16KB Aligned: YES              |
|  • 60Hz Physics Lock: ACTIVE             |
|                                          |
|  [⚡ Install with Low-SDK Bypass (Shizuku)]|
|                                          |
|  Progress: [====================] 100%   |
|  Status: Successfully installed!         |
+------------------------------------------+
```

---

## Canary Verification Suite

ApkRevive includes 8 pairs of control and failing canary test vectors (16 APKs total) validating every failure mode:

| # | Canary Name | Focus Area | Failure Trigger Tested |
|---|---|---|---|
| 1 | `canary_install_floor` | Package Manager | targetSdk below device install floor (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`) |
| 2 | `canary_apache_http` | Java Runtime | Missing `org.apache.http.legacy` library on API 28+ |
| 3 | `canary_page_size` | Native Linker | 4KB ELF `p_align` on 16KB memory page kernel |
| 4 | `canary_physics_tick` | Surface / Render | Fixed physics timestep failure on >60Hz high-refresh displays |
| 5 | `canary_aspect_ratio` | Window Manager | Fixed 4:3 / 16:9 pillarboxing on modern widescreen devices |
| 6 | `canary_bionic_greylist` | Bionic Linker | Direct dependency on private system `.so` (e.g. `libgui.so`) |
| 7 | `canary_has_code` | ART / Zygote | `hasCode="false"` preventing bytecode execution |
| 8 | `canary_obb_version` | Storage / Expansion | OBB version code mismatch or ahead of APK versionCode |

For the complete OS and device support matrix, refresh rate behaviors, and hardware vs. emulator details, see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

---

## Known Limitations

- **Native ELF `p_align` Not Rewritten:** ApkRevive aligns native libraries within the ZIP archive container to 16KB boundaries, but it **does not rewrite compiled ELF binary segments or `p_align` fields**. On Android 15 with 16KB page size kernels, 64-bit binaries built with 4KB segment alignment cannot load and will trigger a fatal `RED` verdict. On Android 16 (API 36+), ApkRevive injects `android:pageSizeCompat="enabled"` to leverage the OS-level emulator mode.
- **Signature Invalidation & Data Loss:** Re-signing an APK with a new keystore alters its cryptographic certificate digest. Installing a revived APK over an existing installation causes an `INSTALL_FAILED_UPDATE_INCOMPATIBLE` error. **The original application must be uninstalled first, resulting in the permanent loss of existing user data, local app preferences, and game saves.**
- **Self-Signature Checks & Anti-Tamper:** Applications that perform runtime self-signature checks or use proprietary DRM/licensing mechanisms will detect package re-signing and fail to boot.
- **Dalvik Multi-Dex Limitations:** Injected content provider shims placed in secondary DEX files (`classes2.dex`) require modern ART runtimes (Android 5.0+ / API 21+). Legacy Dalvik runtimes do not load secondary DEX files prior to ContentProvider initialization.
- **Split APKs / App Bundles:** ApkRevive currently expects single, monolithic APK files. Split APK sets (Android App Bundles) are not supported.

---

## Legal Notice & Disclaimer

> [!CAUTION]
> **Only modify applications you have legal rights to modify.**
> Modifying, decompiling, patching, and re-signing third-party application binaries may infringe on copyright laws, software licenses, and application terms of service. ApkRevive is provided strictly for educational research, legitimate interoperability analysis, and archival preservation of software for which you hold appropriate rights or explicit owner authorization. The developers and contributors of ApkRevive disclaim all liability for unlawful or unauthorized usage.

---

## Running Tests

Execute the full test suite with Python `unittest` or `pytest`:
```bash
python -m unittest discover -s tests
```

---

## License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
