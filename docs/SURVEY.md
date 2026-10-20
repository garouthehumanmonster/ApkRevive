# ApkRevive Compatibility Survey Report

> [!IMPORTANT]
> **Verification Notice**: Empirical survey results generated from real byte-verified F-Droid archive APKs.
> **Unverified Notice**: arm64 physical devices and variable refresh rate / cutout hardware are strictly **UNVERIFIED**. All measured results below were obtained on headless Android emulator environments.

## Executive Summary

A comprehensive compatibility survey was executed across **35 legacy open-source Android applications** (targetSdk < 24) resolved from the F-Droid archive index. The test evaluates the entire modernization lifecycle from installation gating to runtime execution on modern Android kernels (including 16KB page size).

### Measured Headline Metrics (API 37 16KB Kernel)

- **Device Model**: `sdk_gphone16k_x86_64`
- **OS Version**: Android 16/17 Preview (API 37)
- **Kernel Page Size**: 16384 bytes (16KB)
- **Device ABI**: `x86_64`
- **Total Packages Evaluated**: 35

| Lifecycle Stage | Succeeded | Failed / Blocked | Success Rate |
| :--- | :--- | :--- | :--- |
| **1. Direct Install** (`adb install -r`) | 1 | 34 | 2% |
| **2. Bypass Install** (`--bypass-low-target-sdk-block`) | 21 | 14 | 60% |
| **3. Revive + Install** (`apkrevive revive` + `-r -g`) | 21 | 14 | 60% |
| **4. Liveness Check** (Launch + 8s Polling) | 14 Alive | 2 Crash, 5 Dead, 14 Skipped | 40% (66% of installable) |

---

## Failure Category Classification

Every failure encountered during direct installation, bypass installation, and post-revival runtime execution was categorized into mutually exclusive classifications:

- **ABI Incompatibility (`ABI`)**: 14 (40%)
  - *Cause*: Applications containing only 32-bit ARM native binaries (`armeabi`, `armeabi-v7a`) on 64-bit-only emulator architectures without translation layers. The Android package manager immediately rejects installation with `INSTALL_FAILED_NO_MATCHING_ABIS`.
- **Clean Execution / No Failure (`NONE`)**: 14 (40%)
  - *Result*: Successfully revived, installed, launched into foreground, polled alive for >= 8s, with zero crash buffer events. Visual verification screenshots captured in `build/survey_runs/`.
- **Runtime Crash (`CRASH`)**: 2 (5%)
  - *Cause*: Unhandled runtime exceptions in legacy code (e.g., deprecated Camera hardware API calls or audio manager crashes).
- **Non-Resumed Activity / Service (`OTHER`)**: 5 (14%)
  - *Cause*: Applications that finished their main activity immediately upon launch (e.g. background service helpers, lockscreen widgets, or finish-on-launch utilities).
- **Private Library Greylist (`GREYLIST`)**: 0 (0%)
- **Legacy GLES 1.x (`GLES1`)**: 0 (0%)
- **Dead / Sunset SDKs (`DEAD_SDK`)**: 0 (0%)
- **Installer Floor Blocked (`INSTALL_FLOOR_BLOCKED`)**: 0 (0%)

---

## TargetSdk Bump vs. Bypass Comparison

Modern Android OS releases (Android 14+ / API 34+) enforce an installation floor (`minInstallFloor = 24`), preventing legacy APKs from installing by default.

1. **The ADB Bypass Flag (`--bypass-low-target-sdk-block`)**:
   - Bypasses the installer gate only.
   - Leaves runtime behavior changes unaddressed (e.g., 16KB page alignment on 64-bit kernels, notification runtime permissions, background restrictions).
   - Cannot be applied via standard system installers or third-party package managers without root/ADB access.
2. **ApkRevive TargetSdk Modernization (`apkrevive revive`)**:
   - Safely updates manifest headers, injects backwards-compatibility shims (e.g. Apache HTTP legacy, 60Hz display mode lock, aspect ratio overrides).
   - Pre-aligns and signs the package to comply with modern v2/v3 signature and 16KB page alignment requirements.
   - Enables direct installation via standard package managers without developer-mode bypass flags.

---

## Comprehensive Per-Application Survey Ledger

Full tabular ledger of all 35 evaluated packages from the F-Droid archive index:

| Package | targetSdk | ABIs | Direct | Bypass | Revive | Liveness | Classification | Cause / Note |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ch.hsr.eyecam` | 18 | `armeabi, armeabi-v7a` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `ch.nexuscomputing.android.osciprimeics` | 19 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `a2dp.Vol` | 19 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `acr.browser.barebones` | 19 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `akk.astro.droid.moonphase` | 18 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `android.androidVNC` | 4 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `atm.rocketguardian` | 25 | `arm64-v8a, armeabi, armeabi-v7a, x86, x86_64` | PASS | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `atm.starun.game` | 20 | `arm64-v8a, armeabi, armeabi-v7a, x86, x86_64` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `com.falconware.prestissimo` | 17 | `armeabi, armeabi-v7a` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `com.sgr_b2.compass` | 18 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `com.proch.practicehub` | 10 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `com.poinsart.votar` | 19 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `jp.sblo.pandora.aGrep` | 8 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `uobikiemukot.yaft` | 9 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `org.xapek.andiodine` | 16 | `armeabi, x86` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `org.dyndns.fules.ck` | 8 | `arm64-v8a, armeabi, armeabi-v7a, mips, mips64, x86, x86_64` | FAIL | PASS | PASS | **DEAD** | `OTHER` | Main activity finished on launch or service-only app |
| `com.termux` | 22 | `armeabi-v7a, x86` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `trikita.obsqr` | 19 | `armeabi, x86` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `ro.ui.pttdroid` | 18 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `com.roguetemple.hyperroid` | 11 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `org.mosspaper` | 21 | `arm64-v8a, armeabi, armeabi-v7a, mips, mips64, x86, x86_64` | FAIL | PASS | PASS | **DEAD** | `OTHER` | Main activity finished on launch or service-only app |
| `com.kvance.Nectroid` | 4 | `armeabi` | FAIL | FAIL | FAIL | **SKIPPED** | `ABI` | 32-bit native libraries incompatible with 64-bit device ABI |
| `net.syntaxblitz.plucklock` | 15 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `ryey.camcov` | 23 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `io.github.sanbeg.flashlight` | 10 | `pure-java` | FAIL | PASS | PASS | **CRASH** | `CRASH` | Runtime exception in crash buffer after foreground launch |
| `com.jwetherell.heart_rate_monitor` | 5 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `de.mangelow.balance` | 16 | `pure-java` | FAIL | PASS | PASS | **DEAD** | `OTHER` | Main activity finished on launch or service-only app |
| `org.billthefarmer.siggen` | 17 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `com.intrications.android.sharebrowser` | 17 | `pure-java` | FAIL | PASS | PASS | **DEAD** | `OTHER` | Main activity finished on launch or service-only app |
| `com.github.wakhub.tinyclock` | 21 | `pure-java` | FAIL | PASS | PASS | **DEAD** | `OTHER` | Main activity finished on launch or service-only app |
| `com.jakebasile.android.hearingsaver` | 8 | `pure-java` | FAIL | PASS | PASS | **CRASH** | `CRASH` | Runtime exception in crash buffer after foreground launch |
| `org.nick.cryptfs.passwdmanager` | 17 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `sk.madzik.android.logcatudp` | 4 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `com.gmail.jerickson314.sdscanner` | 19 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |
| `de.onyxbits.listmyapps` | 17 | `pure-java` | FAIL | PASS | PASS | **ALIVE** | `NONE` | Verified foreground execution; screencap captured |

---

## Verifiable Receipts and Reproducibility

All measurements above are linked to committed JSON test receipts:
- Survey Raw Results: `results/survey/survey_sdk_gphone16k_x86_64_api37_x86_64.json`
- Hardware / Emulator Receipt: `receipts/receipt_survey_sdk_gphone16k_x86_64_api37_x86_64.json`
- Manifest Specification: `tests/corpus/survey.json`
- Automated Reproduction Command:
  ```bash
  python scripts/survey.py --manifest tests/corpus/survey.json --max-apks 35
  ```
