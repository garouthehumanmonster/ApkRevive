# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-21

### Added
- **Ruthless Two-Command CLI:** Streamlined CLI surface to two clean commands: `apkrevive inspect <apk>` and `apkrevive patch <apk> -o <out.apk>`.
- **Live Emulator E2E Verification Harness (`scripts/verify_emulator_e2e.py`):** Compiles a real API 19 Canary APK using local Android SDK build tools, proves it is blocked on Android 14–16, patches it, and proves it installs and runs live without crashing.
- **DEX Compatibility Shim (`com.apkrevive.shim.ApkReviveInitProvider`):** Lightweight, deterministic ContentProvider doing two verified compatibility calls in `onCreate()`:
  - `StrictMode.disableDeathOnFileUriExposure()` + `StrictMode.ThreadPolicy.LAX` / `StrictMode.VmPolicy.LAX` to prevent API 24+ file URI and main-thread I/O crashes.
  - `dalvik.system.VMRuntime.getRuntime().setHiddenApiExemptions(new String[]{"L"})` via meta-reflection to unlock hidden internal APIs.
  - Injected as `classes{max_N + 1}.dex` with dynamic authority `${packageName}.apkrevive.init` and `initOrder="2147483647"`.
- **Hardened AXML Surgeon (`axml.py`):**
  - Target SDK Floor: Automatically bumps `targetSdkVersion` to 24 (when `< 24`, or via `--bump-target-sdk`), creating `<uses-sdk>` if missing.
  - Apache HTTP Legacy: Injects `<uses-library android:name="org.apache.http.legacy" android:required="false" />` under `<application>`.
  - Application Attributes: Sets `android:pageSizeCompat="enabled"`, `android:requestLegacyExternalStorage="true"`, `android:usesCleartextTraffic="true"`, `android:resizeableActivity="true"`, and `android:hasCode="true"`.
  - Component `android:exported` Safety: Automatically enforces `android:exported="true"` on components with `<intent-filter>` for Android 12+ (API 31+) safety.
  - Split-Lock Stripping: Purges `isSplitRequired`, `requiredSplitTypes`, and split install metadata.
  - Strict ascending numerical resource-ID attribute order for `ResXMLTree` binary search compliance.
- **16KB ZipAlign & V2/V3 Signing:**
  - 16KB boundary zipalignment for `.so` and `resources.arsc` using Android tag `0xD935`.
  - APK Signing Block 4KB alignment with Verity Padding Block (`0x42726577`).

### Removed
- **Fake `.so` Stubs:** Deleted all synthetic stub shared libraries (`libkrypto.so`, `libkssl.so`, etc.) returning NULL/zero, and removed `apkrevive/stubs/`.
- **Enterprise Fluff & Bloat:** Removed web triage hub, companion app, split mergers, SARIF telemetry generators, and ASCII diff visualizers.
