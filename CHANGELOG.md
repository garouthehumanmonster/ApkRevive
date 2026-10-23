# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-10-23

### Fixed
- **16KB Compatibility AXML Type Safety (F-17)**:
  - Corrected `android:pageSizeCompat` binary serialization to emit `TYPE_INT_DEC` (`0x10`) with integer enum payload `32` (`0x20`) for `"enabled"`, ensuring modern Android 15/16 runtimes activate 16KB compat mode.
- **Aspect Ratio Float Serialization (F-19)**:
  - Corrected `android:maxAspectRatio` serialization to emit IEEE float binary payload (`TYPE_FLOAT`, `0x04`), preventing Android `TypedArray.getFloat()` fallback to `0.0f`.
- **Contiguous Multidex Sequencing (F-20)**:
  - Refactored `get_next_multidex_name` to allocate the lowest missing sequential index (filling holes such as `classes2.dex`), ensuring compatibility with ART's sequential `DexPathList` loader.

### Removed
- **Dead Code Pruning (F-18 / Ponytail Audit)**:
  - Removed 134 lines of dead and unreferenced code in `apkrevive/core/axml.py` (`append_string_to_pool` and `strip_split_locks`).

## [0.5.0] - 2026-10-22

### Added
- **Unified Release Versioning & Schemas:**
  - Unified package version `0.5.0` across `pyproject.toml`, `apkrevive/__init__.py`, and `SECURITY.md`.
  - Comprehensive, authoritative output schemas documented in `docs/SCHEMA.md` covering `inspect`, `triage`, `patch`, `verify`, `diff`, `doctor`, and verification receipts.
- **Toolchain Doctor (`apkrevive doctor`):**
  - Host runtime environment diagnostic engine verifying JDK binaries (`javac`, `keytool`) and Android SDK build/platform tools (`apksigner`, `aapt2`, `d8`, `adb`).
  - Terminal table formatting and machine-readable JSON output (`--json`) with remediation install hints.
- **Deep Binary Diff Engine (`apkrevive diff`):**
  - Structural comparison across AndroidManifest.xml, ELF 16KB segment alignment, DEX class expansion, APK Signing Block, and container entry deltas.
  - SARIF 2.1.0 telemetry output (`--sarif`) for GitHub Code Scanning and CI/CD security pipelines.
- **Verification Receipt & Survey Tooling:**
  - `scripts/make_receipt.py`: Generates structured verification receipts from target APKs with cryptographic hashing (SHA-256, SHA-1, MD5) and post-patch container validation.
  - `scripts/survey.py`: Directory-wide legacy APK compatibility survey runner and triage aggregator producing formatted summary tables and JSON breakdowns.
- **Container Verification & Alignment Hardening:**
  - Enforced 4KB alignment on Central Directory entries and APK Signing Block verity padding (`0x42726577`).
  - Support for unsigned container verification semantics (`is_unsigned=True`) for `--no-sign` workflows.
  - Dry-run emulator receipts and enhanced 16KB emulator verification harness.

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
