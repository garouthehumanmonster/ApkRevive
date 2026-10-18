# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0a1] - 2026-10-18

### Added
- **AXML Surgeon Round-Trip Testing:** Hermetic byte-for-byte serialization tests (`test_axml_correctness.py`) ensuring non-mutated manifests serialize identically to original inputs.
- **Fail-Closed ELF Alignment on Android 16+:** Triage now returns a strict `RED` verdict (`UNFIXABLE_ELF_SEGMENT_MISALIGNMENT`) when 4KB-aligned 64-bit native libraries cannot safely run on API 36+ 16KB page-size devices.
- **Post-Revive Certificate Verification:** `verify_apk_certs` runs `apksigner verify --print-certs` (with fallback to internal ASN.1 certificate parser) after every modernization run.
- **New Triage Detection Passes & Canaries (Phase 3):**
  - `WARN_HIDDEN_API_REFLECTION`: Detects restricted grey/dark-list reflection vectors.
  - `WARN_GLES1_DEPRECATED`: Flags legacy OpenGL ES 1.x dependencies.
  - `WARN_DEAD_SDKS`: Detects obsolete SDKs (Google LVL, Maps v1, legacy in-app billing, defunct ad networks).
  - `WARN_TEXTREL`: Detects legacy native libraries containing `DT_TEXTREL`.
  - `WARN_CLEARTEXT` / `WARN_LEGACY_TLS`: Flags unencrypted HTTP and deprecated TLS protocols.
  - `WARN_SCOPED_STORAGE_OBB`: Warns on legacy external storage assumptions on Android 11+ (API 30+).
- **Corpus & Golden Triage Suite (Phase 4):** Hermetic F-Droid corpus download tool (`scripts/download_corpus.py`) with SHA-256 verification, offline-safe execution, and golden-file triage regressions (`tests/test_golden_triage.py`).
- **Android Companion Security Hardening (Phase 5 & 7):**
  - Privileged shell installation fallback via `Shizuku.newProcess` with `--bypass-low-target-sdk-block` on Android 14+ (API 34+).
  - Centralized reflection handler `invokeShizukuNewProcess` with loud `IllegalStateException` on missing private API and R8/ProGuard keep rule (`app/proguard-rules.pro`).
  - Positional shell invocation (`sh -c 'mkdir -p "$1" && cat > "$2"'`) for OBB delivery with atomic `.part` staging, `mv` on success, `rm` cleanup on failure, and byte-count verification.
  - Multi-user storage support (`resolveObbDestinationPath`) supporting non-zero user IDs (e.g. work profiles).
- **Documentation:** Added `docs/DEVICE_TESTING.md` (multi-API test protocol and matrix) and `docs/EMULATOR_16KB.md` (16KB Android 15+ emulator guide).

### Changed
- **Companion App Keystore Migration Notice:** Companion APKs for v0.5.0a1 are signed with a distinct keystore compared to v0.4.0. Upgrading from v0.4.0 requires an explicit uninstall of the existing companion app first (`adb uninstall com.apkrevive`).
- Aligned `mypy` `python_version = "3.9"` with `requires-python = ">=3.9"` in `pyproject.toml`.
- Expanded CI matrix to test Python 3.9 and 3.13 on `ubuntu-latest`.

## [0.4.0] - 2026-10-17

### Added
- In-memory AXML Surgeon Hardening (`axml.py`): Enforced ascending attribute resource-ID sorting invariant for `libandroidfw` binary search compliance; safe string pool style table appending (`stylesStart` shift and 4-byte padding preservation); split-lock stripping.
- Bytecode Shim & Standalone Install: Dynamic `<provider>` authority (`${packageName}.apkrevive.init`), `initOrder=2147483647`, and ART runtime compatibility hooks (reflection `StrictMode.disableDeathOnFileUriExposure()`, `ThreadPolicy.permitAll()`, and `ApkReviveShim` uncaught exception handler).
- Standalone Install Pipeline: `--bump-target-sdk <int>` and `--standalone-install` flags with dangerous permissions triage warning (`WARN_RUNTIME_PERMISSIONS_ON_BUMP`).
- Split APK Merger (`split_merger.py`): Native libraries synchronized as `ZIP_STORED` with `extractNativeLibs="false"` and 16KB ZipAlign; secondary `resources.arsc` split detection emitting `WARN_SPLIT_RESOURCE_TABLE_MERGE`.
- APK Signing Block 4KB Verity Padding: Added `verify_signing_block_padding()` verifying block `0x42726577` and Central Directory 4096-byte alignment.
- Audits and documentation organized into `docs/audits/AUDIT_01.md`, `AUDIT_02.md`, and `AUDIT_03.md`.
- `apkrevive/core/elf16k.py`: Truthful 3-state 16KB ELF page-size verification (`ALIGNED`, `COMPAT_ONLY`, `UNSAFE`).
- `apkrevive/security/zip_guard.py`: Zero-trust Zip Slip prevention, null byte rejection, symlink blocking, and decompression bomb guard.
- `apkrevive/cli/`: Modularized CLI architecture with `diff`, `tui`, and SARIF v2.1.0 telemetry serializers.
- `apkrevive-android`: `Cancelled` and `AwaitingInstaller` lifecycle states in `ReviveJobState` and `ApkReviveViewModel`.
- `web/`: Client-side drag-and-drop APK Triage Hub with JavaScript 16KB inspector verified against Python implementation (`tests/test_parity_web_elf16k.py`).
- Strict `"simulated": true` schema field on all simulated canary receipts, preventing simulated runs from backing hardware claims.

### Changed
- Replaced unsafe in-place ELF segment header rewrites with truthful compatibility mode injection (`android:pageSizeCompat="enabled"`).
- Aligned documentation, README verified capabilities matrix, and AVD status records with real hardware receipts.
- Expanded test suite to 226 passing tests with 100% pass rate.

### Removed
- Purged fake Dalvik multi-dex trampoline (`dex_trampoline.py`).

## [0.3.3-alpha] - 2026-10-15

### Added
- Repository hygiene infrastructure: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.
- Dynamic single version source linking `pyproject.toml` and `apkrevive --version`.
- Comprehensive read-only audit reports in `docs/audits/`.
- Known Limitations and Legal Disclaimer sections in `README.md`.

### Changed
- Relabeled project status from "production-grade" to **Alpha**.
- Documented explicit boundary that ELF `p_align` rewriting is unsupported (read-only audit, Android 16 manifest flag).

## [3.2.0] - 2026-10-12
- Initial implementation of in-memory AXML Surgeon.
- Added 16KB ZIP boundary alignment for uncompressed native libraries.
- Added Shizuku-powered Android companion app (`apkrevive-android`).
- Added 8 canary test pairs in `canaries/`.
