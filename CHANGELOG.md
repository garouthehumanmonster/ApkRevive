# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
