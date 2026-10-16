# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-16

### Added
- `apkrevive/core/elf16k.py`: Truthful 3-state 16KB ELF page-size verification (`ALIGNED`, `COMPAT_ONLY`, `UNSAFE`).
- `apkrevive/security/zip_guard.py`: Zero-trust Zip Slip prevention, null byte rejection, symlink blocking, and decompression bomb guard.
- `apkrevive/cli/`: Modularized CLI architecture with `diff`, `tui`, and SARIF v2.1.0 telemetry serializers.
- `apkrevive-android`: `Cancelled` and `AwaitingInstaller` lifecycle states in `ReviveJobState` and `ApkReviveViewModel`.
- `web/`: Client-side drag-and-drop APK Triage Hub with JavaScript 16KB inspector verified against Python implementation (`tests/test_parity_web_elf16k.py`).
- Strict `"simulated": true` schema field on all simulated canary receipts, preventing simulated runs from backing hardware claims.

### Changed
- Replaced unsafe in-place ELF segment header rewrites with truthful compatibility mode injection (`android:pageSizeCompat="enabled"`).
- Aligned documentation, README verified capabilities matrix, and AVD status records with real hardware receipts.
- Expanded test suite to 218 passing tests with 100% pass rate across Linux, macOS, and Windows.

### Removed
- Purged fake Dalvik multi-dex trampoline (`dex_trampoline.py`).

## [0.3.3-alpha] - 2026-10-15

### Added
- Repository hygiene infrastructure: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.
- Dynamic single version source linking `pyproject.toml` and `apkrevive --version`.
- Comprehensive read-only audit report in `AUDIT.md`.
- Known Limitations and Legal Disclaimer sections in `README.md`.

### Changed
- Relabeled project status from "production-grade" to **Alpha**.
- Documented explicit boundary that ELF `p_align` rewriting is unsupported (read-only audit, Android 16 manifest flag).

## [3.2.0] - 2026-10-12
- Initial implementation of in-memory AXML Surgeon.
- Added 16KB ZIP boundary alignment for uncompressed native libraries.
- Added Shizuku-powered Android companion app (`apkrevive-android`).
- Added 8 canary test pairs in `canaries/`.
