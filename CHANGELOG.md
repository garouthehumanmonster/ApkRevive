# Changelog

All notable changes to ApkRevive will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.0-alpha] - 2026-10-14

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
