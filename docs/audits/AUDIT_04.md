# Comprehensive Pre-Remediation Technical Audit: ApkRevive Modernizer Engine (v0.5.0a1)

**Date:** 2026-10-20  
**Commit:** `7b84647` (tag `v0.5.0a1`)  
**Auditor:** Senior Android Tooling & Systems Engineer  
**Scope:** Full codebase audit covering Python core/CLI (`/apkrevive`), Android Kotlin companion app (`/apkrevive-android`), verification canaries (`/canaries`), tests (`/tests`), and documentation.

---

## 1. Executive Summary & Baseline State

ApkRevive diagnoses, modernizes, and installs legacy Android APKs targeting API levels 3 through 28 onto modern Android runtimes (API 34–36+, Android 14/15/16 QPR) with 16KB kernel page sizes, targetSdk install floors (API 34 minSdk 23, API 35 minSdk 24), and modern display aspect ratios.

This audit establishes the baseline verification state prior to remediating 29 verified engineering defects across the container aligner, AXML surgeon, CLI reliability, test suites, split merger, packaging, Android companion, web hub, and hygiene.

### Baseline Verification Status (Commit `7b84647`)
- **Unit / Integration Tests:** 308 passed, 33 skipped, 1 failed (342 total) in 10.12s (`pytest tests/`)
- **Python Test Coverage:** 86% line/branch coverage (satisfies `fail_under = 85` gate in `pyproject.toml`)
- **Known Test Failure:** `tests/test_cli.py::test_revive_succeeds_on_red_with_force` fails when host lacks `keytool`/Java SDK (`AssertionError: 1 != 4`).
- **Skipped Tests (33):** Integration tests requiring Android SDK, ADB, aapt2, keytool, or live internet corpus downloads.
- **Linting & Types:** `ruff check .` clean; `mypy apkrevive --ignore-missing-imports` clean.

---

## 2. Catalog of 29 Verified Defects Scheduled for Remediation

### Phase 1 — ZIP Aligner Correctness (`apkrevive/core/align.py`)
1. **1.1 EOCD Comment Truncation:** `eocd_record = bytearray(in_buf[eocd_pos : eocd_pos + 22])` truncated trailing archive comments.
2. **1.2 LFH Extra Field Destruction:** Overwrote extra fields (`0x7075` Info-ZIP Unicode, NTFS timestamps, Zip64) instead of merging with `0xD935` alignment padding.
3. **1.3 Data Descriptors Dropped (GP bit 3):** Dropped 12/16/20/24-byte trailing streaming descriptors when `flags & 0x0008`.
4. **1.4 Silent Zip64 Corruption:** Zip64 archives (`0xFFFF` count, `0xFFFFFFFF` offsets/sizes, EOCD64 locator `PK\x06\x07`) were processed without Zip64 support, causing silent archive corruption.
5. **1.5 Verifier Broken Fail-Closed Invariant:** `verify_apk_alignment` silently broke out of loops on truncated entries and could return `{"aligned": True}` on truncated inputs.

### Phase 2 — AXML Surgeon Correctness (`apkrevive/core/axml.py`)
6. **2.1 Dangling String Index (S0):** Type `0x03` attribute with `raw_value is None` re-emitted `a.data` (old pool index pointing to arbitrary strings).
7. **2.2 String Pool Premature Freeze:** String pool was frozen before node serialization, allowing pool mutations after emission.
8. **2.3 Unknown Chunk Dropping:** Dropped unsupported chunks (e.g. CDATA `0x0104`) silently instead of failing closed with `UnsupportedAxmlChunk`.
9. **2.4 Missing Namespace Declarations:** Hardcoded single Android namespace, discarding `xmlns:tools` and OEM namespaces.
10. **2.5 Declared File Size Ignored:** XML header `file_size` was parsed but ignored, allowing out-of-bounds reads.
11. **2.6 Attribute Truncation Silent Break:** Truncated attribute lists broke cleanly instead of raising.
12. **2.7 Aspect Ratio Invariant Drift:** README claimed aspect ratio unlocked to 2.5, but restrictive existing values were preserved.
13. **2.8 Post-Condition Validation Missing:** Produced manifests lacked structural validation prior to emission.

### Phase 3 — CLI Reliability (`apkrevive/cli/__init__.py`)
14. **3.1 Silent Missing Shim:** Missing or corrupted `shim.dex` registered provider in manifest but omitted bytecode, causing runtime crash.
15. **3.2 Non-Atomic Pipeline Cleanup:** Failed repack/align/sign left partially-written output APKs on disk.
16. **3.3 Faulty `probe_cmd`:** Returned 0 even if no device was connected; dropped errors; duplicated `--json` argument.
17. **3.4 Missing Repack Integrity Invariants:** Repack loop did not assert entry count parity and manifest/DEX presence.

### Phase 4 — Test Suite Integrity (`tests/`)
18. **4.1 Host-Dependent Keytool Failure in CLI Tests:** Mocked signer and certificate verification in unit tests.
19. **4.2 Inappropriate `@pytest.mark.skipif` Usage:** Replaced fragile runtime skips with `@pytest.mark.integration` and `pyproject.toml` marker exclusion.
20. **4.3 Missing Regression Tests:** Comprehensive test coverage added for Phases 1-3.

### Phase 5 — Split Merger Correctness (`apkrevive/core/split_merger.py`)
21. **5.1 Incorrect Compression Modes:** Native libraries and resource tables compressed with Deflate instead of Stored.
22. **5.2 Fragile Base APK Detection:** Heuristic filename-based base APK detection failed on split APKs without `"base"` in name.
23. **5.3 Silent Resource Table Loss:** Dropped split resource tables silently without explicit `--allow-resource-table-loss` opt-in.
24. **5.4 Silent DEX Renumbering:** Multi-dex files renumbered without diagnostic warnings.
25. **5.5 Silent Colliding Entry Dropping:** Secondary split collisions dropped without user visibility.

### Phase 6 — Packaging, CI & Docs Truth
26. **6.1-6.6 CI & Docs Drift:** Double coverage gate (`--fail-under=80` vs `85`), disabled Dependabot (`limit: 0`), missing `python -m apkrevive`, outdated canary count in README, missing limits and architectural invariant documents.

### Phase 7 — Android Companion (`apkrevive-android/`)
27. **7.1-7.5 Android Hardening:** Missing Shizuku package visibility in Android 11+ `<queries>`, enabled backup risk, missing runtime `POST_NOTIFICATIONS` permission check on API 33+, fragile reflection on `INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK`.

### Phase 8 — Web Hub (`web/app.js`)
28. **8.1-8.2 Web Hub Security & Parity:** Unescaped model variables in DOM (DOM-XSS), hardcoded web triage rules drifted from Python source of truth.

### Phase 9 — Engineering Hygiene
29. **9.1-9.5 Hygiene:** Bare `except Exception: pass` in signer, missing `Elf16kStatus.EXEMPT` for 32-bit binaries, loose path traversal check in `zip_guard.py`, leftover debug comments, version string drift in `models.py`.
