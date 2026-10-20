# ApkRevive Engineering Roadmap

This document outlines the prioritized engineering roadmap for ApkRevive across upcoming release cycles. Features are prioritized by operational necessity and backed by strict verification discipline.

---

## Current Release: v0.5.0a1 (Alpha)
- [x] Initial release & unified repository packaging.
- [x] Structured receipt schema (`scripts/make_receipt.py`) and dynamic verification engine.
- [x] 35-APK legacy compatibility survey harness (`scripts/survey.py`) and API 37 16KB emulator evidence.
- [x] Hardened supply chain: Dependabot, CodeQL static analysis, pip-audit, action commit SHA pinning, Sigstore build provenance attestations.
- [x] Authoritative JSON output schemas (`docs/SCHEMA.md`, `schema_version: "1.0.0"`).
- [x] Explicit operational limits documentation (`docs/LIMITS.md`).

---

## Near-Term: v0.5.1 – v0.5.3 (Hardening & Hardware Evidence)

### 1. Physical ARM64 16KB Hardware Execution
- **Objective**: Collect and commit non-simulated receipts from physical ARM64 hardware (e.g. Pixel 8 / Pixel 9 running Android 15 with 16KB kernel enabled via Developer Options).
- **Target**: Validate whether real-world ARM64 native `.so` binaries trigger `NativeLibraryHelper` page-size backcompat identically to x86_64 emulators.

### 2. Android 16 (API 36) & Android 17 (API 37) QPR Tracking
- **Objective**: Validate platform behavior changes across Android 16 Quarterly Platform Releases (QPR) and Android 17 previews.
- **Target**: Confirm `android:pageSizeCompat="enabled"` manifest injection behavior as platform flags evolve.

### 3. Display Refresh Rate & Notch/Cutout Emulation
- **Objective**: Develop automated test rigs for variable refresh rate switching (60Hz / 90Hz / 120Hz) and display cutout letterboxing on physical panels.

---

## Medium-Term: v0.6.0 (Companion App & DEX Optimization)

### 1. Wireless Shizuku & Rootless Direct Pairing
- **Objective**: Enable direct wireless ADB pairing within `apkrevive-android` for devices where Shizuku is not running as a persistent background daemon.
- **Target**: One-tap pairing via Android 11+ Wireless Debugging service.

### 2. Pre-emptive Runtime Permission Grant Interface
- **Objective**: For APKs modernized with `--bump-target-sdk`, generate a helper UI or ADB script to batch-grant dangerous permissions declared in the manifest, eliminating runtime crashes caused by install-time expectation mismatch.

### 3. Secondary DEX & Multi-Split Archive Consolidation
- **Objective**: Enhance `split_merger.py` to optimize resource table deduplication across multi-split APK architectures without invoking heavyweight external toolchains.

---

## Long-Term: v1.0.0 (General Availability & Archival Preservation)

### 1. Continuous Archival Corpus Crawler
- **Objective**: Maintain an automated continuous integration test matrix running thousands of historical F-Droid and Internet Archive APKs against modern emulator images.

### 2. 32-Bit Translation Layer Interoperability
- **Objective**: Integrate with existing ARM32-on-ARM64 translation layers (such as Tango or Houdini/libndk_translation wrappers) to allow 32-bit legacy games to run on 64-bit-only hardware where feasible.

### 3. Reproducible Build Telemetry
- **Objective**: Achieve bit-for-bit reproducible packaging across `apkrevive revive` invocations when provided with deterministic timestamps and key inputs.
