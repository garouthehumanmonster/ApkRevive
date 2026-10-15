# ApkRevive Audit Report 2: Documentation vs. Code Mismatches & Behavioral Grounding

**Date:** 2026-10-15  
**Audit Scope:** Codebase (`apkrevive/`), tests (`tests/`), canaries (`canaries/`), docs (`docs/COMPATIBILITY.md`, `README.md`), and platform behavior rules.

---

## 1. Executive Summary

This second audit scrutinizes the behavioral accuracy of ApkRevive's triage logic, test canaries, documentation claims, and transform risk models against actual Android OS platform behavior.

A core philosophy of ApkRevive is to **retain the original legacy `targetSdkVersion`** (often API 3–22). Modern Android runtimes maintain extensive backward compatibility shims for applications with lower target SDKs. Consequently, applying warnings or transforms based solely on the host device API level without conditioning on `targetSdkVersion` produces false positives, unnecessary transforms, and inaccurate triage verdicts.

---

## 2. Docs-vs-Code & Behavioral Mismatches

### 2.1 TargetSdk vs. Device API Platform Behaviors
- **Cleartext HTTP Traffic:**
  - *Current Code:* `triage.py` emits `WARN_CLEARTEXT_LEGACY_TLS` if `target_sdk < 28 and uses_cleartext is None and not has_nsc`.
  - *Android Platform Reality:* Android 9 (API 28+) blocks cleartext HTTP by default **only for apps with `targetSdkVersion >= 28`** ([Android 9 Behavior Changes](https://developer.android.com/about/versions/pie/android-9.0-changes-28#opt-out-cleartext)). For apps with `targetSdkVersion < 28`, cleartext HTTP remains enabled by default even on Android 14/15/16. The current check was inverted.
- **Apache HTTP Legacy (`org.apache.http.legacy`):**
  - *Current Code:* `triage.py` only triggers `INJECT_USES_LIBRARY_APACHE_HTTP` when `target_sdk == 28`.
  - *Android Platform Reality:* `org.apache.http.legacy` was removed from the bootclasspath starting on API 28, but the platform automatically injects it into the class loader for apps targeting API <= 27 ([Apache HTTP Legacy Documentation](https://developer.android.com/about/versions/pie/android-9.0-changes-28#apache-p)). Apps targeting <= 27 do not need `<uses-library>`, while apps targeting >= 28 do.
- **Scoped Storage & OBB:**
  - *Current Code:* Emits warning for any app on API 30+ requesting external storage.
  - *Android Platform Reality:* Android 10/11 enforced scoped storage primarily for apps targeting API 29/30+. Apps targeting < 29 running on Android 10+ operate under compatibility modes with raw filesystem access still permitted for app-specific and external paths, though raw access to `/sdcard/Android/data` and `/sdcard/Android/obb` is strictly blocked on Android 11+ regardless of targetSdk.

### 2.2 Cleartext Detection via String Grep
- *Current Code:* `extractor.py` scans `classes*.dex` byte streams for `"http://"`.
- *Issue:* String scanning flags XML namespace definitions (`http://schemas.android.com/...`), documentation references, and dead metadata strings, resulting in rampant false positive cleartext warnings.
- *Fix:* Cleartext capability must be evaluated from `android:usesCleartextTraffic` and `android:networkSecurityConfig` in `AndroidManifest.xml` and manifest resources. Legacy TLS tokens (SSLv3, TLS 1.0, TLS 1.1) must be separated into a distinct `WARN_LEGACY_TLS` signal.

### 2.3 Canary Grounding & Verification
- *Current Code:* `test_canaries.py` asserts triage outputs on synthetic metadata, but fails to record cryptographic build hashes of canary APKs or prove failure/success deltas across real device environments.
- *Fix:* `canary_apache_http` failing variant must target API 28 to actually trigger `ClassNotFoundException` without the library. Every canary's build hash must be persistently tracked.

### 2.4 Empirical Evidence vs. Theoretical Matrices
- *Current Code:* `docs/COMPATIBILITY.md` presents theoretical compatibility tables.
- *Issue:* Hard rules mandate that no claim be made without a test or recorded result.
- *Fix:* Replace static matrices with data-driven result JSON files in `results/*.json`. Add a generator script (`scripts/generate_matrix.py` or `apkrevive/tools/generate_matrix.py`). Any configuration lacking a verified JSON receipt must be displayed as `NOT RUN`.

### 2.5 Uncontrolled Risky Transforms
- *Current Code:* `EXPAND_ASPECT_RATIO` (`resizeableActivity="true"`) is injected automatically whenever `is_non_resizeable` is detected on a widescreen device.
- *Issue:* Forcing activity resizing on legacy games with fixed aspect ratio math frequently breaks touch coordinate mapping, HUD scaling, and 2D canvas projections.
- *Fix:* Make resizing opt-in via `--enable-resizable`. Assign risk levels (`LOW`, `MEDIUM`, `HIGH`) to every required transform.

### 2.6 Shim Provenance & Verification
- *Current Code:* `doctor` checks `shim.dex` against a hardcoded hash, but does not verify or rebuild from `ApkReviveInitProvider.java` source.
- *Issue:* Users cannot verify that `shim.dex` is clean and free of telemetry or spyware.
- *Fix:* Wire `doctor` to verify `ApkReviveInitProvider.java` source hash and provide build verification. Add clear telemetry/security disclosures in `SECURITY.md`.

### 2.7 Unverified `pageSizeCompat` Claims
- *Current Code:* `evaluate_triage` recommends `PAGE_SIZE_COMPAT` for 16KB kernels on Android 16 (API 36+) as an automatic `YELLOW` verdict.
- *Issue:* Android 16 16KB emulation mode has not been verified on real or emulated target hardware in this repo.
- *Fix:* Mark verdict and transforms as `(UNVERIFIED)` at runtime unless a passing result exists in `results/` for an API 36 16KB environment.

### 2.8 Versioning and Housekeeping
- *Current Code:* Package version is set to `3.3.0` despite being an Alpha release.
- *Fix:* Downgrade versioning to a `0.x` scheme (e.g. `0.3.3`) to honestly reflect Alpha status across `pyproject.toml`, CLI `--version`, and documentation. Sync project tree in `README.md`.

---

## 3. Action Items Mapping

| Item # | Focus Area | Responsible Module / Action |
|:---:|---|---|
| **1** | Behavior Table | Create `apkrevive/core/behavior_changes.py`, map `(targetSdk, deviceApi)`, drive triage, test per row. |
| **2** | Cleartext / TLS Detection | Parse manifest `usesCleartextTraffic` & `networkSecurityConfig`, remove `"http://"` grep, split warnings. |
| **3** | Canary Realism & Hashes | Fix `canary_apache_http` targetSdk=28, record all canary build hashes in `canaries/canary_hashes.json`. |
| **4** | Empirical Evidence Matrix | Create `results/*.json`, add matrix generator script, mark unrun cells `NOT RUN`. |
| **5** | Risky Transforms | Add `--enable-resizable` opt-in flag, add risk level (`LOW`/`MEDIUM`/`HIGH`) to transform reports. |
| **6** | Shim Provenance | Connect `doctor` to source hash of `ApkReviveInitProvider.java`, update `SECURITY.md`. |
| **7** | `pageSizeCompat` Guard | Print `(UNVERIFIED)` on API 36 16KB verdicts unless proven in `results/*.json`. |
| **8** | Housekeeping & 0.x | Sync tree, change version to `0.3.3` in `pyproject.toml`, add GitHub description/topics checklist. |
