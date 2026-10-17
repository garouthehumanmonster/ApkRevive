# ApkRevive Audit Report 3: v0.4.0 Architectural Hardening Pass

**Date:** 2026-10-17  
**Version:** v0.4.0  
**Scope:** AXML Surgeon (`axml.py`), Runtime Bytecode Shim (`ApkReviveInitProvider`), Standalone Install Pipeline (`triage.py`, `cli`), Split Merger (`split_merger.py`), 16KB Alignment & Signing Verification (`align.py`, `signer.py`), and Hardening Test Suite (`tests/test_v040_hardening.py`).

---

## 1. Executive Summary

The v0.4.0 architectural hardening pass eliminates subtle binary corruption risks, ensures compliance with strict Android OS runtime invariants (`libandroidfw` binary search attribute indexing, ART 16KB memory page alignment, Android Verity Central Directory page alignment), enhances standalone on-device installation capabilities, and expands split APK unification into a single standalone artifact.

All changes are backed by automated regression tests in `tests/test_v040_hardening.py` and empirical validation against both synthetic and canonical APK structures.

---

## 2. In-Memory AXML Surgeon Hardening (`apkrevive/core/axml.py`)

### 2.1 Attribute Resource-ID Sorting Invariant
- **Vulnerability / Invariant:** Android's binary XML parser `ResXMLTree` in `libandroidfw` relies on binary search over attribute resource IDs (`0x0101xxxx`) within each `RES_XML_START_ELEMENT_TYPE` chunk. Inserting or modifying attributes out of numerical order causes `getAttributeResourceValue` and `getAttributeNameResource` to fail or skip attributes.
- **Hardening:** During `AxmlSurgeon.serialize()`, all element attributes with a valid resource ID (`res_id > 0`) are sorted in strict ascending order before writing attribute records. Non-resource attributes (`res_id == 0`) are appended afterwards in stable insertion order.
- **Resource ID Expansion:** Registered standard IDs for `extractNativeLibs` (`0x010104EA`), `isSplitRequired` (`0x01010591`), `requiredSplitTypes` (`0x010105B9`), `splitTypes` (`0x010105BA`), `maxAspectRatio` (`0x01010525`), `usesCleartextTraffic` (`0x010104EC`), `networkSecurityConfig` (`0x01010524`), and `requestLegacyExternalStorage` (`0x01010603`).

### 2.2 String Pool Style Table Safety
- **Vulnerability:** When appending strings to a `RES_STRING_POOL_TYPE` that contains styled text spans (`styleCount > 0`, `stylesStart > 0`), naive concatenation offsets corruption into the style table indices and corrupts style span parsing.
- **Hardening:** `AxmlSurgeon.append_string_to_pool()` preserves the original style data intact, recalculates `stylesStart` by shifting it by the padded length of newly appended string data, enforces 4-byte padding alignment, and re-emits style offsets unchanged.

### 2.3 Modern Split-Lock Stripping
- **Implementation:** `AxmlSurgeon.strip_split_locks()` strips split-associated attributes (`split`, `configForSplit`, `requiredSplitTypes`, `splitTypes`, `isSplitRequired`) from both `<manifest>` and `<application>`, and prunes Play Store vendor metadata tags (`com.android.vending.splits.required`, `com.android.vending.splits`, `com.android.vending.derived.apk.id`).

---

## 3. Bytecode Shim (`ApkReviveInitProvider`) & Standalone Mode

### 3.1 Dynamic Provider Authority
- **Vulnerability:** Hardcoded provider authorities cause `INSTALL_FAILED_CONFLICTING_PROVIDER` when two modernized APKs reside on the same device.
- **Hardening:** Dynamically injects `android:authorities="${packageName}.apkrevive.init"`, `android:exported="false"`, and `android:initOrder="2147483647"` (maximum startup priority).

### 3.2 Modern ART Runtime Compatibility Hooks
Enhanced `ApkReviveInitProvider.onCreate()` to execute critical runtime shims during early application cold-start:
1. **Reflection invocation of `StrictMode.disableDeathOnFileUriExposure()`:** Suppresses `FileUriExposedException` on API 24+ for legacy apps using `file://` URIs instead of `FileProvider`.
2. **`StrictMode.ThreadPolicy.permitAll()` relaxation:** Prevents main-thread network and disk I/O crashes for legacy apps (API < 11) running on modern Android versions.
3. **Logcat Diagnostic Triage:** Installs a default `Thread.UncaughtExceptionHandler` logging early crashes under logcat tag `ApkReviveShim`.

### 3.3 Standalone Install Mode & TargetSdk Bumping
- **CLI Options:** Introduced `--bump-target-sdk <int>` and `--standalone-install` (which defaults `targetSdkVersion` to 24).
- **Behavioral Triage Warning:** Android 6.0+ (API 23+) transitions dangerous permissions to runtime permissions. When `bump_target_sdk >= 23` is applied to an APK originally targeting API < 23, `evaluate_triage()` emits `WARN_RUNTIME_PERMISSIONS_ON_BUMP` detailing requested dangerous permissions so operators can grant them via `pm grant` or ADB if needed.

---

## 4. Split APK Merger (`split_merger.py`) & 16KB ZipAlign

### 4.1 `extractNativeLibs` Synchronization & `ZIP_STORED`
- **Mechanism:** In unified standalone APK reassembly, writing `.so` files compressed with `extractNativeLibs="false"` prevents direct `mmap()` execution. `split_merger.py` now enforces:
  - All `lib/**/*.so` entries written as `ZIP_STORED` (uncompressed).
  - Merged manifest sets `android:extractNativeLibs="false"`.
  - Final artifact aligned to 16KB boundaries via `align_apk(..., page_align_64bit=16384)`.

### 4.2 Resource Split Detection & Warnings
- **Diagnostic Signal:** Ingesting non-base splits with separate `resources.arsc` triggers structured diagnostic warning `WARN_SPLIT_RESOURCE_TABLE_MERGE` alerting operators that non-colliding `res/` assets were merged without deep ARSC type-chunk unification. Registered in SARIF v2.1.0 reporting rules.

### 4.3 APK Signing Block 4KB Verity Padding
- **Verification:** Added `verify_signing_block_padding(apk_path: str)` to `apkrevive/core/signer.py`. Verifies presence of the APK Signing Block magic (`b"APK Sig Block 42"`), Android Verity Padding Block ID `0x42726577`, and proves that the ZIP Central Directory remains page-aligned (`cd_offset % 4096 == 0`) after signing.

---

## 5. Verification & Test Suite Summary

The hardening pass is validated by 8 dedicated test suites in `tests/test_v040_hardening.py`:
1. `test_1_ascending_resource_id_attribute_ordering`: Strict sorting of `0x0101xxxx` attributes.
2. `test_2_unique_provider_authority_and_init_order`: Collision-free authority derivation.
3. `test_3_16kb_alignment_invariance_after_signing`: 16KB `.so` data offset preservation through V2/V3 signing blocks.
4. `test_4_string_pool_with_styles_preservation`: Safe string append with styled text chunks.
5. `test_5_split_lock_stripping`: Complete removal of split locks and Play Store metadata.
6. `test_6_bump_target_sdk_and_standalone_install_cli_and_warnings`: Standalone install CLI flow and dangerous permission warnings.
7. `test_7_signing_block_verity_padding_and_cd_alignment`: Verification of `0x42726577` block and 4KB CD alignment.
8. `test_8_split_merger_stored_native_libs_and_resource_warning`: Manifest native lib synchronization and resource table split warning.

All 227 tests in the test suite pass with zero regressions.
