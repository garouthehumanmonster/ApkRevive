# ApkRevive Comprehensive Tooling & Runtime Audit (Phase 1)

This document contains the static security, binary architecture, and runtime review of **ApkRevive** (v0.4.0, commit `b36b1e4`) across 9 core subsystems:
1. **Signing & Identity Invariants**
2. **ELF 16KB Page Alignment & Modulo Congruence**
3. **In-Memory Binary AXML Parsing, Serialization & Schema Safety**
4. **Bytecode Shim (`ApkReviveInitProvider`) Timing & Window Context**
5. **ZIP Container Alignment, Zip-Slip & Zip64 Safety**
6. **ADB & Low-TargetSDK Bypass Mechanics**
7. **Triage Verdict Soundness (False GREEN Elimination)**
8. **Build Reproducibility & CI Bytecode Verification**
9. **Specification Reality Check (README Claims vs Test Receipts)**

---

## Executive Summary Matrix

| ID | Subsystem | Severity | Location | Summary |
|---|---|---|---|---|
| **F-01** | CLI / Inspect | **CRITICAL** | [`apkrevive/cli/__init__.py:71`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L71) | Unhandled `NameError` crash when inspecting APKs with private Bionic dependencies |
| **F-02** | Triage Logic | **CRITICAL** | [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170) | False `GREEN` verdict for native libraries containing text relocations (`DT_TEXTREL`) |
| **F-03** | Triage Logic | **CRITICAL** | [`apkrevive/core/triage.py:278-284`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L278-L284) | False `GREEN` verdict on 16KB kernels for 4KB-linked ELFs without `pageSizeCompat` |
| **F-04** | TargetSDK / Perms | **HIGH** | [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242) | Bumping targetSdkVersion triggers unhandled Bionic namespace isolation & runtime permission blocks |
| **F-05** | CLI / Patch | **HIGH** | [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346) | `run_patch()` ignores signing failure and emits `verdict="GREEN"` for unsigned APKs |
| **F-06** | CLI / Keystore | **HIGH** | [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189) | Custom keystore password & alias CLI arguments are dropped by `run_patch()` |
| **F-07** | Shim Lifecycle | **HIGH** | [`apkrevive/shim/ApkReviveInitProvider.java:14-62`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/ApkReviveInitProvider.java#L14-L62) | 60Hz display lock & cutout flags cannot execute in ContentProvider without Activity lifecycle hooks |
| **F-08** | AXML Surgeon | **HIGH** | [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261) | StringPool length truncation on long UTF-16 strings and integer overflow on UTF-8 serialization |
| **F-09** | AXML Surgeon | **HIGH** | [`apkrevive/core/axml.py:521-525`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L521-L525) | `serialize()` crashes with `ValueError` on unmapped attributes in legacy manifests |
| **F-10** | Container / Zip | **MEDIUM** | [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35) | `validate_zip_archive()` fails to detect duplicate entry filenames (Zip-Slip / Master-Key vulnerability) |
| **F-11** | Container / Zip | **MEDIUM** | [`apkrevive/core/align.py:134-138`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L134-L138) | Deflated (compressed) native shared libraries bypass 16KB alignment |
| **F-12** | Signing Bridge | **MEDIUM** | [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40) | Missing diagnostics and pure-Python fallback when `apksigner`/`keytool` are absent |
| **F-13** | Reproducibility | **MEDIUM** | [`.github/workflows/ci.yml:15-79`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L15-L79) | CI tests trusted binary blob `shim.dex` without verifying source compilation |
| **F-14** | CI Pipeline | **LOW** | [`.github/workflows/ci.yml:80-144`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L80-L144) | CI references deleted `apkrevive-android` companion app directory |
| **F-15** | Documentation | **LOW** | [`README.md:126-131`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L126-L131) | README documents unsupported CLI options (`--force`, `--device-api`) for `patch` |
| **F-16** | Documentation | **LOW** | [`README.md:1-152`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L1-L152) | Re-signing operational limitations (data wipe, signature permissions) omitted from README |

---

## Detailed Findings & Remediations

### 1. F-01 (CRITICAL): Unhandled `NameError` in `cli.run_inspect()`
- **File & Line**: [`apkrevive/cli/__init__.py:69-72`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L69-L72)
- **Why it matters**: 
  When auditing native libraries for private Bionic platform libraries, line 71 evaluates:
  ```python
  private_bionic_found = [
      lib for lib in meta.private_libs
      if lib in DEFAULT_BIONIC_RENAME_MAP or "libcrypto" in lib or "libssl" in lib or "libcutils" in lib
  ]
  ```
  `DEFAULT_BIONIC_RENAME_MAP` was completely deleted during the de-bloat of `elf_surgeon.py` and is neither defined nor imported in `apkrevive.cli`. Any APK whose `meta.private_libs` contains entries will immediately cause `apkrevive inspect <apk>` to crash with:
  `NameError: name 'DEFAULT_BIONIC_RENAME_MAP' is not defined`.
- **Proposed Fix**:
  Use `PRIVATE_BIONIC_LIBS` (which is already imported at line 33 from `apkrevive.core.elf_surgeon`):
  ```python
  private_bionic_found = [
      lib for lib in meta.private_libs
      if lib in PRIVATE_BIONIC_LIBS or "libcrypto" in lib or "libssl" in lib or "libcutils" in lib
  ]
  ```

---

### 2. F-02 (CRITICAL): False `GREEN` Verdict for Native Libraries with Text Relocations (`DT_TEXTREL`)
- **File & Line**: [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170), [`apkrevive/core/triage.py:415-428`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L415-L428)
- **Why it matters**:
  Android 6.0+ (API 23+) dynamic linker strictly refuses to load native binaries with text relocations (`DT_TEXTREL`) to enforce W^X (Write XOR Execute) memory security. The application crashes immediately during `System.loadLibrary()` with `dlopen failed: ... has text relocations`.
  However, in `triage.py`, `has_textrel` only appends a text string to `warnings`. It adds no entry to `required_transforms`. If the APK has no other issues, the triage engine proceeds to line 415 and returns:
  `verdict: GREEN`, `reason: RUNNABLE_UNMODIFIED`.
  Claiming an APK with text relocations will run unmodified on Android 14–16 is provably false.
- **Proposed Fix**:
  In `triage.py`, if `apk.get("has_textrel")` is true and `device_sdk >= 23`, return `Verdict.RED` with reason `TriageSignal.INCOMPATIBLE_TEXTREL` (or unresolvable blocker).

---

### 3. F-03 (CRITICAL): False `GREEN` Verdict on 16KB Kernels for 4KB-Linked ELFs without `pageSizeCompat`
- **File & Line**: [`apkrevive/core/triage.py:278-284`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L278-L284), [`apkrevive/core/triage.py:415-428`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L415-L428)
- **Why it matters**:
  On 16KB page-size kernels (Android 15+ / API 35+), 64-bit ELF binaries compiled with 4KB alignment (`p_align == 4096`) fail to `mmap` or crash due to segment page collisions. On Android 16 (API 36+), the OS introduces `pageSizeCompat` backcompat mode, which MUST be explicitly enabled in `AndroidManifest.xml` via `android:pageSizeCompat="enabled"` under `<application>`.
  In `triage.py`:
  ```python
  elif force_page_size_compat:
      required_transforms.append("PAGE_SIZE_COMPAT")
      reasons.append(TriageSignal.NEEDS_PAGE_SIZE_COMPAT_ANDROID16.value)
  else:
      has_16kb_advisory = True
      warnings.append("WARN_PAGE_SIZE_COMPAT_ADVISORY: ...")
  ```
  Unless `force_page_size_compat` is explicitly set in the input dictionary, `triage.py` emits only an advisory warning and returns `Verdict.GREEN`. A legacy APK does not have `android:pageSizeCompat="enabled"` in its manifest and will crash when run.
- **Proposed Fix**:
  If the target device is a 16KB kernel and native 64-bit libraries are `COMPAT_ONLY`, `PAGE_SIZE_COMPAT` MUST be added to `required_transforms`, resulting in `Verdict.YELLOW` (or `Verdict.RED` if `device_sdk < 36`), requiring manifest modification.

---

### 4. F-04 (HIGH): Bumping `targetSdkVersion` Triggers Runtime Permission & Bionic Linker Traps
- **File & Line**: [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242), [`apkrevive/cli/__init__.py:208-216`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L208-L216)
- **Why it matters**:
  1. **Runtime Permissions**: Legacy apps (API < 23) rely on install-time permission grants. When `targetSdkVersion` is bumped to 24 (to bypass the API 34+ install floor), dangerous permissions (e.g. `READ_EXTERNAL_STORAGE`, `CAMERA`) are not auto-granted. App code that never calls `requestPermissions()` silently loses access or crashes.
  2. **Bionic Namespace Isolation**: On Android 7.0+ (API 24+), the dynamic linker isolates private platform libraries (`libcrypto.so`, `libssl.so`, `libcutils.so`). For apps targeting `< 24`, Bionic provides a greylist fallback. When `bump_target_sdk` bumps the manifest to 24, Bionic greylist exemptions are revoked, causing immediate `UnsatisfiedLinkError`.
- **Proposed Fix**:
  `triage.py` must evaluate Bionic isolation against `effective_target_sdk` (accounting for `bump_target_sdk`). If private libraries are present, bumping targetSdk must be blocked (`Verdict.RED`). Furthermore, CLI output must recommend installing bumped APKs with `adb install -g` (auto-grant all runtime permissions).

---

### 5. F-05 (HIGH): `run_patch()` Ignores Signing Failures and Emits `verdict="GREEN"`
- **File & Line**: [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346)
- **Why it matters**:
  `sign_apk()` returns a boolean indicating success or failure. In `run_patch()`:
  ```python
  if not no_sign:
      sign_apk(output_apk, keystore_path=keystore_path)
      remediations.append("Signer: Applied APK Signature Scheme v2/v3")
  ```
  The return value of `sign_apk()` is discarded. If `apksigner` fails or is not found, `run_patch` still records that V2/V3 signing was applied and returns `PatchReport(verdict="GREEN")`. The output APK remains unsigned and will fail installation with `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.
- **Proposed Fix**:
  Check the return value of `sign_apk(...)`:
  ```python
  if not no_sign:
      signed = sign_apk(output_apk, keystore_path=keystore_path, ...)
      if not signed:
          raise RuntimeError("APK signing failed. Check apksigner installation or keystore credentials.")
      remediations.append("Signer: Applied APK Signature Scheme v2/v3")
  ```

---

### 6. F-06 (HIGH): Custom Keystore Password & Key Alias Arguments Dropped by `run_patch()`
- **File & Line**: [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189), [`apkrevive/cli/__init__.py:471-477`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L471-L477)
- **Why it matters**:
  `apkrevive patch` defines CLI arguments `--ks-pass`, `--ks-alias`, and `--key-pass`. However, `run_patch()` only accepts `keystore_path`. When users supply custom credentials via CLI, `run_patch()` discards them and calls `sign_apk(output_apk, keystore_path=keystore_path)`. `signer.ensure_keystore()` then triggers a fallback warning and defaults the keystore password to `"android"`, failing if the keystore has a custom password.
- **Proposed Fix**:
  Update `run_patch()` signature to accept `keystore_pass: Optional[str] = None`, `key_alias: Optional[str] = None`, `key_pass: Optional[str] = None`, and forward them to `sign_apk()`.

---

### 7. F-07 (HIGH): 60Hz Lock and Display Cutout Mode Cannot Execute in `ContentProvider` without Activity Lifecycle Hooks
- **File & Line**: [`apkrevive/shim/ApkReviveInitProvider.java:14-62`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/ApkReviveInitProvider.java#L14-L62), [`apkrevive/cli/__init__.py:235-236`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L235-L236)
- **Why it matters**:
  `ApkReviveInitProvider` runs during startup before `Application.onCreate()`. At this point in the process lifecycle, no Activity exists and `getContext()` is an `Application` context without a `Window` or display attributes.
  Window attributes such as `WindowManager.LayoutParams.preferredDisplayModeId` (locking 60Hz) and `layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES` cannot be set globally from `ContentProvider.onCreate()`. They MUST be applied to each Activity's Window. To achieve this, the Provider must register an `Application.ActivityLifecycleCallbacks` listener on `(Application) getContext().getApplicationContext()` and apply attributes during `onActivityStarted` or `onActivityResumed`.
  Currently, `ApkReviveInitProvider.java` has no Activity lifecycle callbacks or display logic at all, yet CLI passes `enable_60hz: True` and documentation claims 60Hz locking is supported.
- **Proposed Fix**:
  Implement an `Application.ActivityLifecycleCallbacks` class within `ApkReviveInitProvider.java` that inspects `Activity.getWindow()`, setting `preferredDisplayModeId` (found via `Display.getSupportedModes()`) and `layoutInDisplayCutoutMode = 1` (`SHORT_EDGES`). Alternatively, remove the claim from documentation and mark the feature as `UNVERIFIED`.

---

### 8. F-08 (HIGH): AXML StringPool Truncation on UTF-16 Lengths and UTF-8 Length Overflow
- **File & Line**: [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261), [`apkrevive/core/axml.py:635`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L635)
- **Why it matters**:
  1. In `axml.py:261`, UTF-16 string length parsing reads a single 16-bit word:
     `u16_len = struct.unpack_from("<H", pool_data, p)[0]`
     In Android's `ResStringPool`, if `u16_len & 0x8000 != 0`, the length is stored across two 16-bit words: `((u16_len & 0x7FFF) << 16) | next_word`. Reading only one word corrupts strings longer than 32,767 code units.
  2. In `axml.py:635`:
     `struct.pack(">HH", c_len | 0x8000, b_len | 0x8000)`
     If `c_len >= 0x8000` or `b_len >= 0x8000`, bitwise OR with `0x8000` overflows unsigned 16-bit integers and causes `struct.error`.
- **Proposed Fix**:
  Support two-word length decoding in UTF-16 parsing, and clamp maximum string length to 0x7FFF (32,767 characters) or encode multi-word lengths strictly per Android `ResourceTypes.h`.

---

### 9. F-09 (HIGH): `AxmlSurgeon.serialize()` Crashes on Unmapped Android Attributes
- **File & Line**: [`apkrevive/core/axml.py:521-525`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L521-L525)
- **Why it matters**:
  In `AxmlSurgeon.serialize()`:
  ```python
  elif a.ns == ANDROID_NS or a.name.startswith("android:"):
      raise ValueError(
          f"Unknown Android manifest attribute '{a.name}' (namespace '{a.ns}'): "
          f"no resource ID found in original manifest resource map or known platform definitions."
      )
  ```
  If an incoming legacy APK contains standard Android attributes not in the hardcoded 35-item `KNOWN_RESOURCE_IDS` dictionary (e.g. `android:persistent`, `android:sharedUserId`, `android:largeHeap`, `android:hardwareAccelerated`, `android:permission`, `android:enabled`), and the input APK was built without a `CHUNK_RESOURCE_MAP` chunk (or the attribute was injected), `serialize()` crashes with `ValueError`.
- **Proposed Fix**:
  Expand `KNOWN_RESOURCE_IDS` with all standard Android manifest attributes, and allow fallback attributes to serialize with resource ID 0 rather than raising an unhandled exception.

---

### 10. F-10 (MEDIUM): `validate_zip_archive()` Fails to Detect Duplicate Entry Names
- **File & Line**: [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35)
- **Why it matters**:
  `validate_zip_archive()` verifies path traversal (`..`, leading slashes) and compression ratio bombs, but does not track `seen = set()` for entry names. Malicious or corrupt APKs containing duplicate filenames (such as two `classes.dex` or two `AndroidManifest.xml` files—the Android Master Key vulnerability class) bypass validation. When passed to `align_apk` or Python's `zipfile`, different parsers pick different entries.
- **Proposed Fix**:
  Maintain a `seen_names = set()` during archive iteration. If `info.filename in seen_names`, raise `ValueError(f"Duplicate entry name detected in ZIP: {info.filename}")`.

---

### 11. F-11 (MEDIUM): Deflated (Compressed) Native Libraries Bypass 16KB Alignment
- **File & Line**: [`apkrevive/core/align.py:134-138`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L134-L138)
- **Why it matters**:
  `align_apk()` checks:
  ```python
  alignment = 4
  if method == 0:  # STORED
      if (filename.startswith("lib/") and filename.endswith(".so")) or filename == "resources.arsc":
          alignment = 16384
  ```
  If an input APK has native libraries that were compressed with `DEFLATE` (`method == 8`), `align_apk` aligns them to 4 bytes instead of 16KB. Although `run_patch()` sets `compress_type = zipfile.ZIP_STORED` during repacking, any standalone invocation of `align_apk` on a legacy APK leaves deflated libraries unaligned.
- **Proposed Fix**:
  If a `.so` entry in `align_apk` has `method != 0`, emit a warning or provide an option to uncompress stored entries to enforce 16KB alignment.

---

### 12. F-12 (MEDIUM): Missing Pure-Python Fallback or Clear Diagnostics for Missing `apksigner` / `keytool`
- **File & Line**: [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40), [`apkrevive/core/signer.py:110-120`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L110-L120)
- **Why it matters**:
  `signer.py` delegates to external subprocesses `keytool` and `apksigner`. If Android build-tools are absent from the host system, `sign_apk` fails silently or with unformatted subprocess errors.
- **Proposed Fix**:
  Provide an explicit, user-actionable error message detailing that Android SDK `build-tools` (`apksigner`) and JDK (`keytool`) are required, and verify availability during `apkrevive doctor` / early CLI validation.

---

### 13. F-13 (MEDIUM): CI Trusts Binary Blob `shim.dex` without Compiling from Source
- **File & Line**: [`.github/workflows/ci.yml:15-79`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L15-L79), [`apkrevive/shim/shim.dex`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/shim.dex)
- **Why it matters**:
  `shim.dex` is committed as a pre-compiled binary blob. In GitHub Actions CI, `test_shim.py` checks that `hashlib.sha256(shim.dex)` matches `CANONICAL_SHIM_SHA256`. However, CI never compiles `ApkReviveInitProvider.java` using `javac` and `d8` to verify that the binary blob actually matches the checked-in Java source code. This creates supply-chain and tampering risk.
- **Proposed Fix**:
  Add a dedicated build step in GitHub Actions CI (on Ubuntu with Android SDK tools):
  `python -m apkrevive.shim.build_shim --verify`
  recompiling the Java source and asserting SHA-256 identity against `CANONICAL_SHIM_SHA256`.

---

### 14. F-14 (LOW): Orphaned References in CI Workflow to Non-Existent `apkrevive-android`
- **File & Line**: [`.github/workflows/ci.yml:80-144`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L80-L144)
- **Why it matters**:
  The `android-ci` job executes `chmod +x apkrevive-android/gradlew` and runs Gradle tasks in `apkrevive-android`. This directory does not exist on `main`, causing GitHub Actions runs to fail with `No such file or directory`.
- **Proposed Fix**:
  Remove or comment out the orphaned `android-ci` job in `.github/workflows/ci.yml` until the companion app is restored as a submodule or separate repository.

---

### 15. F-15 (LOW): README Documents Unsupported CLI Arguments (`--force`, `--device-api` on `patch`)
- **File & Line**: [`README.md:126-131`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L126-L131), [`apkrevive/cli/__init__.py:432-449`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L432-L449)
- **Why it matters**:
  `README.md` documents `--force` and `--device-api` as flags for `apkrevive patch`. Neither flag is defined in `p_patch`. Users copying commands from the README will encounter `argparse` errors: `error: unrecognized arguments: --force`.
- **Proposed Fix**:
  Update `README.md` to document the exact arguments supported by `apkrevive patch`, or add `--force` as a recognized flag in `p_patch`.

---

### 16. F-16 (LOW): Re-Signing Operational Limitations Omitted from README
- **File & Line**: [`README.md:1-152`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L1-L152)
- **Why it matters**:
  Re-signing legacy APKs with a new private key alters the certificate fingerprint. This breaks:
  1. Google Play in-place updates (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`), requiring a full app uninstall and resulting in permanent user data loss.
  2. Apps using signature-level permissions (`protectionLevel="signature"`) shared between components.
  3. Google Sign-In, Firebase, and Play Integrity checks tied to SHA-1/SHA-256 certificate fingerprints.
- **Proposed Fix**:
  Add a prominent "Re-Signing Limitations & Security Boundaries" warning section in `README.md`.

---

## Remediation Roadmap (Phase 2 & Phase 3)

1. **Step 1: Test-Driven Fixes for Critical & High Issues (Phase 2)**:
   - F-01: Fix `DEFAULT_BIONIC_RENAME_MAP` `NameError` in `cli/__init__.py`.
   - F-02: Fix `DT_TEXTREL` false GREEN in `triage.py`.
   - F-03: Fix 16KB kernel 4KB-ELF false GREEN in `triage.py`.
   - F-05 & F-06: Check `sign_apk` return code and accept `--ks-pass`, `--ks-alias`, `--key-pass` in `run_patch()`.
   - F-08 & F-09: Harden AXML StringPool decoding and unmapped attribute serialization.
   - F-10: Add duplicate entry rejection in `align.validate_zip_archive()`.
2. **Step 2: Property & Fuzz Testing**:
   - Add Hypothesis fuzz test suites for AXML parsing/serialization and ELF parsing.
   - Add corpus test harness (`tests/corpus`).
3. **Step 3: Verification & Tooling Hardening (Phase 3)**:
   - Implement `apkrevive verify <out.apk>` verifying 16KB alignment, V2/V3 signatures, and contiguous DEX structures with non-zero exit codes.
   - Update `README.md` with Capability Matrix (`VERIFIED` / `PARTIAL` / `UNVERIFIED`) and test citations.
