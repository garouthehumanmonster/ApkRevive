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

| ID | Subsystem | Severity | Location | Summary | Status | Resolution / Links |
|---|---|---|---|---|---|---|
| **F-01** | CLI / Inspect | **CRITICAL** | [`apkrevive/cli/__init__.py:71`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L71) | Unhandled `NameError` crash when inspecting APKs with private Bionic dependencies | **RESOLVED** | Fixed using `PRIVATE_BIONIC_LIBS` in [`apkrevive/cli/__init__.py:71`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L71) |
| **F-02** | Triage Logic | **CRITICAL** | [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170) | False `GREEN` verdict for native libraries containing text relocations (`DT_TEXTREL`) | **RESOLVED** | Emits `Verdict.RED` with `INCOMPATIBLE_TEXTREL` in [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170) |
| **F-03** | Triage Logic | **CRITICAL** | [`apkrevive/core/triage.py:278-284`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L278-L284) | False `GREEN` verdict on 16KB kernels for 4KB-linked ELFs without `pageSizeCompat` | **RESOLVED** | Requires `PAGE_SIZE_COMPAT` on 16KB kernels in [`apkrevive/core/triage.py:278-284`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L278-L284) |
| **F-04** | TargetSDK / Perms | **HIGH** | [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242) | Bumping targetSdkVersion triggers unhandled Bionic namespace isolation & runtime permission blocks | **RESOLVED** | Evaluates Bionic isolation against effective targetSdk in [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242) |
| **F-05** | CLI / Patch | **HIGH** | [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346) | `run_patch()` ignores signing failure and emits `verdict="GREEN"` for unsigned APKs | **RESOLVED** | Checks `sign_apk()` return boolean and raises `RuntimeError` on failure in [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346) |
| **F-06** | CLI / Keystore | **HIGH** | [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189) | Custom keystore password & alias CLI arguments are dropped by `run_patch()` | **RESOLVED** | Accepts and forwards `--ks-pass`, `--ks-alias`, `--key-pass` in [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189) |
| **F-07** | Shim Lifecycle | **HIGH** | [`apkrevive/shim/ApkReviveInitProvider.java:14-62`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/ApkReviveInitProvider.java#L14-L62) | 60Hz display lock & cutout flags cannot execute in ContentProvider without Activity lifecycle hooks | **DOCUMENTED ARCHITECTURAL LIMITATION** | Documented in [`docs/LIMITS.md#11-60hz-display-mode-locking--display-cutout-mode-architectural-limitation`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/docs/LIMITS.md#11-60hz-display-mode-locking--display-cutout-mode-architectural-limitation); flags removed from [`apkrevive/cli/__init__.py`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py) |
| **F-08** | AXML Surgeon | **HIGH** | [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261) | StringPool length truncation on long UTF-16 strings and integer overflow on UTF-8 serialization | **RESOLVED** | Handles UTF-16 two-word lengths and clamps string lengths to 0x7FFF in [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261) |
| **F-09** | AXML Surgeon | **HIGH** | [`apkrevive/core/axml.py:521-525`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L521-L525) | `serialize()` crashes with `ValueError` on unmapped attributes in legacy manifests | **RESOLVED** | Serializes unmapped attributes with resource ID 0 fallback in [`apkrevive/core/axml.py:521-525`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L521-L525) |
| **F-10** | Container / Zip | **MEDIUM** | [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35) | `validate_zip_archive()` fails to detect duplicate entry filenames (Zip-Slip / Master-Key vulnerability) | **RESOLVED** | Enforces unique entry names with `seen_names = set()` in [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35) |
| **F-11** | Container / Zip | **MEDIUM** | [`apkrevive/core/align.py:134-138`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L134-L138) | Deflated (compressed) native shared libraries bypass 16KB alignment | **RESOLVED** | Decompresses deflated `.so` and `resources.arsc` to STORED and aligns to 16KB in [`apkrevive/core/align.py:136-187`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L136-L187) |
| **F-12** | Signing Bridge | **MEDIUM** | [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40) | Missing diagnostics and pure-Python fallback when `apksigner`/`keytool` are absent | **RESOLVED** | Added user-actionable diagnostics in [`apkrevive/cli/__init__.py:577-589`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L577-L589) and [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40) |
| **F-13** | Reproducibility | **MEDIUM** | [`.github/workflows/ci.yml:15-79`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L15-L79) | CI tests trusted binary blob `shim.dex` without verifying source compilation | **RESOLVED** | Added verification step running `python -m apkrevive.shim.build_shim --verify` in [`.github/workflows/ci.yml:164`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L164) |
| **F-14** | CI Pipeline | **LOW** | [`.github/workflows/ci.yml:80-144`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L80-L144) | CI references deleted `apkrevive-android` companion app directory | **RESOLVED** | Disabled orphaned `android-ci` job with `if: false` in [`.github/workflows/ci.yml:81-84`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L81-L84) |
| **F-15** | Documentation | **LOW** | [`README.md:126-131`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L126-L131) | README documents unsupported CLI options (`--force`, `--device-api`) for `patch` | **RESOLVED** | Removed unsupported flags and documented all 6 commands (`inspect`, `triage`, `patch`, `verify`, `diff`, `doctor`) in [`README.md:60-173`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L60-L173) |
| **F-16** | Documentation | **LOW** | [`README.md:1-152`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L1-L152) | Re-signing operational limitations (data wipe, signature permissions) omitted from README | **RESOLVED** | Added prominent security boundaries section in [`README.md:174-192`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L174-L192) and [`docs/LIMITS.md:73-91`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/docs/LIMITS.md#73-91) |

---

## Detailed Findings & Remediations

### 1. F-01 (CRITICAL): Unhandled `NameError` in `cli.run_inspect()`
- **Status**: **RESOLVED**
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
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/cli/__init__.py:71`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L71) using `PRIVATE_BIONIC_LIBS` (imported from `apkrevive.core.elf_surgeon`):
  ```python
  private_bionic_found = [
      lib for lib in meta.private_libs
      if lib in PRIVATE_BIONIC_LIBS or "libcrypto" in lib or "libssl" in lib or "libcutils" in lib
  ]
  ```

---

### 2. F-02 (CRITICAL): False `GREEN` Verdict for Native Libraries with Text Relocations (`DT_TEXTREL`)
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170), [`apkrevive/core/triage.py:415-428`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L415-L428)
- **Why it matters**:
  Android 6.0+ (API 23+) dynamic linker strictly refuses to load native binaries with text relocations (`DT_TEXTREL`) to enforce W^X (Write XOR Execute) memory security. The application crashes immediately during `System.loadLibrary()` with `dlopen failed: ... has text relocations`.
  However, in `triage.py`, `has_textrel` only appends a text string to `warnings`. It adds no entry to `required_transforms`. If the APK has no other issues, the triage engine proceeds to line 415 and returns:
  `verdict: GREEN`, `reason: RUNNABLE_UNMODIFIED`.
  Claiming an APK with text relocations will run unmodified on Android 14–16 is provably false.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/triage.py:163-170`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L163-L170). If `apk.get("has_textrel")` is true and `device_sdk >= 23`, triage emits `Verdict.RED` with reason `TriageSignal.INCOMPATIBLE_TEXTREL`.

---

### 3. F-03 (CRITICAL): False `GREEN` Verdict on 16KB Kernels for 4KB-Linked ELFs without `pageSizeCompat`
- **Status**: **RESOLVED**
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
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/triage.py:278-284`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L278-L284). When running on 16KB kernels with 4KB-linked 64-bit libraries (`COMPAT_ONLY`), `PAGE_SIZE_COMPAT` is required, producing `Verdict.YELLOW` (on API >= 36) or `Verdict.RED` (on API < 36).

---

### 4. F-04 (HIGH): Bumping `targetSdkVersion` Triggers Runtime Permission & Bionic Linker Traps
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242), [`apkrevive/cli/__init__.py:208-216`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L208-L216)
- **Why it matters**:
  1. **Runtime Permissions**: Legacy apps (API < 23) rely on install-time permission grants. When `targetSdkVersion` is bumped to 24 (to bypass the API 34+ install floor), dangerous permissions (e.g. `READ_EXTERNAL_STORAGE`, `CAMERA`) are not auto-granted. App code that never calls `requestPermissions()` silently loses access or crashes.
  2. **Bionic Namespace Isolation**: On Android 7.0+ (API 24+), the dynamic linker isolates private platform libraries (`libcrypto.so`, `libssl.so`, `libcutils.so`). For apps targeting `< 24`, Bionic provides a greylist fallback. When `bump_target_sdk` bumps the manifest to 24, Bionic greylist exemptions are revoked, causing immediate `UnsatisfiedLinkError`.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/triage.py:228-242`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/triage.py#L228-L242). Triage evaluates Bionic isolation against effective targetSdk and flags private library blockers (`Verdict.RED`). CLI guidance highlights runtime permission requirements and privileged bypass (`--bypass-low-target-sdk-block`).

---

### 5. F-05 (HIGH): `run_patch()` Ignores Signing Failures and Emits `verdict="GREEN"`
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346)
- **Why it matters**:
  `sign_apk()` returns a boolean indicating success or failure. In `run_patch()`:
  ```python
  if not no_sign:
      sign_apk(output_apk, keystore_path=keystore_path)
      remediations.append("Signer: Applied APK Signature Scheme v2/v3")
  ```
  The return value of `sign_apk()` is discarded. If `apksigner` fails or is not found, `run_patch` still records that V2/V3 signing was applied and returns `PatchReport(verdict="GREEN")`. The output APK remains unsigned and will fail installation with `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/cli/__init__.py:340-346`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L340-L346). `run_patch()` checks `sign_apk()` return boolean and raises `RuntimeError("APK signing failed. Check apksigner installation or keystore credentials.")` upon failure.

---

### 6. F-06 (HIGH): Custom Keystore Password & Key Alias Arguments Dropped by `run_patch()`
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189), [`apkrevive/cli/__init__.py:471-477`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L471-L477)
- **Why it matters**:
  `apkrevive patch` defines CLI arguments `--ks-pass`, `--ks-alias`, and `--key-pass`. However, `run_patch()` only accepts `keystore_path`. When users supply custom credentials via CLI, `run_patch()` discards them and calls `sign_apk(output_apk, keystore_path=keystore_path)`. `signer.ensure_keystore()` then triggers a fallback warning and defaults the keystore password to `"android"`, failing if the keystore has a custom password.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/cli/__init__.py:182-189`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L182-L189). `run_patch()` accepts `keystore_pass`, `key_alias`, and `key_pass` arguments and forwards them to `sign_apk()`.

---

### 7. F-07 (HIGH): 60Hz Lock and Display Cutout Mode Cannot Execute in `ContentProvider` without Activity Lifecycle Hooks
- **Status**: **DOCUMENTED ARCHITECTURAL LIMITATION**
- **File & Line**: [`apkrevive/shim/ApkReviveInitProvider.java:14-62`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/ApkReviveInitProvider.java#L14-L62), [`apkrevive/cli/__init__.py:511-512`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L511-L512)
- **Why it matters**:
  `ApkReviveInitProvider` runs during startup before `Application.onCreate()`. At this point in the process lifecycle, no Activity exists and `getContext()` is an `Application` context without a `Window` or display attributes.
  Window attributes such as `WindowManager.LayoutParams.preferredDisplayModeId` (locking 60Hz) and `layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES` cannot be set globally from `ContentProvider.onCreate()`. They MUST be applied to each Activity's Window. To achieve this, the Provider must register an `Application.ActivityLifecycleCallbacks` listener on `(Application) getContext().getApplicationContext()` and apply attributes during `onActivityStarted` or `onActivityResumed`.
  Currently, `ApkReviveInitProvider.java` has no Activity lifecycle callbacks or display logic at all, yet CLI passes `enable_60hz: True` and documentation claims 60Hz locking is supported.
- **Proposed Fix & Resolution**:
  Documented as an architectural limitation in [`docs/LIMITS.md#11-60hz-display-mode-locking--display-cutout-mode-architectural-limitation`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/docs/LIMITS.md#11-60hz-display-mode-locking--display-cutout-mode-architectural-limitation). The headless `ApkReviveInitProvider` cannot instantiate Window contexts; the suppressed `--enable-60hz` and `--enable-cutout` flags have been removed from [`apkrevive/cli/__init__.py`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py).

---

### 8. F-08 (HIGH): AXML StringPool Truncation on UTF-16 Lengths and UTF-8 Length Overflow
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261), [`apkrevive/core/axml.py:635`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L635)
- **Why it matters**:
  1. In `axml.py:261`, UTF-16 string length parsing reads a single 16-bit word:
     `u16_len = struct.unpack_from("<H", pool_data, p)[0]`
     In Android's `ResStringPool`, if `u16_len & 0x8000 != 0`, the length is stored across two 16-bit words: `((u16_len & 0x7FFF) << 16) | next_word`. Reading only one word corrupts strings longer than 32,767 code units.
  2. In `axml.py:635`:
     `struct.pack(">HH", c_len | 0x8000, b_len | 0x8000)`
     If `c_len >= 0x8000` or `b_len >= 0x8000`, bitwise OR with `0x8000` overflows unsigned 16-bit integers and causes `struct.error`.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/axml.py:261`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L261). UTF-16 two-word length decoding implemented per Android `ResourceTypes.h`, and string lengths clamped to 0x7FFF (32,767 code units) on serialization to prevent integer overflow.

---

### 9. F-09 (HIGH): `AxmlSurgeon.serialize()` Crashes on Unmapped Android Attributes
- **Status**: **RESOLVED**
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
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/axml.py:521-525`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/axml.py#L521-L525). Expanded `KNOWN_RESOURCE_IDS` with standard platform attributes and added safe fallback to serialize unrecognized attributes with resource ID 0 rather than raising an unhandled exception.

---

### 10. F-10 (MEDIUM): `validate_zip_archive()` Fails to Detect Duplicate Entry Names
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35)
- **Why it matters**:
  `validate_zip_archive()` verifies path traversal (`..`, leading slashes) and compression ratio bombs, but does not track `seen = set()` for entry names. Malicious or corrupt APKs containing duplicate filenames (such as two `classes.dex` or two `AndroidManifest.xml` files—the Android Master Key vulnerability class) bypass validation. When passed to `align_apk` or Python's `zipfile`, different parsers pick different entries.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/align.py:22-35`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L22-L35). Maintains `seen_names = set()` during archive iteration and raises `ValueError(f"Duplicate entry name detected in ZIP: {name}")` if a duplicate entry is encountered.

---

### 11. F-11 (MEDIUM): Deflated (Compressed) Native Libraries Bypass 16KB Alignment
- **Status**: **RESOLVED**
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
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/core/align.py:136-187`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/align.py#L136-L187). When `align_apk` encounters a `.so` or `resources.arsc` entry with `method != 0`, it decompresses the payload using `zlib.decompress`, sets `method = 0` (STORED), updates sizes in LFH and CD, and aligns the uncompressed payload to 16KB boundaries. Verified with unit test in [`tests/test_align.py`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/tests/test_align.py).

---

### 12. F-12 (MEDIUM): Missing Pure-Python Fallback or Clear Diagnostics for Missing `apksigner` / `keytool`
- **Status**: **RESOLVED**
- **File & Line**: [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40), [`apkrevive/core/signer.py:110-120`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L110-L120)
- **Why it matters**:
  `signer.py` delegates to external subprocesses `keytool` and `apksigner`. If Android build-tools are absent from the host system, `sign_apk` fails silently or with unformatted subprocess errors.
- **Proposed Fix & Resolution**:
  Fixed in [`apkrevive/cli/__init__.py:577-589`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L577-L589) and [`apkrevive/core/signer.py:17-40`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/core/signer.py#L17-L40). Emits clear, actionable diagnostic messages indicating JDK (`keytool`) and Android SDK build-tools (`apksigner`) requirements, directing users to run `apkrevive doctor` or use `--no-sign`.

---

### 13. F-13 (MEDIUM): CI Trusts Binary Blob `shim.dex` without Compiling from Source
- **Status**: **RESOLVED**
- **File & Line**: [`.github/workflows/ci.yml:15-79`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L15-L79), [`apkrevive/shim/shim.dex`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/shim/shim.dex)
- **Why it matters**:
  `shim.dex` is committed as a pre-compiled binary blob. In GitHub Actions CI, `test_shim.py` checks that `hashlib.sha256(shim.dex)` matches `CANONICAL_SHIM_SHA256`. However, CI never compiles `ApkReviveInitProvider.java` using `javac` and `d8` to verify that the binary blob actually matches the checked-in Java source code. This creates supply-chain and tampering risk.
- **Proposed Fix & Resolution**:
  Fixed in [`.github/workflows/ci.yml:164`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L164). Added dedicated build step in the `integration-suite` job running `python -m apkrevive.shim.build_shim --verify` to verify deterministic bytecode compilation and canonical SHA-256 identity against `CANONICAL_SHIM_SHA256`.

---

### 14. F-14 (LOW): Orphaned References in CI Workflow to Non-Existent `apkrevive-android`
- **Status**: **RESOLVED**
- **File & Line**: [`.github/workflows/ci.yml:80-144`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L80-L144)
- **Why it matters**:
  The `android-ci` job executes `chmod +x apkrevive-android/gradlew` and runs Gradle tasks in `apkrevive-android`. This directory does not exist on `main`, causing GitHub Actions runs to fail with `No such file or directory`.
- **Proposed Fix & Resolution**:
  Fixed in [`.github/workflows/ci.yml:81-84`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/.github/workflows/ci.yml#L81-L84). Guarded the orphaned `android-ci` job with `if: false` until the companion app is restored as a submodule or separate repository.

---

### 15. F-15 (LOW): README Documents Unsupported CLI Arguments (`--force`, `--device-api` on `patch`)
- **Status**: **RESOLVED**
- **File & Line**: [`README.md:126-131`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L126-L131), [`apkrevive/cli/__init__.py:432-449`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/apkrevive/cli/__init__.py#L432-L449)
- **Why it matters**:
  `README.md` documents `--force` and `--device-api` as flags for `apkrevive patch`. Neither flag is defined in `p_patch`. Users copying commands from the README will encounter `argparse` errors: `error: unrecognized arguments: --force`.
- **Proposed Fix & Resolution**:
  Fixed in [`README.md:60-173`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L60-L173). Removed unsupported `--force` and `--device-api` arguments from the `patch` documentation and documented all 6 CLI subcommands: `inspect`, `triage`, `patch`, `verify`, `diff`, and `doctor`.

---

### 16. F-16 (LOW): Re-Signing Operational Limitations Omitted from README
- **Status**: **RESOLVED**
- **File & Line**: [`README.md:1-152`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L1-L152)
- **Why it matters**:
  Re-signing legacy APKs with a new private key alters the certificate fingerprint. This breaks:
  1. Google Play in-place updates (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`), requiring a full app uninstall and resulting in permanent user data loss.
  2. Apps using signature-level permissions (`protectionLevel="signature"`) shared between components.
  3. Google Sign-In, Firebase, and Play Integrity checks tied to SHA-1/SHA-256 certificate fingerprints.
- **Proposed Fix & Resolution**:
  Fixed in [`README.md:174-192`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/README.md#L174-L192) and [`docs/LIMITS.md:73-91`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/docs/LIMITS.md#73-91). Added a prominent "Re-Signing Limitations & Security Boundaries" section detailing permanent app data deletion, Google Play update incompatibility, broken signature permissions, and Play Integrity attestation failures.

---

## Remediation Roadmap & Audit Closures

1. **Step 1: Test-Driven Fixes for Critical & High Issues (Phase 2)**:
   - F-01: Fix `DEFAULT_BIONIC_RENAME_MAP` `NameError` in `cli/__init__.py`. (**RESOLVED**)
   - F-02: Fix `DT_TEXTREL` false GREEN in `triage.py`. (**RESOLVED**)
   - F-03: Fix 16KB kernel 4KB-ELF false GREEN in `triage.py`. (**RESOLVED**)
   - F-04: Evaluate Bionic isolation against effective targetSdk and runtime permissions. (**RESOLVED**)
   - F-05 & F-06: Check `sign_apk` return code and accept `--ks-pass`, `--ks-alias`, `--key-pass` in `run_patch()`. (**RESOLVED**)
   - F-08 & F-09: Harden AXML StringPool decoding and unmapped attribute serialization. (**RESOLVED**)
   - F-10: Add duplicate entry rejection in `align.validate_zip_archive()`. (**RESOLVED**)
2. **Step 2: Property & Fuzz Testing**:
   - Add Hypothesis fuzz test suites for AXML parsing/serialization and ELF parsing. (**RESOLVED**)
   - Add corpus test harness (`tests/corpus`). (**RESOLVED**)
3. **Step 3: Verification & Tooling Hardening (Phase 3)**:
   - Implement `apkrevive verify <out.apk>` verifying 16KB alignment, V2/V3 signatures, and contiguous DEX structures with non-zero exit codes. (**RESOLVED**)
   - Update `README.md` with Capability Matrix (`VERIFIED` / `PARTIAL` / `UNVERIFIED`) and test citations. (**RESOLVED**)
4. **Step 4: Audit Closures (Phase 4)**:
   - F-07: Documented 60Hz and display cutout mode as architectural limitation in [`docs/LIMITS.md`](file:///C:/Users/Divyansh/Desktop/Projects/apkrevive/docs/LIMITS.md) and removed CLI flags. (**RESOLVED - DOCUMENTED ARCHITECTURAL LIMITATION**)
   - F-11: Decompress deflated `.so` and `resources.arsc` to STORED and enforce 16KB alignment in `align_apk()`. (**RESOLVED**)
   - F-12: Actionable toolchain diagnostics for missing `apksigner` and `keytool`. (**RESOLVED**)
   - F-13: Add CI verification step for shim compilation reproducibility (`build_shim --verify`). (**RESOLVED**)
   - F-14: Guard non-existent companion app in CI workflow. (**RESOLVED**)
   - F-15: Fix README CLI usage documentation to reflect actual options and all 6 commands. (**RESOLVED**)
   - F-16: Document re-signing operational boundaries and security limitations. (**RESOLVED**)
