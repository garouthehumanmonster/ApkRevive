# Comprehensive Technical Audit: ApkRevive Modernizer Engine & Companion

**Date:** 2026-10-18  
**Auditor:** Senior Android Tooling & Systems Engineer  
**Scope:** Full codebase audit covering Python CLI (`/apkrevive`), Android Kotlin companion app (`/apkrevive-android`), verification canaries (`/canaries`), tests (`/tests`), and documentation (`README.md`, `pyproject.toml`).

---

## 1. Executive Summary

ApkRevive is designed to diagnose, modernize, and install legacy Android APKs targeting API levels 3 through 28 (Android 1.5 Cupcake to Android 9 Pie) onto modern Android runtimes (API 34–36+, Android 14/15/16 QPR) with 16KB kernel page sizes, targetSdk install floors (API 34 minSdk 23, API 35 minSdk 24), and modern display aspect ratios.

This audit provides a factual, line-by-line inspection of all source code, verifies existing claims against actual implementations and tests, investigates cryptographic signing practices, analyzes 16KB ELF memory page handling, dissects binary Android XML (AXML) manipulation, and audits the Shizuku IPC installer bridge.

### Baseline Verification Status (Empirical Run)
- **Unit / Integration Tests:** 226 passed in 23.29s (`pytest tests/`)
- **Python Test Coverage:** 83% line/branch coverage (exceeds the 80% gate in `pyproject.toml`)
- **Linting:** Clean (`ruff check .` reported 0 errors)
- **Static Type Checking:** Clean (`mypy apkrevive --ignore-missing-imports` reported 0 issues in 26 source files)
- **Android Companion Tests:** Clean (`gradlew.bat test` executed 45 tasks successfully in 44s)

---

## 2. README Claims vs. Implementation Mapping

The table below maps every functional capability, architectural block, and CLI tool advertised in [`README.md`](README.md) to its exact implementation in the codebase and its verification test suites.

| Capability / Claim in README | Source Implementation (File & Lines) | Test Suite (File & Lines) | Implementation Fidelity |
|---|---|---|---|
| **Zero-Trust Zip Guard**<br>Path traversal (Zip Slip), symlink rejection, decompression bomb limits | [`apkrevive/security/zip_guard.py#L17-L64`](apkrevive/security/zip_guard.py#L17-L64) | [`tests/test_zip_guard.py#L1-L150`](tests/test_zip_guard.py#L1-L150), [`tests/test_correctness.py#L150-L220`](tests/test_correctness.py#L150-L220) | **FULL**: Path canonicalization, null byte rejection, `0o120000` symlink check, and 100:1 ratio limit. |
| **Split APK Merger**<br>Native library merge, sequential DEX renumbering, split-lock removal | [`apkrevive/core/split_merger.py#L56-L169`](apkrevive/core/split_merger.py#L56-L169) | [`tests/test_split_merger.py#L1-L90`](tests/test_split_merger.py#L1-L90), [`tests/test_v040_hardening.py#L225-L270`](tests/test_v040_hardening.py#L225-L270) | **FULL**: Synchronizes `ZIP_STORED` native libs, renumbers multi-dex (`classes2.dex`, etc.), removes `isSplitRequired`. Emits warning on multiple `resources.arsc`. |
| **Triage Engine**<br>Rule-based evaluation for GREEN/YELLOW/RED verdicts | [`apkrevive/core/triage.py#L57-L335`](apkrevive/core/triage.py#L57-L335), [`apkrevive/core/behavior_changes.py#L136-L275`](apkrevive/core/behavior_changes.py#L136-L275) | [`tests/test_triage.py#L1-L120`](tests/test_triage.py#L1-L120), [`tests/test_triage_coverage.py#L1-L260`](tests/test_triage_coverage.py#L1-L260) | **FULL**: Comprehensive matrix mapping targetSdk and device API level behavior changes. |
| **SARIF v2.1.0 Telemetry**<br>`--sarif` output for CI/CD integration | [`apkrevive/cli/sarif.py#L154-L347`](apkrevive/cli/sarif.py#L154-L347) | [`tests/test_cli_ux.py#L180-L240`](tests/test_cli_ux.py#L180-L240) | **FULL**: Valid SARIF schema generation with rule descriptors and physical locations. |
| **In-Memory AXML Surgeon**<br>Binary AST parser & byte serializer | [`apkrevive/core/axml.py#L110-L584`](apkrevive/core/axml.py#L110-L584) | [`tests/test_axml.py#L1-L45`](tests/test_axml.py#L1-L45), [`tests/test_v040_hardening.py#L18-L60`](tests/test_v040_hardening.py#L18-L60) | **PARTIAL / DRIFT**: Mutates and serializes AXML AST. Rebuilds string pool from scratch. Does not round-trip unmutated bytes identically. |
| **16KB ELF Classification**<br>3-state classification (`ALIGNED`, `COMPAT_ONLY`, `UNSAFE`) | [`apkrevive/core/elf16k.py#L53-L213`](apkrevive/core/elf16k.py#L53-L213), [`apkrevive/core/elf.py#L59-L134`](apkrevive/core/elf.py#L59-L134) | [`tests/test_elf16k.py#L1-L150`](tests/test_elf16k.py#L1-L150), [`tests/test_elf_surgeon.py#L1-L110`](tests/test_elf_surgeon.py#L1-L110) | **AUDIT ONLY**: Audits `p_align`, modulo congruence, and vaddr overlap. Does **not** rewrite or realign ELF segments. |
| **16KB Boundary ZipAligner**<br>Aligns uncompressed `.so` and `resources.arsc` with tag `0xD935` | [`apkrevive/core/align.py#L12-L171`](apkrevive/core/align.py#L12-L171) | [`tests/test_align.py#L1-L110`](tests/test_align.py#L1-L110), [`tests/test_v040_hardening.py#L100-L135`](tests/test_v040_hardening.py#L100-L135) | **FULL**: Memory-mapped rewriter writing extra field `0xD935` to align STORED 64-bit `.so` to 16KB boundaries and `resources.arsc` to 4KB. |
| **Bytecode Shim Injection**<br>`ApkReviveInitProvider` injection into secondary DEX | [`apkrevive/cli/__init__.py#L313-L320`](apkrevive/cli/__init__.py#L313-L320), [`apkrevive/shim/ApkReviveInitProvider.java`](apkrevive/shim/ApkReviveInitProvider.java) | [`tests/test_shim.py#L1-L60`](tests/test_shim.py#L1-L60) | **PARTIAL**: Injects precompiled `shim.dex` as next `classesN.dex`. Does not patch Dalvik ClassLoader for API < 21. |
| **V2/V3 APK Re-signing**<br>Signing block injection via `apksigner` | [`apkrevive/core/signer.py#L126-L160`](apkrevive/core/signer.py#L126-L160) | [`tests/test_signer.py#L1-L130`](tests/test_signer.py#L1-L130) | **DELEGATED**: Delegates completely to host Android SDK `apksigner`. Has no in-process signing block serializer. |
| **Host Toolchain Check (`apkrevive doctor`)**<br>Checks Python, JDK, SDK, build-tools, ADB, keystore, shim | [`apkrevive/core/doctor.py#L14-L160`](apkrevive/core/doctor.py#L14-L160), [`apkrevive/cli/__init__.py#L421-L435`](apkrevive/cli/__init__.py#L421-L435) | [`tests/test_doctor.py#L1-L180`](tests/test_doctor.py#L1-L180) | **FULL**: Comprehensive toolchain environment prober. |
| **Visual Binary Diff (`apkrevive diff`)**<br>Manifest AST diff, DEX inspection, ASCII alignment ladder | [`apkrevive/cli/diff.py#L24-L408`](apkrevive/cli/diff.py#L24-L408) | [`tests/test_cli_diff.py#L1-L170`](tests/test_cli_diff.py#L1-L170) | **FULL**: Renders side-by-side terminal comparison, byte-alignment ladder, and JSON/SARIF deltas. |
| **ADB Install Floor Probe (`apkrevive probe`)**<br>Queries device props and detects install floor | [`apkrevive/adb/probe.py#L13-L39`](apkrevive/adb/probe.py#L13-L39), [`apkrevive/cli/__init__.py#L397-L405`](apkrevive/cli/__init__.py#L397-L405) | [`tests/test_adb.py#L100-L160`](tests/test_adb.py#L100-L160) | **DISCREPANCY**: Code returns `floor`, `status`, `sdk`. README claims it returns `abis` and `page_size`. |
| **OBB Delivery Validation (`apkrevive push-obb`)**<br>Validates expansion file format and version match | [`apkrevive/core/obb.py#L12-L40`](apkrevive/core/obb.py#L12-L40), [`apkrevive/cli/__init__.py#L407-L418`](apkrevive/cli/__init__.py#L407-L418) | [`tests/test_obb.py#L1-L50`](tests/test_obb.py#L1-L50) | **FULL**: Verifies naming format `main.<version>.<package>.obb`. |
| **Shizuku Android Companion App**<br>Rootless on-device package installer with low-SDK bypass | [`apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L25-L458`](apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L25-L458) | [`apkrevive-android/app/src/test/java/com/apkrevive/installer/ShizukuConnectionStateTest.kt`](apkrevive-android/app/src/test/java/com/apkrevive/installer/ShizukuConnectionStateTest.kt), [`ShizukuBridgeReflectionTest.kt`](apkrevive-android/app/src/test/java/com/apkrevive/ShizukuBridgeReflectionTest.kt) | **FULL**: Reflective `PackageInstaller` IPC via Shizuku binder with `INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK`. |
| **Web Triage Hub (`web/`)**<br>Client-side browser triage visualizer | [`web/app.js#L1-L250`](web/app.js#L1-L250), [`web/index.html`](web/index.html) | [`tests/test_parity_web_elf16k.py#L1-L98`](tests/test_parity_web_elf16k.py#L1-L98) | **FULL**: Verified parity between JavaScript and Python ELF 16KB parsing. |

---

## 3. Discrepancies: Claims with No Implementation or No Test

1. **Version Single-Source Mismatch:**
   - [`README.md:1`](README.md#L1) and [`README.md:6`](README.md#L6) state `# ApkRevive v0.3.3 (Alpha)`.
   - [`pyproject.toml:7`](pyproject.toml#L7) states `version = "0.4.0"`.
   - [`CHANGELOG.md:8`](CHANGELOG.md#L8) lists `0.4.0` as the latest release.
   - `apkrevive/__init__.py:28` falls back to `0.4.0`. The README is out of sync.

2. **`apkrevive probe` JSON Output Discrepancy:**
   - [`README.md:286-293`](README.md#L286-L293) claims `apkrevive probe` outputs:
     ```json
     {
       "sdk": 35,
       "floor": 24,
       "status": "CONFIRMED_VIA_PROP",
       "abis": ["arm64-v8a"],
       "page_size": 16384
     }
     ```
   - In [`apkrevive/adb/probe.py:13-39`](apkrevive/adb/probe.py#L13-L39), `probe_install_floor()` only returns `{"floor": ..., "status": ..., "sdk": ...}`. It does not query or return `"abis"` (`ro.product.cpu.abilist`) or `"page_size"` (`getconf PAGE_SIZE`).

3. **README Matrix Points to Non-Existent Test File:**
   - [`README.md:154`](README.md#L154) lists `tests/test_security.py` as the verification artifact for Zip Slip Guard. That file does not exist; the actual test file is [`tests/test_zip_guard.py`](tests/test_zip_guard.py).

4. **Aspect Ratio Metadata Handling:**
   - [`README.md:62`](README.md#L62) claims: *"Sets android:resizeableActivity='true' and removes restrictive android.max_aspect metadata to unlock modern widescreen aspect ratios."*
   - In [`apkrevive/core/axml.py:537-544`](apkrevive/core/axml.py#L537-L544), `AxmlSurgeon.patch_manifest` checks `if not existing_aspect: aspect_node.set_attr("value", "2.5")`. It does **not** remove an existing restrictive `android.max_aspect` (such as `1.33` or `1.78`); it leaves it untouched if present.

5. **Dalvik Multi-Dex Trampoline Claim:**
   - [`README.md:76`](README.md#L76) claims: *"Avoids fragile bytecode patching of multi-dex classes on legacy Dalvik runtimes (API < 21)."*
   - In reality, Dalvik runtimes (API < 21) only load `classes.dex` on startup. Secondary dex files (`classes2.dex`, `classes3.dex`) are **not** automatically indexed or loaded by Dalvik before `ContentProvider.onCreate()` fires unless the application initializes AndroidX MultiDex in `attachBaseContext()`. Injected `ApkReviveInitProvider` placed into `classesN.dex` will crash with `ClassNotFoundException` on real Dalvik runtimes.

6. **Missing Verification Checks in Pipeline:**
   - [`README.md:155`](README.md#L155) claims V2/V3 signing is verified. However, [`apkrevive/cli/__init__.py:335`](apkrevive/cli/__init__.py#L335) calls `sign_apk()` during `revive`, but never calls `verify_apk()` or `apksigner verify --print-certs` post-signing.
   - There are no tests comparing mutated AXML output against official tools (`aapt2 dump xmltree` or `apkanalyzer`).
   - There is no test verifying byte-level round-tripping of unmodified AXML (`serialize(parse(data)) == data`).

7. **Untested / Unimplemented Triage Detections:**
   - OpenGL ES 1.x dependency (`libGLESv1_CM.so` or `reqGlEsVersion < 0x00020000`) is neither triaged nor warned.
   - Known-dead SDKs (Google LVL, Maps v1, legacy In-App Billing v2/v3, old ad networks) are not detected.
   - TEXTREL (relocations in read-only text segments, blocked on API 23+) in 32-bit or 64-bit native libraries is not checked.

---

## 4. Cryptographic Signing Architecture (V2/V3) & Key Provenance

The signing subsystem is implemented in [`apkrevive/core/signer.py`](apkrevive/core/signer.py).

### How Signing is Performed
1. ApkRevive does **not** contain an in-process ASN.1 / DER cryptographic encoder or APK Signing Block writer.
2. It delegates signing entirely to the external Android SDK binary `apksigner` via [`get_apksigner_cmd()`](apkrevive/core/signer.py#L16-L39). It searches `ANDROID_HOME`, `ANDROID_SDK_ROOT`, platform-specific default paths, and `PATH`.
3. In [`sign_apk()`](apkrevive/core/signer.py#L126-L160), it executes:
   ```bash
   apksigner sign --ks <keystore> --ks-pass env:APKREVIVE_KS_PASS --ks-key-alias <alias> --key-pass env:APKREVIVE_KEY_PASS <target_apk>
   ```
   Passwords are passed securely via process environment variables to prevent leakage in process tables (`ps`).

### Key Provenance
- **User Keystore:** If `--ks` is provided on the CLI, that keystore is used with provided or default credentials.
- **Generated Default Keystore:** If no keystore is specified:
  - Keystore path: `~/.apkrevive/user_<username>.p12` ([`signer.py:51`](apkrevive/core/signer.py#L51)).
  - Key alias: `apkrevive_<username>` ([`signer.py:53`](apkrevive/core/signer.py#L53)).
  - Keystore password: Generated using `secrets.token_hex(16)` and stored in `~/.apkrevive/user_<username>.pwd` with strict file permissions `0600` ([`signer.py:58-69`](apkrevive/core/signer.py#L58-L69)).
  - Generation mechanism: If the `.p12` file does not exist, [`ensure_keystore()`](apkrevive/core/signer.py#L96-L121) executes JDK `keytool`:
    ```bash
    keytool -genkeypair -v -keystore <ks_path> -storetype PKCS12 -storepass <pass> -alias <alias> -keypass <pass> -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=ApkRevive (<alias>),O=ApkRevive,C=US"
    ```
- **Hardcoded Key Risk:** **NO hardcoded private keys or static passwords exist in the codebase.** Keystores are generated dynamically per-user.

### Critical Operational Caveats
- **Loss of Google Play Update Capability:** Modifying and re-signing an APK invalidates the original developer certificate. Any attempt to install an updated APK over an existing version fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`.
- **Signature-Based Licensing Breakdown:** Applications utilizing Google Play Licensing (LVL), signature verification, or anti-tamper checksums fail immediately upon boot.
- **Missing Post-Signing Verification:** Currently, [`revive_cmd()`](apkrevive/cli/__init__.py#L335) checks the exit code of `sign_apk()`, but does not run `apksigner verify --print-certs` to assert signature validity.

---

## 5. 16KB ELF Handling: Audit vs. Rewrite & Modulo Congruence

The 16KB handling logic is distributed across [`apkrevive/core/elf.py`](apkrevive/core/elf.py), [`apkrevive/core/elf16k.py`](apkrevive/core/elf16k.py), and [`apkrevive/core/elf_surgeon.py`](apkrevive/core/elf_surgeon.py).

### Audit vs. Rewrite Analysis
- **Does it rewrite ELF segments? NO.**
  - In [`apkrevive/core/elf_surgeon.py:25-35`](apkrevive/core/elf_surgeon.py#L25-L35), `rewrite_elf_16kb(data)` calls `elf16k.fix(data)`.
  - In [`apkrevive/core/elf16k.py:216-240`](apkrevive/core/elf16k.py#L216-L240), `fix(data)` evaluates the binary:
    - If `ALIGNED`: returns `data, []`.
    - If `COMPAT_ONLY`: returns `data, ["4KB-linked ELF cannot have virtual addresses shifted without binary relinking; Android 15+ pageSizeCompat backcompat mode required"]`.
    - If `UNSAFE`: returns `data, [f"Unsafe ELF layout cannot be repaired..."]`.
  - In all cases, `fix(data)` returns the original `data` untouched.
  - **The ELF rewriter is strictly an audit tool.** It does not modify binary bytes, shift ELF program headers, pad loadable segments, or rewrite relocation tables.

### Congruence and Collision Mechanics
In [`apkrevive/core/elf16k.py#L146-L213`](apkrevive/core/elf16k.py#L146-L213), the engine evaluates three strict criteria:
1. **Self-Congruence:**
   $$\text{seg.p\_vaddr} \pmod{\text{seg.p\_align}} == \text{seg.p\_offset} \pmod{\text{seg.p\_align}}$$
   If false, classified as `UNSAFE`.
2. **16KB Kernel Congruence:**
   $$\text{seg.p\_vaddr} \pmod{0x4000} == \text{seg.p\_offset} \pmod{0x4000}$$
   Evaluated for every `PT_LOAD` segment.
3. **Segment Page Isolation (Collision Detection):**
   ```python
   s1_page_end = (s1.p_vaddr + s1.p_memsz + PAGE_16KB - 1) // PAGE_16KB
   s2_page_start = s2.p_vaddr // PAGE_16KB
   if s2_page_start < s1_page_end:
       has_page_collision = True
   ```
   On 16KB kernels, `bionic` uses `mmap()` with `MAP_FIXED` to map each `PT_LOAD` segment into memory on 16KB page boundaries. If segment 1 and segment 2 share a 16KB virtual address page (`s2_page_start < s1_page_end`), the second `mmap()` call unmaps the end of the first segment, resulting in `SIGSEGV` or memory corruption.
   - If an ELF has `p_align == 16384` but suffers from page collision, `elf16k.py` flags it as a **fake header patch** and returns `UNSAFE` ([`elf16k.py:193-201`](apkrevive/core/elf16k.py#L193-L201)).

### Triage Verdict on 16KB
- **Android 15 (API 35) on 16KB Kernel:** Fails closed. Because Android 15 lacks the `pageSizeCompat` manifest backcompat flag, triage emits `VERDICT: RED` with `INCOMPATIBLE_PAGE_SIZE` ([`triage.py:210-219`](apkrevive/core/triage.py#L210-L219)).
- **Android 16+ (API 36+):** Returns `VERDICT: YELLOW` and injects `android:pageSizeCompat="enabled"` into `AndroidManifest.xml` ([`triage.py:220-223`](apkrevive/core/triage.py#L220-L223), [`axml.py:547-548`](apkrevive/core/axml.py#L547-L548)).

---

## 6. Binary AXML Mutation Engine: Internal Mechanics & Invariants

The binary XML engine is located in [`apkrevive/core/axml.py`](apkrevive/core/axml.py).

### How AXML Edits Handle String Pool, Resource Maps, Ordering, and Sizes

1. **String Pool (`CHUNK_STRING_POOL = 0x0001`):**
   - **Parsing (`parse()`):** Correctly unpacks both UTF-8 and UTF-16LE strings based on header flags (`flags & 0x0100`) and offset tables ([`axml.py:162-196`](apkrevive/core/axml.py#L162-L196)).
   - **Serialization (`serialize()`):**
     - Completely discards the original string pool chunk!
     - Constructs a brand-new string pool from scratch.
     - Seeds the pool by appending `ANDROID_NS`, `"android"`, and every key in `KNOWN_RESOURCE_IDS` (22 items) ([`axml.py:395-399`](apkrevive/core/axml.py#L395-L399)).
     - Encodes all strings strictly as UTF-8 (flags `0x0100`), converting original UTF-16 strings to UTF-8 ([`axml.py:424-432`](apkrevive/core/axml.py#L424-L432)).
     - Discards all string styles: sets `style_count = 0` and `styles_start = 0` ([`axml.py:442`](apkrevive/core/axml.py#L442)). (Note: [`append_string_to_pool()`](apkrevive/core/axml.py#L241-L340) supports style preservation, but `serialize()` does not use it).

2. **Resource-ID Map (`CHUNK_RESOURCE_MAP = 0x0180`):**
   - In [`axml.py:444-449`](apkrevive/core/axml.py#L444-L449), the resource map is populated by iterating over every string in the new string pool:
     ```python
     res_ids = [KNOWN_RESOURCE_IDS.get(s, 0) for s in string_list]
     ```
   - If an attribute name matches `KNOWN_RESOURCE_IDS`, its integer resource ID (`0x0101xxxx`) is written; otherwise `0` is emitted.
   - Any custom framework or OEM attributes not registered in `KNOWN_RESOURCE_IDS` lose their resource ID mapping.

3. **Attribute Ordering Invariant:**
   - Android's `libandroidfw` (`ResXMLTree::getAttribute()`) performs binary search on attribute resource IDs. If attributes are out of numerical order, lookups fail.
   - In [`axml.py:465-472`](apkrevive/core/axml.py#L465-L472):
     ```python
     def attr_sort_key(attr: AxmlAttribute):
         attr_base_name = attr.name.split(":")[-1]
         res_id = KNOWN_RESOURCE_IDS.get(attr.name, KNOWN_RESOURCE_IDS.get(attr_base_name, 0))
         if res_id > 0:
             return (0, res_id)
         return (1, 0)
     ```
   - Attributes with `res_id > 0` are sorted in strict ascending order, followed by attributes without resource IDs in stable order.

4. **Chunk Sizes and Header Calculations:**
   - Element chunks: `elem_size = 36 + (attr_count * 20)` ([`axml.py:475`](apkrevive/core/axml.py#L475)).
   - Attribute record format: `<III HBB I` (20 bytes: `ns_idx:4`, `name_idx:4`, `raw_val_idx:4`, `typed_val_size:2` (8), `res0:1` (0), `data_type:1`, `data:4`) ([`axml.py:490`](apkrevive/core/axml.py#L490)).
   - Total file size: `8 + len(sp_chunk) + len(rm_chunk) + len(start_ns) + len(body_bytes) + len(end_ns)` ([`axml.py:501-502`](apkrevive/core/axml.py#L501-L502)).

5. **Round-Trip Byte Fidelity:**
   - **Byte Round-Trip Fails:** Because `serialize()` generates a synthetic string pool with predefined known keys, forces UTF-8 encoding, drops non-Android namespace chunks, resets line numbers to 1, and strips original style tables, running `parse(data) -> serialize()` produces completely different bytes than the original input file.

---

## 7. Android Companion App (`apkrevive-android`) & Shizuku IPC Review

The companion app is located in [`apkrevive-android`](apkrevive-android).

### Flow & Permissions
- **IPC Binding:** Binds to Shizuku via `ShizukuBinderWrapper` to acquire privileged `IPackageManager` and `IPackageInstaller` interfaces ([`ShizukuPackageInstallerBridge.kt:268-284`](apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L268-L284)).
- **Low-targetSdk Bypass Flag:**
  - In Android 14+ (API 34+), `PackageManager.INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK` is `0x01000000`.
  - In [`ShizukuPackageInstallerBridge.kt:221-242`](apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L221-L242), `applyBypassLowTargetSdkFlag(params)` reflectively searches `params.installFlags` and sets `installFlags |= 0x01000000`.
  - **Per-API Level Availability & Fallback:**
    - On API < 34, `0x01000000` is not an install bypass flag (Android 14 introduced this floor). If `installFlags` is modified on API < 34, it may conflict with other internal flags.
    - If reflection fails or the field is absent, it logs a warning and returns `false`, proceeding with standard install.
- **Session Lifecycle & DeadObject Protection:**
  - Streams APK bytes into `session.openWrite("package", 0L, apkSize)` with progress reporting ([`ShizukuPackageInstallerBridge.kt:314-337`](apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L314-L337)).
  - Broadcast receiver [`InstallResultReceiver`](apkrevive-android/app/src/main/java/com/apkrevive/installer/InstallResultReceiver.kt) catches completion intent.
  - In case of failure or timeout (60s), [`abandonSessionSafely()`](apkrevive-android/app/src/main/java/com/apkrevive/installer/ShizukuPackageInstallerBridge.kt#L427-L457) catches `DeadObjectException` and `RemoteException` without crashing.
- **Bionic Greylist Inspection Discrepancy:**
  - In [`ApkInspector.kt:268-274`](apkrevive-android/app/src/main/java/com/apkrevive/core/ApkInspector.kt#L268-L274), the Android app checks if the file name of a *bundled* library in the APK matches `BIONIC_GREYLIST`. It does **not** inspect `DT_NEEDED` ELF headers. Apps linking against private platform libraries (e.g. `libandroid_runtime.so`) do not bundle them, so the companion app fails to detect private library linkages.
- **Hardcoded Paths & Key Inspection:**
  - No cryptographic keys or private tokens are hardcoded.
  - Local configuration [`apkrevive-android/local.properties`](apkrevive-android/local.properties#L1) contains a machine-specific path (`<android-sdk-path>`) which should be untracked in git.
  - [`canaries/build_canaries.py:34`](canaries/build_canaries.py#L34) and [`L84`](canaries/build_canaries.py#L84) contain hardcoded machine paths (`<local-sdk-path>`) in fallback lists.

---

## 8. Summary of Findings & Action Plan for Subsequent Phases

| Focus Area | Identified Risk / Finding | Phase Scheduled |
|---|---|---|
| **Hygiene** | Single-source version mismatch (`0.3.3` in README vs `0.4.0` in pyproject/changelog). Apache 2.0 LICENSE already in place. | **Phase 1** |
| **AXML Round-Trip** | Current serializer replaces string pool and mutates formatting. Needs round-trip test and validation against `aapt2 dump xmltree` / `apkanalyzer`. | **Phase 2** |
| **ELF Segment Alignment** | `elf16k.fix()` is an audit returning byte-identical binaries; if realignment is not feasible, unfixable 16KB ELFs must strictly fail closed (RED). | **Phase 2** |
| **Signing Pipeline** | Add post-revive `apksigner verify --print-certs` verification; ensure user-supplied keystore support; document Play update and signature-licensing breakage. | **Phase 2** |
| **Triage Hardening** | 32-bit only native libs on 64-bit only target devices must fail closed (RED) instead of YELLOW. | **Phase 2** |
| **New Triage Detections** | Detect hidden-API reflection, GLES 1.x, dead SDKs (LVL, Maps v1, legacy billing), TEXTREL, cleartext/TLS, and scoped-storage assumptions with canary pairs. | **Phase 3** |
| **Corpus & Golden Tests** | Add F-Droid redistributable corpus download script with checksums; add golden-file tests for triage JSON; document 16KB AVD testing. | **Phase 4** |
| **Companion App Polish** | Clean machine-specific SDK paths; align `DT_NEEDED` private library detection between Kotlin and Python. | **Phase 5** |
