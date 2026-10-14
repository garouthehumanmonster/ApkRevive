# ApkRevive Audit Report (Milestone 0)

**Date:** 2026-10-14  
**Audit Scope:** Codebase inspection (`apkrevive/`, `apkrevive-android/`, `canaries/`, `tests/`), test execution (`python -m unittest discover -s tests`), canary build execution (`canaries/build_canaries.py`), and companion Android build (`gradlew test`).

---

## 1. Executive Summary

ApkRevive provides a functional baseline for diagnosing legacy APKs, patching binary `AndroidManifest.xml` files in-place, aligning ZIP archives, and installing low-targetSdk APKs on modern Android versions using ADB or Shizuku.

However, the audit identified significant gaps between claims in `README.md` and actual code, including:
1. False claims regarding native ELF `p_align` rewriting.
2. Insecure, hardcoded signing keystore generation without user keystore support.
3. Lack of idempotency guarantees across consecutive `revive` runs.
4. Vulnerabilities to malformed/malicious ZIP archives (Zip-Slip, Zip Bombs, Truncation).
5. Missing core documentation and hygiene files (`LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`).
6. Premature claims of "production-grade" readiness for software in early alpha.

---

## 2. Test & Build Execution Results

### 2.1 Python Test Suite
- **Command:** `python -m unittest discover -s tests`
- **Result:** PASSED (26 tests, 6.255s)
- **Breakdown:**
  - `test_align.py` (2 tests): ELF PT_LOAD alignment parsing & ZIP entry boundary alignment.
  - `test_axml.py` (3 tests): AXML AST parse/serialize roundtrip, manifest mutation, idempotency check.
  - `test_canaries.py` (8 tests): 8 canary test pairs (control vs. failing) verified against triage & extractor.
  - `test_cli.py` (5 tests): CLI triage, OBB push, probe, revive.
  - `test_extractor.py` (1 test): Synthetic APK metadata extraction.
  - `test_obb.py` (1 test, 6 sub-tests): OBB filename validation, path traversal, version checks.
  - `test_triage.py` (1 test, 16 sub-tests): 16 triage decision vectors.

### 2.2 Canary Build Pipeline
- **Command:** `python canaries/build_canaries.py`
- **Result:** PASSED (16 signed canary APKs + 2 OBB expansion files compiled to `canaries/build/`).

### 2.3 Android Companion App Build
- **Command:** `.\gradlew test` in `apkrevive-android/`
- **Result:** PASSED (All Gradle unit tests passed: `ApkInspectorTest`, `TriageEvaluatorTest`, `ObbValidatorTest`, `ShizukuBridgeReflectionTest`, `ApkReviveViewModelTest`).

---

## 3. README Claims vs. Implemented & Tested

| Claim in README | Implementation Status | Evidence / Gap |
|---|---|---|
| **"Production-grade"** | **False / Exaggerated** | Status is alpha. Lacks basic hardening, error handling, custom keystores, and fuzz testing. |
| **"Apache 2.0 License"** | **Missing** | Badge and text link to `LICENSE`, but `LICENSE` file does not exist in repository. |
| **"16KB ELF & ZipAligner (p_align)"** | **Misleading / Incomplete** | `align.py` aligns ZIP container offsets for uncompressed entries. **It does NOT rewrite ELF `p_align`**. `elf.py` only *reads* `p_align`. If `p_align < 16384` on Android 15, triage returns `RED`. On Android 16, it only adds `android:pageSizeCompat="enabled"` to manifest. No binary ELF segment patching exists. |
| **"Bionic Linker Greylist Detection"** | **Partial (64-bit only)** | `extractor.py` only scans 64-bit native libraries (`arm64-v8a`, `x86_64`) for `DT_NEEDED`. 32-bit native libraries (`armeabi-v7a`, `x86`) are ignored despite being vulnerable to linker namespace restrictions on Android 7+. |
| **"Deterministic V2/V3 APK Re-Signer"** | **Insecure & External Only** | No internal fallback exists (contrary to prerequisites claim). Shells out to `apksigner` with a single shared RSA debug key (`~/.apkrevive/debug.p12`) and hardcoded credentials (`pass:android`). No user keystore flags exist. |
| **"Bytecode Shim Injection"** | **Precompiled Blob Without Build Script** | `shim.dex` is committed as a binary blob. While `ApkReviveInitProvider.java` is present, there is no reproducible build script or hash verification in CI/tests. |
| **CLI Options & UX** | **Missing Features** | Missing `--json` flag (always outputs JSON), missing `--version`, missing `--dry-run`, missing `doctor` diagnostic command, non-standard exit codes (triage returns 1 for `YELLOW`). |
| **Companion App** | **Implemented** | `apkrevive-android` is implemented with Compose and Shizuku binder reflection, tested via JVM unit tests. |

---

## 4. Bugs & Logic Flaws

1. **Non-Existent ELF `p_align` Rewriting:**
   - `README.md` and diagrams claim 16KB ELF alignment patching.
   - Code reality: `elf.py` only reads `p_align`. `triage.py` flags 4KB ELF on 16KB OS as fatal `RED` on API < 36. If a tool claims to revive an APK for 16KB devices, it must clarify that binary ELF segments cannot be safely rewritten without relocations, and only Android 16's page size compatibility mode is supported.
2. **`revive` Lacks True Idempotency:**
   - In `apkrevive/cli.py`, if an APK is revived multiple times, `classes.dex` checks look for `b"ApkReviveInitProvider"`, but multi-dex handling and repeated AXML attribute injections can diverge or append unnecessary dex files if previously modified under different flags.
3. **Silent Failure in `ensure_keystore`:**
   - In `apkrevive/core/signer.py`:
     ```python
     try:
         subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     except Exception:
         pass
     return str(path)
     ```
     If `keytool` fails or is missing, the exception is swallowed, and a non-existent path is returned. `sign_apk` then fails cryptically.
4. **Memory Exhaustion on Large APKs in `align_apk`:**
   - In `apkrevive/core/align.py`, `f_in.read()` loads the entire APK into memory. For large 1GB+ game APKs, this creates massive memory pressure and risks `MemoryError` crashes.
5. **Exit Code Semantics in CLI:**
   - `triage_cmd` returns exit code `1` for `YELLOW` verdicts (`0 if res["verdict"] == "GREEN" else 1`). A `YELLOW` verdict means the app is compatible after transformation, not an execution error.

---

## 5. Crash Risks & Edge Cases

1. **Missing or Corrupt `AndroidManifest.xml`:**
   - In `cli.py`: `manifest_data = zf.read("AndroidManifest.xml")` raises an unhandled `KeyError` if the APK lacks a manifest or is corrupted.
2. **Zip-Slip & Path Traversal:**
   - While `obb.py` checks for `..`, `cli.py` processes raw `zipfile.ZipInfo` entries from input APKs directly. Malicious ZIP entries containing `../` or absolute paths are not sanitized before repackaging.
3. **Zip Bomb / Decompression Abuse:**
   - No quota checks on uncompressed file sizes or expansion ratios when reading archive entries.
4. **Truncated ZIP Central Directory:**
   - `align.py` unpacks binary ZIP structures without validating boundary sizes against remaining buffer length. Truncated Central Directories cause uncaught `struct.error`.
5. **Dalvik Multi-Dex Crash on API < 21:**
   - Injecting `classes2.dex` containing a `ContentProvider` on legacy Android (< 5.0) causes runtime crashes on launch because Dalvik does not load secondary DEX files prior to ContentProvider initialization without MultiDexApplication support.
6. **Split APKs / Android App Bundles:**
   - The CLI assumes single monolithic APKs. Attempting to revive a split config APK will corrupt package structure.

---

## 6. Security Concerns

1. **Shared Insecure Signing Key:**
   - Every revived APK is signed with the same debug key generated in `~/.apkrevive/debug.p12` with password `android`.
   - Any malicious app signed with the same key could potentially exploit signature-level permissions or shared UIDs on devices where multiple revived apps are installed.
2. **Silent Signature Mismatch & Data Loss:**
   - Re-signing changes the APK's certificate fingerprint. When installing over an existing original app, Android rejects the install with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`.
   - The user must uninstall the existing app, resulting in total loss of local app data, save files, and preferences. ApkRevive must prominently warn users of this consequence.
3. **Self-Signature Checks & DRM:**
   - Triage flags `has_self_sig_check`, but `revive` proceeds anyway without warning if executed via CLI.
4. **Lack of Legal & Ownership Disclaimer:**
   - Modifying and re-signing third-party binaries requires explicit user authorization. The tool must include legal disclaimers instructing users to only modify applications they have rights to modify.

---

## 7. Recommended Action Plan for Subsequent Milestones

- **Milestone 1 (Repo Hygiene):** Add `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`. Single version source in `pyproject.toml` + `apkrevive --version`. Relabel status from "production-grade" to "alpha". Add Known Limitations and legal disclaimers.
- **Milestone 2 (Trust & Signing):** Provide reproducible build script for `shim.dex` and verify hash in test suite. Support custom user keystores (`--ks`, `--ks-pass`, `--ks-alias`) and generate unique per-user keys. Add signature change / data loss warnings.
- **Milestone 3 (Correctness):** Confirm and document that `p_align` is not rewritten (return RED/YELLOW appropriately). Make `revive` idempotent. Harden against malformed ZIPs (Zip-Slip, Zip Bomb, truncation).
- **Milestone 4 (Triage Coverage):** Expand triage warnings and remediation for 32-bit only apps, scoped storage/OBB on Android 11+, hidden APIs, cleartext TLS, and deprecated permissions.
- **Milestone 5 (CI & UX):** Add GitHub Actions matrix, ruff, mypy, coverage. CLI improvements (`--json`, `--dry-run`, exit codes per verdict, `apkrevive doctor`).
- **Milestone 6 (Evidence & Docs):** `docs/COMPATIBILITY.md`, sample before/after runs, app screenshots.
