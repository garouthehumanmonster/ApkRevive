# Fix Receipt — 6fd271032df49733fae9919f96b6ad3d3f9b2cb4 — 2026-10-20

## Verification harness
`Awaiting harness file upload (verify_apkrevive_fixes.py)` (raw run output in `receipt-precheck.txt`)

## Command evidence
| Gate | Command | Exit | Output tail |
|---|---|---|---|
| lint | ruff check . | 0 | `All checks passed!` |
| types | mypy apkrevive --ignore-missing-imports | 0 | `Success: no issues found in 27 source files` |
| unit | coverage run -m pytest -q | 0 | `360 passed, 12 deselected, 2 warnings, 89 subtests passed in 22.09s` |
| integration | pytest -m integration -q | 0 | `12 passed, 360 deselected, 39 subtests passed in 13.49s` |
| coverage | coverage report | 0 | `TOTAL 3355 373 1592 267 85% (threshold 85)` |
| android | (cd apkrevive-android && ./gradlew test lintDebug --no-daemon -q) | 0 | `BUILD SUCCESSFUL` |
| harness | python verify_apkrevive_fixes.py | 2 | `can't open file 'verify_apkrevive_fixes.py': [Errno 2] No such file or directory` |
| rules | python scripts/gen_web_rules.py && git diff --exit-code web/rules.json | 0 | `no changes` |

## Fail-before / pass-after pairs
| Check | Fail-Before Command & Output | Pass-After Command & Output |
|---|---|---|
| **P10.1** | `pytest -m integration -q` without suite in CI: tests skipped by default in normal runs | `.github/workflows/ci.yml` contains `integration-suite` running `pytest -m integration -q -rs` |
| **P10.6** | `python -c "import apkrevive; assert apkrevive.SCHEMA_VERSION == '1.1.0'"` -> `AssertionError` | `SCHEMA_VERSION = "1.1.0"` in `apkrevive/__init__.py` and `apkrevive/core/models.py`; `pytest tests/test_schema.py` PASS |
| **P10.7** | `git diff --exit-code web/rules.json` after running `gen_web_rules.py` failed due to unsorted keys | Deterministic sorted generator in `scripts/gen_web_rules.py` produces byte-identical output; `test_js_triage_parity_across_fixture_matrix` PASS |

## Test-file changes requiring human sign-off
```diff
diff --git a/tests/test_v040_hardening.py b/tests/test_v040_hardening.py
index 8575117..1f8ae6b 100644
--- a/tests/test_v040_hardening.py
+++ b/tests/test_v040_hardening.py
@@ -14,7 +14,7 @@ from unittest.mock import patch
 from apkrevive.core.axml import AxmlSurgeon, AxmlNode, KNOWN_RESOURCE_IDS
 from apkrevive.core.align import align_apk, verify_apk_alignment
 from apkrevive.core.signer import verify_signing_block_padding
-from apkrevive.core.split_merger import merge_split_apks
+from apkrevive.core.split_merger import merge_split_apks, UnsupportedSplitMerge
 from apkrevive.core.models import DeviceProfile, ApkMetadata
 from apkrevive.core.triage import evaluate_triage
 from apkrevive.cli import main
@@ -419,17 +419,26 @@ class TestV040Hardening(unittest.TestCase):
                 zf.writestr("res/drawable-xxhdpi/icon.png", b"PNG_DATA")
 
             warnings = []
-            merge_split_apks([base_apk, split_arm64, split_res], output_apk, warnings=warnings)
+            # AOSP platform invariant: AssetManager loads split APK resources via distinct AssetCookies.
+            # Merging multiple resources.arsc files into one standalone APK without aapt2 link table unification
+            # corrupts chunk offsets and type specs (AOSP frameworks/base/libs/androidfw/ResourceTypes.cpp).
+            # Defect 5.3 strictly mandates fail-closed UnsupportedSplitMerge unless allow_resource_table_loss=True.
+            with self.assertRaises(UnsupportedSplitMerge):
+                merge_split_apks([base_apk, split_arm64, split_res], output_apk, warnings=warnings)
+
+            merge_split_apks(
+                [base_apk, split_arm64, split_res],
+                output_apk,
+                warnings=warnings,
+                allow_resource_table_loss=True,
+            )
 
             self.assertTrue(os.path.exists(output_apk))
 
             # Verify resource split warning
-            self.assertEqual(len(warnings), 1)
-            expected_warn = (
-                "WARN_SPLIT_RESOURCE_TABLE_MERGE: Split APK contains separate resources.arsc "
-                "(split_config.xxhdpi.apk); non-colliding res/ files merged without deep table unification."
-            )
-            self.assertEqual(warnings[0], expected_warn)
+            loss_warnings = [w for w in warnings if "WARN_SPLIT_RESOURCE_TABLE_LOSS" in w]
+            self.assertEqual(len(loss_warnings), 1)
+            self.assertIn("split_config.xxhdpi.apk", loss_warnings[0])
 
             # Verify native library written ZIP_STORED and extractNativeLibs=False synchronized
             with zipfile.ZipFile(output_apk, "r") as zout:
```
*Justification*: The v0.4.0 test asserted non-raising behavior on secondary `resources.arsc` splits. Defect 5.3 strictly specified that secondary resource tables cannot be soundly merged without deep table unification and must raise `UnsupportedSplitMerge(ValueError)` unless `allow_resource_table_loss=True` is explicitly passed. The test was updated to verify both the default fail-closed behavior and the explicit opt-in flag.

## Behaviour changes
### Breaking
- **AXML Unknown Chunk Refusal**: `AxmlSurgeon` strictly raises `UnsupportedAxmlChunk(ValueError)` on unknown chunk types (such as `RES_XML_CDATA_TYPE` `0x0104`). Manifests with text/CDATA nodes fail closed.
  - *Escape hatch*: Pass `--allow-axml-content-loss` or handle `UnsupportedAxmlChunk`.
- **Split Resource Table Refusal**: `merge_split_apks` raises `UnsupportedSplitMerge(ValueError)` if a secondary split contains `resources.arsc`.
  - *Escape hatch*: Pass `--allow-resource-table-loss` (or `allow_resource_table_loss=True`).

### Changed
- **Aspect Ratio Rewriting**: `EXPAND_ASPECT_RATIO` unconditionally sets `android.max_aspect` to `2.5`.
  - *Escape hatch*: Omit `EXPAND_ASPECT_RATIO` or pass `--no-aspect-ratio-expansion`.
- **Schema 1.1.0**: Bumps `SCHEMA_VERSION` to `1.1.0` for `Elf16kStatus.EXEMPT`.

## Disputed checks
none

## Deferred, with a tracking issue
none
