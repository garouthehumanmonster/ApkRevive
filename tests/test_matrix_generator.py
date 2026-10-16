"""test_matrix_generator.py - Unit tests for scripts/generate_matrix.py (Item 4 EVIDENCE).

Verifies:
- JSON results schema validation and loading.
- Environment matching logic.
- Markdown table formatting with all 8 canaries and standard environments.
- Unrun canary/environment pairs displaying 'NOT RUN'.
- Updating docs/COMPATIBILITY.md between delimiters.
- CLI main() interface.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.generate_matrix import (
    DELIMITER_END,
    DELIMITER_START,
    SCHEMA_FIELD_TYPES,
    STANDARD_CANARIES,
    STANDARD_ENVIRONMENTS,
    format_evidence_log,
    format_markdown_table,
    format_results_section,
    load_results,
    main,
    match_environment,
    update_compatibility_doc,
    validate_result_schema,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_RESULTS_DIR = REPO_ROOT / "results"
REAL_COMPATIBILITY_DOC = REPO_ROOT / "docs" / "COMPATIBILITY.md"


class TestMatrixGenerator(unittest.TestCase):
    def test_load_real_results(self):
        """Loads and verifies the 8 real results from the repo's results/ directory."""
        self.assertTrue(REAL_RESULTS_DIR.exists(), f"results dir missing at {REAL_RESULTS_DIR}")
        results = load_results(REAL_RESULTS_DIR)
        self.assertEqual(len(results), 8, f"Expected 8 results, got {len(results)}")

        loaded_canary_ids = {r["canary_id"] for r in results}
        for canary in STANDARD_CANARIES:
            self.assertIn(canary, loaded_canary_ids)

        for res in results:
            self.assertEqual(res["pass_fail"], "PASS")
            self.assertEqual(res["emulator_or_hardware"], "local_host")
            self.assertTrue(len(res["tool_commit"]) > 0)
            self.assertTrue(len(res["date"]) > 0)
            self.assertTrue(res["simulated"])

    def test_load_results_nonexistent_or_empty_dir(self):
        """Non-existent or empty directories should return an empty list gracefully."""
        self.assertEqual(load_results(REPO_ROOT / "non_existent_dir_123"), [])

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertEqual(load_results(tmp_dir), [])

    def test_schema_requires_simulated_field(self):
        """Receipt schema requires 'simulated' boolean field."""
        self.assertIn("simulated", SCHEMA_FIELD_TYPES)
        self.assertIs(SCHEMA_FIELD_TYPES["simulated"], bool)

    def test_simulated_receipt_renders_not_run_for_emulators(self):
        """Simulated receipts targeting emulators or hardware must render as NOT RUN."""
        sample = {
            "device_model": "Android Emulator API 35 (16KB)",
            "android_build": "sdk_gphone64_arm64-userdebug 15 AP2A (API 35)",
            "kernel_page_size": 16384,
            "refresh_rate": 60,
            "emulator_or_hardware": "emulator",
            "date": "2026-10-15",
            "tool_commit": "20778b3",
            "canary_id": "canary_page_size",
            "expected": "Pass",
            "observed": "Simulated pass",
            "pass_fail": "PASS",
            "simulated": True,
        }
        table = format_markdown_table([sample])
        lines = [line.strip() for line in table.strip().splitlines() if line.startswith("| `canary_page_size`")]
        self.assertTrue(len(lines) == 1)
        parts = [p.strip() for p in lines[0].split("|")[1:-1]]
        # Emulator API 35 column is index 3
        self.assertEqual(parts[3], "NOT RUN")

    def test_schema_validation_valid(self):
        """Valid schema dictionary passes validation."""
        valid_sample = {
            "device_model": "Pixel 8",
            "android_build": "AP2A.240805.005",
            "kernel_page_size": 16384,
            "refresh_rate": 120,
            "emulator_or_hardware": "hardware",
            "date": "2026-10-15",
            "tool_commit": "20778b3",
            "canary_id": "canary_page_size",
            "expected": "Pass on 16KB",
            "observed": "App loaded cleanly",
            "pass_fail": "PASS",
            "simulated": False,
        }
        # Should not raise
        validate_result_schema(valid_sample, "sample.json")

    def test_schema_validation_missing_field(self):
        """Missing field raises ValueError."""
        invalid_sample = {
            "device_model": "Pixel 8",
            "android_build": "AP2A.240805.005",
            "kernel_page_size": 16384,
            # missing refresh_rate
            "emulator_or_hardware": "hardware",
            "date": "2026-10-15",
            "tool_commit": "20778b3",
            "canary_id": "canary_page_size",
            "expected": "Pass",
            "observed": "Pass",
            "pass_fail": "PASS",
        }
        with self.assertRaises(ValueError) as ctx:
            validate_result_schema(invalid_sample, "sample.json")
        self.assertIn("Missing required field 'refresh_rate'", str(ctx.exception))

    def test_schema_validation_wrong_type(self):
        """Wrong field type raises ValueError."""
        invalid_sample = {
            "device_model": "Pixel 8",
            "android_build": "AP2A.240805.005",
            "kernel_page_size": "16384",  # str instead of int
            "refresh_rate": 120,
            "emulator_or_hardware": "hardware",
            "date": "2026-10-15",
            "tool_commit": "20778b3",
            "canary_id": "canary_page_size",
            "expected": "Pass",
            "observed": "Pass",
            "pass_fail": "PASS",
        }
        with self.assertRaises(ValueError) as ctx:
            validate_result_schema(invalid_sample, "sample.json")
        self.assertIn("Field 'kernel_page_size'", str(ctx.exception))

    def test_schema_validation_invalid_enum_values(self):
        """Invalid emulator_or_hardware or pass_fail raises ValueError."""
        sample1 = {
            "device_model": "Pixel 8",
            "android_build": "AP2A",
            "kernel_page_size": 4096,
            "refresh_rate": 60,
            "emulator_or_hardware": "cloud_device",  # invalid
            "date": "2026-10-15",
            "tool_commit": "20778b3",
            "canary_id": "canary_install_floor",
            "expected": "Pass",
            "observed": "Pass",
            "pass_fail": "PASS",
            "simulated": False,
        }
        with self.assertRaises(ValueError) as ctx:
            validate_result_schema(sample1, "sample.json")
        self.assertIn("Invalid 'emulator_or_hardware'", str(ctx.exception))

        sample2 = sample1.copy()
        sample2["emulator_or_hardware"] = "hardware"
        sample2["pass_fail"] = "SKIPPED"  # invalid
        with self.assertRaises(ValueError) as ctx:
            validate_result_schema(sample2, "sample.json")
        self.assertIn("Invalid 'pass_fail'", str(ctx.exception))

    def test_match_environment(self):
        """Verifies environment matching for various configurations."""
        # 1. Local host
        self.assertEqual(
            match_environment({"emulator_or_hardware": "local_host", "device_model": "Host Test Harness"}),
            "Local Verification Rig",
        )

        # 2. Explicit environment name
        self.assertEqual(
            match_environment({"environment": "Android Emulator API 34 (4KB)"}),
            "Android Emulator API 34 (4KB)",
        )

        # 3. Emulator API 34 (4KB)
        self.assertEqual(
            match_environment({
                "emulator_or_hardware": "emulator",
                "kernel_page_size": 4096,
                "android_build": "sdk_gphone64_arm64-userdebug 14 UP1A (API 34)",
            }),
            "Android Emulator API 34 (4KB)",
        )

        # 4. Emulator API 35 (16KB)
        self.assertEqual(
            match_environment({
                "emulator_or_hardware": "emulator",
                "kernel_page_size": 16384,
                "android_build": "sdk_gphone64_arm64-userdebug 15 AP2A (API 35)",
            }),
            "Android Emulator API 35 (16KB)",
        )

        # 5. Hardware API 35 (16KB)
        self.assertEqual(
            match_environment({
                "emulator_or_hardware": "hardware",
                "kernel_page_size": 16384,
                "android_build": "AP2A.240805.005 (API 35)",
            }),
            "Physical Hardware API 35 (ARM64 16KB)",
        )

        # 6. Android 16 API 36 Preview (16KB)
        self.assertEqual(
            match_environment({
                "emulator_or_hardware": "emulator",
                "kernel_page_size": 16384,
                "android_build": "Android 16 Baklava Preview (API 36)",
            }),
            "Android 16 API 36 Preview (16KB)",
        )

        # 7. Unmatched profile
        self.assertIsNone(
            match_environment({
                "emulator_or_hardware": "other",
                "device_model": "Unknown",
            })
        )

    def test_render_table_contains_all_canaries_and_environments(self):
        """Table output must contain headers for all standard environments and rows for all 8 canaries."""
        results = load_results(REAL_RESULTS_DIR)
        table_md = format_markdown_table(results)

        # Verify environment headers
        for env in STANDARD_ENVIRONMENTS:
            self.assertIn(env, table_md)

        # Verify all 8 canaries appear as rows
        for canary in STANDARD_CANARIES:
            self.assertIn(f"`{canary}`", table_md)

    def test_unrun_environments_display_not_run(self):
        """Unrun canary/environment pairs must output 'NOT RUN'."""
        results = load_results(REAL_RESULTS_DIR)
        table_md = format_markdown_table(results)

        lines = [line.strip() for line in table_md.strip().splitlines() if line.startswith("| `canary_")]
        self.assertEqual(len(lines), 8)

        for line in lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            # columns: Canary, Local Verification Rig, Emulator 34, Emulator 35, HW 35, Emulator 36
            self.assertEqual(len(parts), 6)
            # Local Verification Rig was run and passed
            self.assertEqual(parts[1], "PASS")
            # All other 4 unrun environments must be NOT RUN
            self.assertEqual(parts[2], "NOT RUN")
            self.assertEqual(parts[3], "NOT RUN")
            self.assertEqual(parts[4], "NOT RUN")
            self.assertEqual(parts[5], "NOT RUN")

    def test_empty_results_all_display_not_run(self):
        """When results list is empty, every single environment shows NOT RUN."""
        table_md = format_markdown_table([])
        lines = [line.strip() for line in table_md.strip().splitlines() if line.startswith("| `canary_")]
        self.assertEqual(len(lines), 8)
        for line in lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            for status in parts[1:]:
                self.assertEqual(status, "NOT RUN")

    def test_render_table_with_mock_results(self):
        """Verifies custom results with PASS and FAIL across various environments."""
        mock_results = [
            {
                "device_model": "Local Verification Rig",
                "android_build": "Host Harness",
                "kernel_page_size": 4096,
                "refresh_rate": 60,
                "emulator_or_hardware": "local_host",
                "date": "2026-10-15",
                "tool_commit": "abc1234",
                "canary_id": "canary_install_floor",
                "expected": "Pass",
                "observed": "Pass",
                "pass_fail": "PASS",
            },
            {
                "device_model": "Android Emulator API 34 (4KB)",
                "android_build": "API 34",
                "kernel_page_size": 4096,
                "refresh_rate": 60,
                "emulator_or_hardware": "emulator",
                "date": "2026-10-15",
                "tool_commit": "abc1234",
                "canary_id": "canary_page_size",
                "expected": "Fail on 4KB mismatch",
                "observed": "Crashed on load",
                "pass_fail": "FAIL",
            },
        ]
        table_md = format_markdown_table(mock_results)
        self.assertIn("FAIL", table_md)
        self.assertIn("PASS", table_md)
        self.assertIn("NOT RUN", table_md)

    def test_format_evidence_log(self):
        """Verifies evidence log table generation."""
        results = load_results(REAL_RESULTS_DIR)
        log_md = format_evidence_log(results)
        self.assertIn("| Canary | Environment | Tool Commit | Date | Observed Result | Status |", log_md)
        for canary in STANDARD_CANARIES:
            self.assertIn(f"`{canary}`", log_md)
        self.assertEqual(format_evidence_log([]), "")

    def test_format_results_section(self):
        """Verifies complete section rendering with table, environment descriptions, and evidence log."""
        results = load_results(REAL_RESULTS_DIR)
        section = format_results_section(results)
        self.assertIn("Local Verification Rig", section)
        self.assertIn("*Standard Environments Evaluated:*", section)
        self.assertIn("#### Recorded Verification Evidence", section)

    def test_update_compatibility_doc_with_existing_delimiters(self):
        """Updates file cleanly between existing delimiters without touching surrounding content."""
        initial_doc = (
            "# Header\n\n"
            "Some content before.\n\n"
            f"{DELIMITER_START}\nOld table\n{DELIMITER_END}\n\n"
            "Some content after.\n"
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(initial_doc)
            tmp_path = Path(tmp.name)

        try:
            update_compatibility_doc(tmp_path, "| New Table |")
            updated = tmp_path.read_text(encoding="utf-8")
            self.assertIn("Some content before.", updated)
            self.assertIn("Some content after.", updated)
            self.assertIn(DELIMITER_START, updated)
            self.assertIn(DELIMITER_END, updated)
            self.assertIn("| New Table |", updated)
            self.assertNotIn("Old table", updated)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_update_compatibility_doc_without_delimiters(self):
        """Inserts delimiters and content appropriately when delimiters are missing."""
        initial_doc = (
            "# Compatibility\n\n"
            "## 3. Canary Benchmark Matrix\n\n"
            "Summary table.\n\n"
            "---\n\n"
            "## 4. Execution Environments\n\n"
            "Environments content.\n"
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(initial_doc)
            tmp_path = Path(tmp.name)

        try:
            update_compatibility_doc(tmp_path, "| Inserted Table |")
            updated = tmp_path.read_text(encoding="utf-8")
            self.assertIn(DELIMITER_START, updated)
            self.assertIn(DELIMITER_END, updated)
            self.assertIn("| Inserted Table |", updated)
            self.assertIn("## 4. Execution Environments", updated)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_update_compatibility_doc_missing_file_raises(self):
        """Non-existent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            update_compatibility_doc("non_existent_file.md", "content")

    def test_cli_main_print_only(self):
        """main(['--print-only']) prints table to stdout and exits with 0."""
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["--print-only"])
        self.assertEqual(code, 0)
        output = captured.getvalue()
        self.assertIn("Local Verification Rig", output)
        self.assertIn("NOT RUN", output)

    def test_cli_main_file_update(self):
        """main(['--doc-path', ...]) writes to doc file."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(f"Header\n\n{DELIMITER_START}\nold\n{DELIMITER_END}\nFooter\n")
            tmp_path = Path(tmp.name)

        try:
            code = main(["--doc-path", str(tmp_path)])
            self.assertEqual(code, 0)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("PASS", content)
            self.assertIn("NOT RUN", content)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_actual_compatibility_doc_on_disk(self):
        """Verifies that docs/COMPATIBILITY.md on disk is up to date and valid."""
        self.assertTrue(REAL_COMPATIBILITY_DOC.exists(), "COMPATIBILITY.md missing")
        content = REAL_COMPATIBILITY_DOC.read_text(encoding="utf-8")
        self.assertIn(DELIMITER_START, content)
        self.assertIn(DELIMITER_END, content)
        for env in STANDARD_ENVIRONMENTS:
            self.assertIn(env, content)
        for canary in STANDARD_CANARIES:
            self.assertIn(f"`{canary}`", content)
        self.assertIn("NOT RUN", content)
        self.assertIn("PASS", content)


if __name__ == "__main__":
    unittest.main()
