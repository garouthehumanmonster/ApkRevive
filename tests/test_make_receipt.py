"""
tests/test_make_receipt.py - Unit tests for scripts/make_receipt.py.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.make_receipt import (
    create_receipt,
    main,
    strip_identifying_info,
    validate_receipt,
)


class TestMakeReceipt(unittest.TestCase):
    def test_create_and_validate_receipt(self):
        receipt = create_receipt(
            model="sdk_gphone16k_x86_64",
            api=37,
            abi="x86_64",
            page_size=16384,
            script="scripts/run_emulator_corpus.py",
            date="2026-10-18",
        )
        self.assertEqual(receipt["device_model"], "sdk_gphone16k_x86_64")
        self.assertEqual(receipt["api_level"], 37)
        self.assertEqual(receipt["abi"], "x86_64")
        self.assertEqual(receipt["page_size"], 16384)
        self.assertFalse(receipt["simulated"])
        validate_receipt(receipt)

    def test_validate_receipt_rejections(self):
        # 1. simulated True rejected
        with self.assertRaises(ValueError):
            validate_receipt({
                "device_model": "test",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "s.py",
                "simulated": True,
            })

        # 2. Forbidden keys rejected
        with self.assertRaises(ValueError):
            validate_receipt({
                "device_model": "test",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "s.py",
                "simulated": False,
                "serial": "emulator-5554",
            })

        # 3. Missing keys rejected
        with self.assertRaises(ValueError):
            validate_receipt({
                "device_model": "test",
                "api_level": 37,
            })

    def test_strip_identifying_info(self):
        s = strip_identifying_info("device-serial-1234 on C:\\Users\\Administrator\\Desktop", "device-serial-1234")
        self.assertNotIn("device-serial-1234", s)
        self.assertNotIn("Administrator", s)

    def test_cli_main_write_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "sub" / "receipt.json"
            code = main([
                "--model", "pixel_test",
                "--api", "35",
                "--abi", "x86_64",
                "--page-size", "16384",
                "--output", str(out_file),
            ])
            self.assertEqual(code, 0)
            self.assertTrue(out_file.exists())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["device_model"], "pixel_test")
            self.assertEqual(data["api_level"], 35)
            self.assertFalse(data["simulated"])


if __name__ == "__main__":
    unittest.main()
