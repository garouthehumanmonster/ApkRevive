"""
tests/test_survey.py - Unit tests for the compatibility survey runner.

Tests:
1. Manifest loading and validation (tests/corpus/survey.json).
2. Failure classification across all categories (ABI, GREYLIST, GLES1, DEAD_SDK, CRASH, INSTALL_FLOOR_BLOCKED, NONE, OTHER).
3. CLI argument parsing.
4. Mock execution flow and statistics aggregation.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.survey import (
    FAILURE_CATEGORIES,
    build_parser,
    classify_failure,
    load_manifest,
    main,
    parse_survey_args,
    run_apk_survey,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_survey_manifest_loading_and_validation() -> None:
    manifest_path = REPO_ROOT / "tests" / "corpus" / "survey.json"
    packages = load_manifest(manifest_path)

    assert len(packages) == 35
    for pkg in packages:
        assert "package_name" in pkg or "package" in pkg
        assert "target_sdk" in pkg
        assert "apk_name" in pkg
        assert "sha256" in pkg
        assert len(pkg["sha256"]) == 64
        assert isinstance(pkg["target_sdk"], int)
        assert pkg["target_sdk"] <= 25

    # Verify invalid manifest path raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        load_manifest(REPO_ROOT / "non_existent_manifest.json")


@pytest.mark.parametrize(
    "text,kwargs,expected",
    [
        # ABI
        ("INSTALL_FAILED_NO_MATCHING_ABIS", {}, "ABI"),
        ("INSTALL_FAILED_CPU_ABI_INCOMPATIBLE", {}, "ABI"),
        ("Error: 32-bit native on 64-bit device", {}, "ABI"),
        ("dlopen failed: \"/data/app/libfoo.so\" is 32-bit instead of 64-bit", {}, "ABI"),
        ("dlopen failed: unsupported ELF class: 1", {}, "ABI"),
        ("INCOMPATIBLE_DEVICE_ABI: [armeabi-v7a]", {}, "ABI"),
        # GREYLIST
        ("dlopen failed: library \"libandroid_runtime.so\" not found", {}, "GREYLIST"),
        ("bionic namespace restriction: library is not accessible for the namespace", {}, "GREYLIST"),
        ("dlopen failed: library \"libjavacore.so\" not found", {}, "GREYLIST"),
        ("dlopen failed: library \"libnativehelper.so\" not found", {}, "GREYLIST"),
        ("UNRESOLVABLE_SYSTEM_LIBRARY", {}, "GREYLIST"),
        # GLES1
        ("dlopen failed: library \"libGLESv1_CM.so\" not found", {}, "GLES1"),
        ("GLES1 context creation fail", {}, "GLES1"),
        ("eglCreateContext failed for GLESv1", {}, "GLES1"),
        ("WARN_GLES1_DEPRECATED", {}, "GLES1"),
        # DEAD_SDK
        ("java.lang.NoClassDefFoundError: Failed resolution of: Lcom/google/android/maps/MapActivity;", {}, "DEAD_SDK"),
        ("java.lang.ClassNotFoundException: com.android.vending.billing.IInAppBillingService", {}, "DEAD_SDK"),
        ("WARN_DEAD_SDKS: Defunct legacy SDKs detected", {}, "DEAD_SDK"),
        ("Fatal crash: dead sdk com.google.android.maps", {}, "DEAD_SDK"),
        # INSTALL_FLOOR_BLOCKED
        ("INSTALL_FAILED_DEPRECATED_SDK_VERSION: App version is lower than the minimum allowed version 24", {}, "INSTALL_FLOOR_BLOCKED"),
        ("TARGET_SDK_INSTALL_FLOOR: blocked on API 34+", {}, "INSTALL_FLOOR_BLOCKED"),
        # CRASH
        ("FATAL EXCEPTION: main\njava.lang.NullPointerException", {}, "CRASH"),
        ("AndroidRuntime: FATAL EXCEPTION", {}, "CRASH"),
        ("Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)", {}, "CRASH"),
        ("", {"has_crash": True}, "CRASH"),
        # NONE
        ("", {"is_alive": True, "has_crash": False}, "NONE"),
        ("Success", {}, "NONE"),
        ("", {"is_success": True}, "NONE"),
        # OTHER
        ("INSTALL_FAILED_INSUFFICIENT_STORAGE", {}, "OTHER"),
        ("Random unknown error message", {}, "OTHER"),
    ],
)
def test_failure_classification_categories(text: str, kwargs: dict, expected: str) -> None:
    category = classify_failure(text, **kwargs)
    assert category == expected
    assert category in FAILURE_CATEGORIES


def test_cli_argument_parsing() -> None:
    parser = build_parser()
    assert parser.description is not None

    # Default values
    args = parse_survey_args([])
    assert args.manifest == "tests/corpus/survey.json"
    assert args.bump_target_sdk == 24
    assert args.receipt_dir == "receipts"
    assert args.output is None
    assert args.flags is None
    assert args.max_apks is None
    assert args.package is None

    # Custom values
    custom_args = parse_survey_args(
        [
            "--adb", "/usr/bin/adb",
            "--device", "emulator-5554",
            "--manifest", "custom/survey.json",
            "--output", "results/custom.json",
            "--receipt-dir", "custom_receipts",
            "--screenshots-dir", "custom_screenshots",
            "--bump-target-sdk", "-1",
            "--flags", "--force", "--enable-60hz",
            "--max-apks", "10",
            "--package", "com.example.app",
        ]
    )
    assert custom_args.adb == "/usr/bin/adb"
    assert custom_args.device == "emulator-5554"
    assert custom_args.manifest == "custom/survey.json"
    assert custom_args.output == "results/custom.json"
    assert custom_args.receipt_dir == "custom_receipts"
    assert custom_args.screenshots_dir == "custom_screenshots"
    assert custom_args.bump_target_sdk == -1
    assert custom_args.flags == "--force --enable-60hz"
    assert custom_args.max_apks == 10
    assert custom_args.package == "com.example.app"


def test_mock_execution_flow_clean_success(tmp_path: Path) -> None:
    entry = {
        "package_name": "com.test.app",
        "apk_name": "test.apk",
        "target_sdk": 18,
        "abis": ["x86_64"],
    }
    dummy_apk = tmp_path / "test.apk"
    dummy_apk.write_bytes(b"dummy_apk_content")

    dev_info = {
        "model": "TestPhone",
        "sdk": "35",
        "abi": "x86_64",
        "page_size": "16384",
    }

    def fake_run_command(cmd, timeout=60):
        cmd_str = " ".join(cmd)
        if "install" in cmd and "--bypass-low-target-sdk-block" not in cmd and "-g" not in cmd:
            return {"exit_code": 1, "stdout": "Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION]", "stderr": "", "timed_out": False}
        if "install" in cmd:
            return {"exit_code": 0, "stdout": "Success", "stderr": "", "timed_out": False}
        if "revive" in cmd_str:
            # Produce revived APK
            out_idx = cmd.index("--output")
            revived_path = Path(cmd[out_idx + 1])
            revived_path.write_bytes(b"dummy_revived")
            report = {"verdict": "GREEN", "required_transforms": ["BUMP_TARGET_SDK"]}
            return {"exit_code": 0, "stdout": json.dumps(report), "stderr": "", "timed_out": False}
        if "monkey" in cmd:
            return {"exit_code": 0, "stdout": "Events injected: 1", "stderr": "", "timed_out": False}
        if "crash" in cmd_str:
            return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}

    with patch("scripts.survey.run_command", side_effect=fake_run_command), \
         patch("scripts.survey.poll_liveness_and_activity", return_value=(True, "1234", "MainActivity", True, False)):

        record = run_apk_survey(
            entry=entry,
            adb="adb",
            serial="emulator-5554",
            dev_info=dev_info,
            manifest_dir=tmp_path,
            screenshots_dir=tmp_path / "screenshots",
            temp_out_dir=tmp_path / "temp",
            bump_target_sdk=24,
        )

        assert record["direct_install"]["success"] is False
        assert record["direct_install"]["failure_category"] == "INSTALL_FLOOR_BLOCKED"
        assert record["bypass_install"]["success"] is True
        assert record["bypass_install"]["failure_category"] == "NONE"
        assert record["revive"]["success"] is True
        assert record["revive"]["verdict"] == "GREEN"
        assert record["revive_install"]["success"] is True
        assert record["revive_install"]["failure_category"] == "NONE"
        assert record["liveness"]["status"] == "ALIVE"
        assert record["liveness"]["failure_category"] == "NONE"
        assert record["overall_failure_category"] == "NONE"


def test_mock_execution_flow_crash_bionic_greylist(tmp_path: Path) -> None:
    entry = {
        "package_name": "com.test.greylist",
        "apk_name": "greylist.apk",
        "target_sdk": 18,
        "abis": ["x86_64"],
    }
    dummy_apk = tmp_path / "greylist.apk"
    dummy_apk.write_bytes(b"dummy_apk_content")

    dev_info = {
        "model": "TestPhone",
        "sdk": "35",
        "abi": "x86_64",
        "page_size": "16384",
    }

    def fake_run_command(cmd, timeout=60):
        cmd_str = " ".join(cmd)
        if "install" in cmd:
            return {"exit_code": 0, "stdout": "Success", "stderr": "", "timed_out": False}
        if "revive" in cmd_str:
            out_idx = cmd.index("--output")
            revived_path = Path(cmd[out_idx + 1])
            revived_path.write_bytes(b"dummy_revived")
            report = {"verdict": "YELLOW", "required_transforms": []}
            return {"exit_code": 2, "stdout": json.dumps(report), "stderr": "", "timed_out": False}
        if "monkey" in cmd:
            return {"exit_code": 0, "stdout": "Events injected: 1", "stderr": "", "timed_out": False}
        if "crash" in cmd_str:
            crash_log = (
                "FATAL EXCEPTION: main\n"
                "java.lang.UnsatisfiedLinkError: dlopen failed: library \"libandroid_runtime.so\" not found: "
                "bionic namespace restriction (PID: 9999)"
            )
            return {"exit_code": 0, "stdout": crash_log, "stderr": "", "timed_out": False}
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}

    with patch("scripts.survey.run_command", side_effect=fake_run_command), \
         patch("scripts.survey.poll_liveness_and_activity", return_value=(False, "9999", "", False, False)):

        record = run_apk_survey(
            entry=entry,
            adb="adb",
            serial="emulator-5554",
            dev_info=dev_info,
            manifest_dir=tmp_path,
            screenshots_dir=tmp_path / "screenshots",
            temp_out_dir=tmp_path / "temp",
            bump_target_sdk=24,
        )

        assert record["revive_install"]["success"] is True
        assert record["liveness"]["status"] == "CRASH"
        assert record["liveness"]["failure_category"] == "GREYLIST"
        assert record["overall_failure_category"] == "GREYLIST"


def test_survey_main_summary_and_receipt(tmp_path: Path) -> None:
    manifest_data = {
        "packages": [
            {"package_name": "app1", "apk_name": "app1.apk", "target_sdk": 18, "abis": []},
            {"package_name": "app2", "apk_name": "app2.apk", "target_sdk": 19, "abis": []},
        ]
    }
    manifest_file = tmp_path / "survey_test.json"
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    out_file = tmp_path / "results" / "survey_test.json"
    receipt_dir = tmp_path / "receipts"

    mock_record1 = {
        "package_name": "app1",
        "direct_install": {"success": False},
        "bypass_install": {"success": True},
        "revive": {"success": True},
        "revive_install": {"success": True},
        "liveness": {"status": "ALIVE"},
        "overall_failure_category": "NONE",
    }
    mock_record2 = {
        "package_name": "app2",
        "direct_install": {"success": False},
        "bypass_install": {"success": True},
        "revive": {"success": True},
        "revive_install": {"success": False},
        "liveness": {"status": "SKIPPED"},
        "overall_failure_category": "ABI",
    }

    mock_receipt = {
        "device_model": "TestModel",
        "api_level": 35,
        "abi": "x86_64",
        "page_size": 16384,
        "date": "2026-10-20",
        "script": "scripts/survey.py",
        "simulated": False,
    }

    with patch("scripts.survey.find_adb", return_value="adb"), \
         patch("scripts.survey.shutil.which", return_value="/bin/adb"), \
         patch("scripts.survey.get_attached_device", return_value="emulator-5554"), \
         patch("scripts.survey.get_device_info", return_value={"model": "TestModel", "sdk": "35", "abi": "x86_64", "page_size": "16384"}), \
         patch("scripts.survey.run_apk_survey", side_effect=[mock_record1, mock_record2]), \
         patch("scripts.survey.create_receipt", return_value=mock_receipt):

        ret = main(
            [
                "--manifest", str(manifest_file),
                "--output", str(out_file),
                "--receipt-dir", str(receipt_dir),
                "--max-apks", "2",
            ]
        )
        assert ret == 0
        assert out_file.exists()

        result_data = json.loads(out_file.read_text(encoding="utf-8"))
        assert result_data["total_apks"] == 2
        assert result_data["direct_install_stats"]["success"] == 0
        assert result_data["bypass_install_stats"]["success"] == 2
        assert result_data["revive_install_stats"]["install_success"] == 1
        assert result_data["liveness_stats"]["alive"] == 1
        assert result_data["failure_category_counts"]["NONE"] == 1
        assert result_data["failure_category_counts"]["ABI"] == 1

        # Check receipt was written
        receipts = list(receipt_dir.glob("receipt_survey_*.json"))
        assert len(receipts) == 1
        written_receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert written_receipt["device_model"] == "TestModel"


def test_missing_apk_handling(tmp_path: Path) -> None:
    entry = {
        "package_name": "com.missing.app",
        "apk_name": "missing.apk",
        "target_sdk": 19,
        "abis": [],
    }
    dev_info = {"model": "TestPhone", "sdk": "35", "abi": "x86_64", "page_size": "4096"}
    record = run_apk_survey(
        entry=entry,
        adb="adb",
        serial="emulator-5554",
        dev_info=dev_info,
        manifest_dir=tmp_path / "empty_dir",
        screenshots_dir=tmp_path / "screenshots",
        temp_out_dir=tmp_path / "temp",
    )
    assert record["status"] == "SKIPPED_MISSING_APK"
    assert record["overall_failure_category"] == "OTHER"


def test_mock_execution_flow_revive_fails(tmp_path: Path) -> None:
    entry = {
        "package_name": "com.test.revivefail",
        "apk_name": "revivefail.apk",
        "target_sdk": 18,
        "abis": ["armeabi"],
    }
    dummy_apk = tmp_path / "revivefail.apk"
    dummy_apk.write_bytes(b"dummy_content")
    dev_info = {"model": "TestPhone", "sdk": "35", "abi": "x86_64", "page_size": "16384"}

    def fake_run_command(cmd, timeout=60):
        cmd_str = " ".join(cmd)
        if "install" in cmd:
            return {"exit_code": 1, "stdout": "Failure [INSTALL_FAILED_NO_MATCHING_ABIS]", "stderr": "", "timed_out": False}
        if "revive" in cmd_str:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": "ERROR: Cannot revive APK: INCOMPATIBLE_DEVICE_ABI",
                "timed_out": False,
            }
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}

    with patch("scripts.survey.run_command", side_effect=fake_run_command):
        record = run_apk_survey(
            entry=entry,
            adb="adb",
            serial="emulator-5554",
            dev_info=dev_info,
            manifest_dir=tmp_path,
            screenshots_dir=tmp_path / "screenshots",
            temp_out_dir=tmp_path / "temp",
        )
        assert record["direct_install"]["failure_category"] == "ABI"
        assert record["revive"]["success"] is False
        assert record["revive"]["failure_category"] == "ABI"
        assert record["revive_install"]["success"] is False
        assert record["liveness"]["status"] == "SKIPPED"
        assert record["overall_failure_category"] == "ABI"


def test_get_attached_device_and_info() -> None:
    from scripts.survey import get_attached_device, get_device_info

    def fake_devices(cmd, **kwargs):
        if "devices" in cmd:
            output = (
                "* daemon not running; starting now at tcp:5037\n"
                "* daemon started successfully\n"
                "List of devices attached\n"
                "emulator-5554\tdevice\n"
                "emulator-5556\toffline\n"
            )
            return MagicMock(stdout=output, returncode=0)
        return MagicMock(stdout="", returncode=0)

    with patch("scripts.survey.subprocess.run", side_effect=fake_devices):
        dev = get_attached_device("adb")
        assert dev == "emulator-5554"

        # Explicit serial match
        dev_exact = get_attached_device("adb", serial="emulator-5554")
        assert dev_exact == "emulator-5554"

        # Non-matching serial
        dev_none = get_attached_device("adb", serial="non-existent")
        assert dev_none is None

    def fake_props(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "ro.product.model" in cmd_str:
            return MagicMock(stdout="Pixel 6\n", returncode=0)
        if "ro.build.version.sdk" in cmd_str:
            return MagicMock(stdout="34\n", returncode=0)
        if "ro.product.cpu.abi" in cmd_str:
            return MagicMock(stdout="x86_64\n", returncode=0)
        if "PAGE_SIZE" in cmd_str:
            return MagicMock(stdout="4096\n", returncode=0)
        return MagicMock(stdout="unknown\n", returncode=0)

    with patch("scripts.survey.subprocess.run", side_effect=fake_props):
        info = get_device_info("adb", "emulator-5554")
        assert info["model"] == "Pixel 6"
        assert info["sdk"] == "34"
        assert info["abi"] == "x86_64"
        assert info["page_size"] == "4096"

