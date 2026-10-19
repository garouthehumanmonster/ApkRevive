"""
test_triage_correctness.py - Phase 2 ELF Fake Header Patch Triage Fail-Closed tests.
"""

from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict, TriageSignal
from apkrevive.core.triage import evaluate_triage


def test_fake_header_patched_64bit_elf_on_android16_returns_red():
    """
    a) Fake-header patched 64-bit ELF (inflated p_align with page collision)
       on Android 16 (API 36) returns RED.
    """
    apk = ApkMetadata(
        target_sdk=28,
        abis=["arm64-v8a"],
        elf_16kb_status="UNSAFE",
        has_invalid_elf_layout=True,
        size_bytes=5_000_000,
    )
    dev = DeviceProfile(
        os_api_level=36,
        supported_abis=["arm64-v8a"],
        page_size_bytes=16384,
    )
    res = evaluate_triage(apk, dev)
    assert res["verdict"] == Verdict.RED.value
    assert res["reason"] == TriageSignal.INCOMPATIBLE_PAGE_SIZE.value
    assert "colliding 16KB pages" in res["details"] or "Invalid/fake header" in res["details"]


def test_standard_4kb_linked_64bit_elf_on_android15_returns_red():
    """
    b) Standard 4KB-linked 64-bit ELF on Android 15 (API 35) returns RED.
    """
    apk = ApkMetadata(
        target_sdk=28,
        abis=["arm64-v8a"],
        elf_16kb_status="COMPAT_ONLY",
        elf_load_align_64bit=4096,
        size_bytes=5_000_000,
    )
    dev = DeviceProfile(
        os_api_level=35,
        supported_abis=["arm64-v8a"],
        page_size_bytes=16384,
    )
    res = evaluate_triage(apk, dev)
    assert res["verdict"] == Verdict.RED.value
    assert res["reason"] == TriageSignal.INCOMPATIBLE_PAGE_SIZE.value


def test_standard_4kb_linked_64bit_elf_on_android16_returns_green_advisory():
    """
    c) Standard 4KB-linked 64-bit ELF on Android 16 (API 36) returns GREEN with advisory note.
    """
    apk = ApkMetadata(
        target_sdk=28,
        abis=["arm64-v8a"],
        elf_16kb_status="COMPAT_ONLY",
        elf_load_align_64bit=4096,
        size_bytes=5_000_000,
    )
    dev = DeviceProfile(
        os_api_level=36,
        supported_abis=["arm64-v8a"],
        page_size_bytes=16384,
    )
    res = evaluate_triage(apk, dev)
    assert res["verdict"] == Verdict.GREEN.value
    assert any("WARN_PAGE_SIZE_COMPAT_ADVISORY" in w for w in res["warnings"])

    # Forced transform option returns YELLOW with PAGE_SIZE_COMPAT
    apk_forced = ApkMetadata(
        target_sdk=28,
        abis=["arm64-v8a"],
        elf_16kb_status="COMPAT_ONLY",
        elf_load_align_64bit=4096,
        size_bytes=5_000_000,
        force_page_size_compat=True,
    )
    res_forced = evaluate_triage(apk_forced, dev)
    assert res_forced["verdict"] == Verdict.YELLOW.value
    assert "PAGE_SIZE_COMPAT" in res_forced["required_transforms"]


def test_32bit_only_native_libs_on_64bit_only_device_returns_red():
    """
    d) 32-bit-only native libs on 64-bit-only device returns RED.
    """
    apk = ApkMetadata(
        target_sdk=22,
        abis=["armeabi-v7a"],
        size_bytes=5_000_000,
    )
    dev = DeviceProfile(
        os_api_level=35,
        supported_abis=["arm64-v8a"],
        page_size_bytes=16384,
    )
    res = evaluate_triage(apk, dev)
    assert res["verdict"] == Verdict.RED.value
    assert res["reason"] == TriageSignal.INCOMPATIBLE_DEVICE_ABI.value


def test_blocked_private_library_linkage_returns_red():
    """
    e) Blocked private library linkage returns RED.
    """
    apk = ApkMetadata(
        target_sdk=26,
        abis=["arm64-v8a"],
        elf_load_align_64bit=16384,
        private_libs=["libcrypto.so"],
        size_bytes=5_000_000,
    )
    dev = DeviceProfile(
        os_api_level=35,
        supported_abis=["arm64-v8a"],
        page_size_bytes=16384,
    )
    res = evaluate_triage(apk, dev)
    assert res["verdict"] == Verdict.RED.value
    assert res["reason"] == TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY.value
