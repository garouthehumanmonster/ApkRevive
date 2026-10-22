"""
models.py - Domain models for ApkRevive inspect and patch pipeline.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


SCHEMA_VERSION = "2.1.0"


class Verdict(str, Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"
    NEEDS_USER_INPUT = "NEEDS_USER_INPUT"


class TriageSignal(str, Enum):
    RUNNABLE_UNMODIFIED = "RUNNABLE_UNMODIFIED"
    INCOMPATIBLE_DEVICE_ABI = "INCOMPATIBLE_DEVICE_ABI"
    INCOMPATIBLE_TEXTREL = "INCOMPATIBLE_TEXTREL"
    UNRESOLVABLE_SYSTEM_LIBRARY = "UNRESOLVABLE_SYSTEM_LIBRARY"
    INCOMPATIBLE_PAGE_SIZE = "INCOMPATIBLE_PAGE_SIZE"
    EXCEEDS_2GB_LIMIT_FOR_REPACKING = "EXCEEDS_2GB_LIMIT_FOR_REPACKING"
    MODIFICATION_REQUIRED = "MODIFICATION_REQUIRED"
    SIGNATURE_VERIFICATION_DETECTED = "SIGNATURE_VERIFICATION_DETECTED"
    NEEDS_APACHE_HTTP_LEGACY = "NEEDS_APACHE_HTTP_LEGACY"
    NEEDS_PILLARBOX_FIX = "NEEDS_PILLARBOX_FIX"
    NEEDS_REFRESH_RATE_FIX = "NEEDS_REFRESH_RATE_FIX"
    NEEDS_PAGE_SIZE_COMPAT = "NEEDS_PAGE_SIZE_COMPAT"
    NEEDS_PAGE_SIZE_COMPAT_ANDROID16 = "NEEDS_PAGE_SIZE_COMPAT_ANDROID16"
    NEEDS_HAS_CODE_FLAG = "NEEDS_HAS_CODE_FLAG"
    SPLIT_APK_UNSUPPORTED = "SPLIT_APK_UNSUPPORTED"


@dataclass
class DeviceProfile:
    os_api_level: int = 35
    install_floor: int = 24
    supported_abis: List[str] = field(default_factory=lambda: ["arm64-v8a"])
    page_size_bytes: int = 16384
    is_widescreen: bool = True
    is_high_refresh: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceProfile":
        return cls(
            os_api_level=data.get("os_api_level", 35),
            install_floor=data.get("install_floor", 24),
            supported_abis=data.get("supported_abis", ["arm64-v8a"]),
            page_size_bytes=data.get("page_size_bytes", 16384),
            is_widescreen=data.get("is_widescreen", True),
            is_high_refresh=data.get("is_high_refresh", False),
        )


@dataclass
class ApkMetadata:
    package_name: str = ""
    target_sdk: int = 1
    min_sdk: int = 1
    version_code: int = 1
    abis: List[str] = field(default_factory=list)
    elf_load_align_64bit: Optional[int] = None
    has_invalid_elf_layout: bool = False
    elf_16kb_status: Optional[str] = None
    is_split_apk: bool = False
    private_libs: List[str] = field(default_factory=list)
    uses_apache_http: bool = False
    has_code: bool = True
    is_non_resizeable: bool = False
    has_fixed_physics: bool = False
    has_self_sig_check: bool = False
    has_drm: bool = False
    size_bytes: int = 0
    static_removed_apis: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    uses_cleartext_traffic: Optional[bool] = None
    has_network_security_config: bool = False
    legacy_tls_protocols: List[str] = field(default_factory=list)
    has_cleartext_http: bool = False
    hidden_api_reflections: List[str] = field(default_factory=list)
    accesses_scoped_storage_paths: bool = False
    has_obb: bool = False
    uses_gles1: bool = False
    dead_sdks: List[str] = field(default_factory=list)
    textrel_libs: List[str] = field(default_factory=list)
    has_textrel: bool = False
    has_request_legacy_external_storage: bool = False
    force_page_size_compat: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApkMetadata":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class InspectionReport:
    apk_path: str
    package_name: str
    version_code: int
    min_sdk: int
    target_sdk: int
    abis: List[str]
    fatal_blockers: List[str]
    warnings: List[str]
    remediable_issues: List[str]
    page_size_16kb_status: Optional[str] = None
    private_bionic_libs: List[str] = field(default_factory=list)
    is_32bit_only: bool = False
    needs_apache_http: bool = False
    install_floor_blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PatchReport:
    timestamp: str
    apk_path: str
    package_name: str
    target_sdk: int
    verdict: str
    reason: str
    install_method: Optional[str] = None
    required_transforms: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: str = ""
    output_apk: Optional[str] = None
    transform_risks: Dict[str, str] = field(default_factory=dict)
    page_size_compat_verified: bool = True
    verdict_display: Optional[str] = None
    remediations: List[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    is_signed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
