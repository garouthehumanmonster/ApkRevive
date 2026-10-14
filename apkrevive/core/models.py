"""
models.py - Domain models for ApkRevive v3.3 modernizer pipeline.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


class Verdict(str, Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"
    NEEDS_USER_INPUT = "NEEDS_USER_INPUT"


class TriageSignal(str, Enum):
    RUNNABLE_UNMODIFIED = "RUNNABLE_UNMODIFIED"
    INCOMPATIBLE_DEVICE_ABI = "INCOMPATIBLE_DEVICE_ABI"
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
    private_libs: List[str] = field(default_factory=list)
    uses_apache_http: bool = False
    has_code: bool = True
    is_non_resizeable: bool = False
    has_fixed_physics: bool = False
    has_self_sig_check: bool = False
    has_drm: bool = False
    size_bytes: int = 0
    static_removed_apis: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApkMetadata":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
