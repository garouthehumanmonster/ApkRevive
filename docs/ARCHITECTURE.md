# ApkRevive Architecture & Structural Invariants

This document establishes the architectural contracts, fail-closed guarantees, and regression test matrix for the ApkRevive modernization pipeline. Every invariant listed here must be preserved in all future changes.

---

## 1. Architectural Principles

1. **Stdlib-Only Core (`dependencies = []`)**: The core modernization engine operates exclusively using the Python standard library. No external runtime wheels or heavy dependencies.
2. **Fail-Closed, Never Open**: Malformed, truncated, unsupported, or ambiguous binary inputs must raise explicit typed exceptions (`UnsupportedZip64Error`, `UnsupportedAxmlChunk`, `UnsupportedSplitMerge`, `ValueError`). Never silently fall back, skip, or swallow errors.
3. **Byte Preservation Over Speculative Surgery**: If binary modification cannot be proven sound in-place (such as shifting 4KB-linked ELF virtual addresses), bytes are preserved intact and compatibility is handled via OS platform mechanisms (`android:pageSizeCompat`).
4. **Atomic Operations**: All filesystem transformations execute in temporary staging areas and clean up automatically on failure. No corrupted or half-written APKs are left behind.

---

## 2. Invariant Matrix: Module → Guarantee → Regression Test

### Container Alignment & ZIP Engine (`apkrevive/core/align.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **EOCD Archive Comment** | EOCD comment length is validated against buffer bounds and copied verbatim. | `tests/test_align.py::test_align_preserves_archive_comment` |
| **LFH Extra Fields** | Original extra fields (e.g. `0x7075` Info-ZIP Unicode, NTFS) are preserved; `0xD935` alignment padding is merged. | `tests/test_align.py::test_align_preserves_lfh_extra_field` |
| **Data Descriptors** | If GP bit 3 is set (`flags & 0x0008`), trailing 12/16/20/24-byte descriptors are copied with optional signature detection. | `tests/test_align.py::test_align_data_descriptor_survives` |
| **Zip64 Refusal** | Rejects Zip64 locators, counts (`0xFFFF`), and offsets (`0xFFFFFFFF`) with `UnsupportedZip64Error`. | `tests/test_align.py::test_align_rejects_zip64` |
| **Alignment Verification** | Fail-closed: truncated records or entry count mismatches raise `ValueError`. | `tests/test_align.py::test_verify_alignment_fails_closed_on_truncated` |

### Binary AXML Surgeon (`apkrevive/core/axml.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **Dangling String Index** | Attribute type `0x03` with `raw_value is None` emits `0xFFFFFFFF` rather than leaking old pool index. | `tests/test_axml.py::test_serialize_node_dangling_string_index_fixed` |
| **Two-Pass String Pool** | Node serialization collects all strings in Pass 1, builds pool, and asserts pool size stability in Pass 2. | `tests/test_axml.py::test_serialize_node_asserts_no_growth`, `tests/fuzz/test_fuzz_axml_elf.py` |
| **Unsupported Chunks** | Chunks other than string pool, resource map, namespaces, and elements raise `UnsupportedAxmlChunk`. | `tests/test_axml.py::test_axml_fails_closed_on_unsupported_chunk` |
| **Namespace Preservation** | All referenced and source namespace declarations (`xmlns:tools`, OEM) are preserved in output. | `tests/test_axml.py::test_axml_preserves_multiple_namespaces` |
| **Declared File Size** | XML header file size must be within buffer bounds; chunk walk bounded strictly by declared size. | `tests/test_axml.py::test_axml_validates_declared_file_size` |
| **Attribute Truncation** | Partial or truncated attribute records raise `ValueError("Truncated AXML attribute list")`. | `tests/test_axml.py::test_axml_fails_closed_on_truncated_attributes` |
| **Aspect Ratio Unlock** | `EXPAND_ASPECT_RATIO` forces `maxAspectRatio="2.5"` and `android.max_aspect="2.5"` unconditionally. | `tests/test_axml.py::test_patch_manifest_expands_aspect_ratio_unconditionally` |
| **Post-Condition Gate** | Emitted manifest bytes are re-parsed and validated for provider presence, `hasCode`, and no duplicates. | `tests/test_axml.py::test_patch_manifest_post_condition_validation` |

### CLI & Pipeline Lifecycle (`apkrevive/cli/__init__.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **Shim Integrity** | Fails closed with exit code 1 if `shim.dex` is missing or fails SHA256 checksum check. | `tests/test_cli.py::test_revive_fails_closed_when_shim_missing` |
| **Atomic Cleanup** | Pipeline failure during repack/align/sign/verify cleans up temp files and half-written target APK. | `tests/test_cli.py::test_revive_cleans_up_on_sign_failure`, `test_revive_cleans_up_on_verify_failure` |
| **Probe Device Connectivity** | `probe_cmd` returns 0 only when a physical/virtual device is reached via ADB. | `tests/test_cli.py::test_probe_cmd_fails_when_no_device`, `test_probe_cmd_fails_when_sdk_query_fails` |
| **Repack Parity Check** | Output entry count must match input minus stripped signature files plus injected shim. | `tests/test_cli.py::test_revive_verifies_repack_entry_invariants` |

### Split APK Merger (`apkrevive/core/split_merger.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **Entry Compression** | Native libraries (`.so`) and `resources.arsc` stored (`ZIP_STORED`); manifests/DEX/assets deflated. | `tests/test_split_merger.py::test_split_merger_compression_modes` |
| **Base APK Detection** | Base APK identified strictly by parsing `AndroidManifest.xml` for missing/empty `split` attribute. | `tests/test_split_merger.py::test_split_merger_detects_base_by_manifest` |
| **Resource Table Guard** | Split APK containing `resources.arsc` raises `UnsupportedSplitMerge` unless `--allow-resource-table-loss` is passed. | `tests/test_split_merger.py::test_split_merger_fails_closed_on_split_resources` |
| **Collision & Renumber Warnings** | Emits `WARN_DEX_RENUMBERED` and `WARN_DROPPED_DUPLICATE_ENTRIES` diagnostics during merge. | `tests/test_split_merger.py::test_split_merger_emits_renumbering_and_collision_warnings` |

### 16KB ELF & Memory Page Engine (`apkrevive/core/elf16k.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **32-Bit Exemption** | 32-bit binaries (`ELFCLASS32`) are classified as `EXEMPT` and left unmodified. | `tests/test_elf16k.py::test_elf16k_32bit_exempt` |
| **Page Collision Check** | Virtual address overlap between adjacent segments flags fake header alignment patches. | `tests/test_elf16k.py::test_elf16k_modulo_congruence` |
| **Byte Preservation** | `elf16k.fix()` never attempts in-place binary relinking; returns original bytes unmodified. | `tests/test_elf16k.py::test_elf16k_refusal_preserves_bytes` |

### Security & Sanitization (`apkrevive/security/zip_guard.py`)
| Subsystem Guarantee | Implementation Invariant | Guarding Test |
|---|---|---|
| **Path Traversal / Zip Slip** | Rejects path traversal (`..`), absolute paths, and NTFS Alternate Data Streams (`:`). | `tests/test_zip_guard.py` |
| **Decompression Bombs** | Enforces maximum 100:1 uncompressed-to-compressed ratio threshold and maximum file size limits. | `tests/test_zip_guard.py` |
