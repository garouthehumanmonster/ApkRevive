"""
align.py - 4KB and 16KB ZIP boundary aligner for uncompressed entries (.so, resources.arsc).
"""

import mmap
import struct
from typing import Dict, Any

import os
import zipfile
import zlib


def validate_zip_archive(path: str) -> None:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Archive not found: {path}")
    if os.path.getsize(path) < 22:
        raise ValueError("Truncated ZIP archive entry")
    try:
        with zipfile.ZipFile(path, "r") as zf:
            total_uncompressed = 0
            total_compressed = 0
            seen_names = set()
            for info in zf.infolist():
                name = info.filename
                if name in seen_names:
                    raise ValueError(f"Duplicate entry name detected in ZIP: {name}")
                seen_names.add(name)
                if ".." in name or name.startswith("/") or name.startswith("\\"):
                    raise ValueError(f"Zip-slip path traversal detected: {name}")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError(f"Symlink forbidden in APK archive: {name}")
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
            if total_uncompressed > 2 * 1024 * 1024 * 1024:
                raise ValueError("Uncompressed size exceeds 2GB limit")
            if total_compressed > 0 and (total_uncompressed / total_compressed) > 100:
                if total_uncompressed > 10 * 1024 * 1024:
                    raise ValueError("Zip bomb detected: compression ratio exceeds 100x limit")
    except zipfile.BadZipFile as e:
        raise ValueError(f"Truncated ZIP archive entry: {e}")




class UnsupportedZip64Error(ValueError):
    pass


__all__ = ["align_apk", "verify_apk_alignment", "UnsupportedZip64Error", "validate_zip_archive"]


def strip_alignment_padding(extra: bytes) -> bytes:
    out = bytearray()
    idx = 0
    while idx + 4 <= len(extra):
        tag, length = struct.unpack_from("<HH", extra, idx)
        if idx + 4 + length > len(extra):
            break
        if tag != 0xD935:
            out.extend(extra[idx : idx + 4 + length])
        idx += 4 + length
    return bytes(out)


def align_apk(input_apk: str, output_apk: str, page_align_64bit: int = 16384) -> None:
    validate_zip_archive(input_apk)

    with open(input_apk, "rb") as f_in:
        with mmap.mmap(f_in.fileno(), 0, access=mmap.ACCESS_READ) as in_buf:
            buf_len = len(in_buf)
            eocd_pos = in_buf.rfind(b"PK\x05\x06")
            if eocd_pos == -1 or eocd_pos + 22 > buf_len:
                raise ValueError("Truncated ZIP archive entry")

            if eocd_pos >= 20 and b"PK\x06\x07" in in_buf[max(0, eocd_pos - 20) : eocd_pos]:
                raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

            cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", in_buf, eocd_pos + 10)
            if cd_entries_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
                raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

            if cd_offset + cd_size > buf_len or cd_offset > buf_len:
                raise ValueError("Truncated ZIP archive entry")

            new_central_entries = []
            cd_ptr = cd_offset

            with open(output_apk, "wb") as f_out:
                for _ in range(cd_entries_total):
                    if cd_ptr + 46 > buf_len:
                        raise ValueError("Truncated ZIP archive entry")

                    magic = in_buf[cd_ptr : cd_ptr + 4]
                    if magic != b"PK\x01\x02":
                        raise ValueError("Truncated ZIP archive entry")

                    (
                        flags,
                        method,
                        time,
                        date,
                        crc,
                        comp_size,
                        uncomp_size,
                        fn_len,
                        ef_len,
                        comm_len,
                        d_start,
                        int_attr,
                        ext_attr,
                        lfh_offset,
                    ) = struct.unpack_from("<HHHHIIIHHHHHII", in_buf, cd_ptr + 8)

                    if cd_ptr + 46 + fn_len + ef_len + comm_len > buf_len:
                        raise ValueError("Truncated ZIP archive entry")

                    if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF or lfh_offset == 0xFFFFFFFF:
                        raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

                    if lfh_offset + 30 > buf_len:
                        raise ValueError("Truncated ZIP archive entry")

                    fn_start = cd_ptr + 46
                    filename = in_buf[fn_start : fn_start + fn_len].decode("utf-8", errors="replace")

                    # Read Local File Header
                    if in_buf[lfh_offset : lfh_offset + 4] != b"PK\x03\x04":
                        raise ValueError("Truncated ZIP archive entry")

                    lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", in_buf, lfh_offset + 26)
                    data_start = lfh_offset + 30 + lfh_fn_len + lfh_ef_len
                    if data_start + comp_size > buf_len or lfh_offset + 30 + lfh_fn_len > buf_len:
                        raise ValueError("Truncated ZIP archive entry")

                    lfh_header = in_buf[lfh_offset : lfh_offset + 30 + lfh_fn_len]

                    has_decompressed = False
                    decompressed_data = b""
                    is_so_or_arsc = (
                        (filename.startswith("lib/") and filename.endswith(".so"))
                        or filename.endswith(".so")
                        or filename == "resources.arsc"
                    )
                    orig_flags = flags
                    if is_so_or_arsc and method != 0:
                        raw_data = in_buf[data_start : data_start + comp_size]
                        try:
                            decompressed_data = zlib.decompress(raw_data, -15)
                        except Exception:
                            decompressed_data = zlib.decompress(raw_data)
                        method = 0
                        comp_size = len(decompressed_data)
                        uncomp_size = comp_size
                        if not crc:
                            crc = zlib.crc32(decompressed_data)
                        flags &= ~0x0008
                        alignment = 16384
                        has_decompressed = True
                    else:
                        # Calculate alignment requirement
                        alignment = 4
                        if method == 0:  # STORED
                            if is_so_or_arsc:
                                alignment = 16384

                    new_lfh_offset = f_out.tell()
                    orig_extra = in_buf[lfh_offset + 30 + lfh_fn_len : lfh_offset + 30 + lfh_fn_len + lfh_ef_len]
                    clean_extra = strip_alignment_padding(orig_extra)
                    base_data_offset = new_lfh_offset + 30 + fn_len + len(clean_extra)
                    pad_total = (alignment - (base_data_offset % alignment)) % alignment
                    if 0 < pad_total < 4:
                        pad_total += alignment
                    if pad_total >= 4:
                        payload = pad_total - 4
                        padding_field = struct.pack("<HH", 0xD935, payload) + (b"\x00" * payload)
                    else:
                        padding_field = b""
                    new_extra = clean_extra + padding_field

                    new_lfh = bytearray(lfh_header)
                    if has_decompressed:
                        struct.pack_into("<H", new_lfh, 6, flags)
                        struct.pack_into("<H", new_lfh, 8, method)
                        struct.pack_into("<I", new_lfh, 14, crc)
                        struct.pack_into("<I", new_lfh, 18, comp_size)
                        struct.pack_into("<I", new_lfh, 22, uncomp_size)
                    struct.pack_into("<H", new_lfh, 28, len(new_extra))
                    f_out.write(new_lfh)
                    f_out.write(new_extra)

                    if has_decompressed:
                        f_out.write(decompressed_data)
                    else:
                        CHUNK_SIZE = 64 * 1024
                        curr_pos = data_start
                        rem = comp_size
                        while rem > 0:
                            chunk_sz = min(rem, CHUNK_SIZE)
                            f_out.write(in_buf[curr_pos : curr_pos + chunk_sz])
                            curr_pos += chunk_sz
                            rem -= chunk_sz

                    if (orig_flags & 0x0008) and not has_decompressed:
                        desc_pos = data_start + comp_size
                        has_sig = (desc_pos + 4 <= buf_len and in_buf[desc_pos : desc_pos + 4] == b"PK\x07\x08")
                        is_64 = (comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF)
                        desc_len = (24 if has_sig else 20) if is_64 else (16 if has_sig else 12)
                        if desc_pos + desc_len > buf_len:
                            raise ValueError("Truncated ZIP archive entry")
                        f_out.write(in_buf[desc_pos : desc_pos + desc_len])

                    # Record Central Directory entry
                    cd_record = bytearray(in_buf[cd_ptr : cd_ptr + 46 + fn_len + ef_len + comm_len])
                    if has_decompressed:
                        struct.pack_into("<H", cd_record, 8, flags)
                        struct.pack_into("<H", cd_record, 10, method)
                        struct.pack_into("<I", cd_record, 16, crc)
                        struct.pack_into("<I", cd_record, 20, comp_size)
                        struct.pack_into("<I", cd_record, 24, uncomp_size)
                    struct.pack_into("<H", cd_record, 30, 0)  # zero out extra field in central dir
                    struct.pack_into("<I", cd_record, 42, new_lfh_offset)
                    new_central_entries.append(cd_record[: 46 + fn_len] + cd_record[46 + fn_len + ef_len :])

                    cd_ptr += 46 + fn_len + ef_len + comm_len

                # Write Central Directory & EOCD
                cd_offset_raw = f_out.tell()
                cd_pad = (4096 - (cd_offset_raw % 4096)) % 4096
                if cd_pad > 0:
                    f_out.write(b"\x00" * cd_pad)
                new_cd_offset = f_out.tell()
                for cd_rec in new_central_entries:
                    f_out.write(cd_rec)
                new_cd_size = f_out.tell() - new_cd_offset

                comment_len = struct.unpack_from("<H", in_buf, eocd_pos + 20)[0]
                if eocd_pos + 22 + comment_len > buf_len:
                    raise ValueError("Truncated ZIP archive entry")
                eocd_record = bytearray(in_buf[eocd_pos : eocd_pos + 22 + comment_len])
                struct.pack_into("<II", eocd_record, 12, new_cd_size, new_cd_offset)
                f_out.write(eocd_record)


def verify_apk_alignment(apk_path: str) -> Dict[str, Any]:
    validate_zip_archive(apk_path)

    with open(apk_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            buf_len = len(buf)
            eocd_pos = buf.rfind(b"PK\x05\x06")
            if eocd_pos == -1 or eocd_pos + 22 > buf_len:
                raise ValueError("Truncated ZIP archive entry")

            if eocd_pos >= 20 and b"PK\x06\x07" in buf[max(0, eocd_pos - 20) : eocd_pos]:
                raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

            cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", buf, eocd_pos + 10)
            if cd_entries_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
                raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

            if cd_offset + cd_size > buf_len or cd_offset > buf_len:
                raise ValueError("Truncated ZIP archive entry")

            cd_ptr = cd_offset
            results = {}
            all_aligned = True
            entries_checked = 0

            for _ in range(cd_entries_total):
                if cd_ptr + 46 > buf_len:
                    raise ValueError("Truncated ZIP archive entry")
                if buf[cd_ptr : cd_ptr + 4] != b"PK\x01\x02":
                    raise ValueError("Truncated ZIP archive entry")

                (
                    flags,
                    method,
                    time,
                    date,
                    crc,
                    comp_size,
                    uncomp_size,
                    fn_len,
                    ef_len,
                    comm_len,
                    d_start,
                    int_attr,
                    ext_attr,
                    lfh_offset,
                ) = struct.unpack_from("<HHHHIIIHHHHHII", buf, cd_ptr + 8)

                if cd_ptr + 46 + fn_len + ef_len + comm_len > buf_len:
                    raise ValueError("Truncated ZIP archive entry")

                if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF or lfh_offset == 0xFFFFFFFF:
                    raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")

                fn = buf[cd_ptr + 46 : cd_ptr + 46 + fn_len].decode("utf-8", errors="replace")

                if method == 0:
                    if lfh_offset + 30 > buf_len:
                        raise ValueError("Truncated ZIP archive entry")
                    if buf[lfh_offset : lfh_offset + 4] != b"PK\x03\x04":
                        raise ValueError("Truncated ZIP archive entry")
                    lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", buf, lfh_offset + 26)
                    if lfh_offset + 30 + lfh_fn_len + lfh_ef_len > buf_len:
                        raise ValueError("Truncated ZIP archive entry")
                    data_offset = lfh_offset + 30 + lfh_fn_len + lfh_ef_len
                    req_align = 4
                    if (fn.startswith("lib/") and fn.endswith(".so")) or fn.endswith(".so") or fn == "resources.arsc":
                        req_align = 16384

                    aligned = (data_offset % req_align == 0)
                    results[fn] = {"offset": data_offset, "required_align": req_align, "aligned": aligned}
                    if not aligned:
                        all_aligned = False

                cd_ptr += 46 + fn_len + ef_len + comm_len
                entries_checked += 1

            if entries_checked != cd_entries_total:
                raise ValueError("Truncated ZIP archive entry")

            return {"aligned": all_aligned, "entries": results, "entries_checked": entries_checked}
