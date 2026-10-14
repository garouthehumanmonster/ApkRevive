"""
align.py - 4KB and 16KB ZIP boundary aligner for uncompressed entries (.so, resources.arsc).
"""

import struct
import zipfile
from typing import Dict, Any


def align_apk(input_apk: str, output_apk: str, page_align_64bit: int = 16384) -> None:
    with open(input_apk, "rb") as f_in, open(output_apk, "wb") as f_out:
        in_buf = f_in.read()

        eocd_pos = in_buf.rfind(b"PK\x05\x06")
        if eocd_pos == -1:
            raise ValueError("Invalid ZIP file: EOCD not found")

        cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", in_buf, eocd_pos + 10)

        new_central_entries = []
        cd_ptr = cd_offset

        for _ in range(cd_entries_total):
            magic = in_buf[cd_ptr:cd_ptr + 4]
            if magic != b"PK\x01\x02":
                break

            flags, method, time, date, crc, comp_size, uncomp_size, fn_len, ef_len, comm_len, d_start, int_attr, ext_attr, lfh_offset = struct.unpack_from("<HHHHIIIHHHHHII", in_buf, cd_ptr + 8)

            fn_start = cd_ptr + 46
            filename = in_buf[fn_start:fn_start + fn_len].decode("utf-8", errors="replace")

            # Read Local File Header
            lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", in_buf, lfh_offset + 26)
            lfh_header = in_buf[lfh_offset:lfh_offset + 30 + lfh_fn_len]
            entry_data = in_buf[lfh_offset + 30 + lfh_fn_len + lfh_ef_len : lfh_offset + 30 + lfh_fn_len + lfh_ef_len + comp_size]

            # Calculate alignment requirement
            alignment = 4
            if method == 0:  # STORED
                if filename.endswith(".so") and ("arm64-v8a" in filename or "x86_64" in filename):
                    alignment = page_align_64bit
                elif filename == "resources.arsc" or filename.endswith(".so"):
                    alignment = 4096

            new_lfh_offset = f_out.tell()
            base_data_offset = new_lfh_offset + 30 + fn_len
            pad_len = (alignment - (base_data_offset % alignment)) % alignment
            if 0 < pad_len < 4:
                pad_len += alignment

            # Write LFH with padding extra field
            new_lfh = bytearray(lfh_header)
            if pad_len >= 4:
                extra_field = struct.pack("<HH", 0xD935, pad_len - 4) + (b"\x00" * (pad_len - 4))
            else:
                extra_field = b"\x00" * pad_len
            struct.pack_into("<H", new_lfh, 28, len(extra_field))
            f_out.write(new_lfh)
            f_out.write(extra_field)
            f_out.write(entry_data)

            # Record Central Directory entry
            cd_record = bytearray(in_buf[cd_ptr:cd_ptr + 46 + fn_len + ef_len + comm_len])
            struct.pack_into("<H", cd_record, 30, 0)  # zero out extra field in central dir
            struct.pack_into("<I", cd_record, 42, new_lfh_offset)
            new_central_entries.append(cd_record[:46 + fn_len] + cd_record[46 + fn_len + ef_len:])

            cd_ptr += 46 + fn_len + ef_len + comm_len

        # Write Central Directory & EOCD
        new_cd_offset = f_out.tell()
        for cd_rec in new_central_entries:
            f_out.write(cd_rec)
        new_cd_size = f_out.tell() - new_cd_offset

        eocd_record = bytearray(in_buf[eocd_pos:eocd_pos + 22])
        struct.pack_into("<II", eocd_record, 12, new_cd_size, new_cd_offset)
        f_out.write(eocd_record)


def verify_apk_alignment(apk_path: str) -> Dict[str, Any]:
    with open(apk_path, "rb") as f:
        buf = f.read()

    eocd_pos = buf.rfind(b"PK\x05\x06")
    cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", buf, eocd_pos + 10)

    cd_ptr = cd_offset
    results = {}
    all_aligned = True

    for _ in range(cd_entries_total):
        if buf[cd_ptr:cd_ptr + 4] != b"PK\x01\x02": break
        method = struct.unpack_from("<H", buf, cd_ptr + 10)[0]
        fn_len, ef_len, comm_len = struct.unpack_from("<HHH", buf, cd_ptr + 28)
        lfh_offset = struct.unpack_from("<I", buf, cd_ptr + 42)[0]
        fn = buf[cd_ptr + 46 : cd_ptr + 46 + fn_len].decode("utf-8", errors="replace")

        if method == 0:
            lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", buf, lfh_offset + 26)
            data_offset = lfh_offset + 30 + lfh_fn_len + lfh_ef_len
            req_align = 4096
            if fn.endswith(".so") and ("arm64-v8a" in fn or "x86_64" in fn):
                req_align = 16384

            aligned = (data_offset % req_align == 0)
            results[fn] = {"offset": data_offset, "required_align": req_align, "aligned": aligned}
            if not aligned:
                all_aligned = False

        cd_ptr += 46 + fn_len + ef_len + comm_len

    return {"aligned": all_aligned, "entries": results}
