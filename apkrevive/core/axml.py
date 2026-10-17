"""
axml.py - Binary AXML parser, serializer, and idempotent manifest surgeon.
Guarantees AXML(N) == AXML(N+1).
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


CHUNK_XML = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NS = 0x0100
CHUNK_END_NS = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103

ANDROID_NS = "http://schemas.android.com/apk/res/android"

KNOWN_RESOURCE_IDS = {
    "name": 0x01010003,
    "hasCode": 0x0101000C,
    "value": 0x01010024,
    "exported": 0x01010010,
    "initOrder": 0x0101001A,
    "authorities": 0x01010018,
    "required": 0x0101028E,
    "resizeableActivity": 0x010104E1,
    "pageSizeCompat": 0x0101062B,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    # v0.4.0 Architectural additions
    "extractNativeLibs": 0x010104EA,
    "isSplitRequired": 0x01010591,
    "requiredSplitTypes": 0x0101064D,
    "splitTypes": 0x0101064E,
    "maxAspectRatio": 0x01010526,
    "usesCleartextTraffic": 0x010104EC,
    "networkSecurityConfig": 0x01010527,
    "requestLegacyExternalStorage": 0x01010603,
}


@dataclass
class AxmlAttribute:
    ns: str
    name: str
    raw_value: Optional[str]
    data_type: int
    data: int

    def get_value(self) -> Any:
        if self.data_type == 0x03:
            return self.raw_value
        elif self.data_type == 0x12:
            return bool(self.data != 0)
        return self.data


@dataclass
class AxmlNode:
    tag: str
    ns: str = ""
    attributes: List[AxmlAttribute] = field(default_factory=list)
    children: List["AxmlNode"] = field(default_factory=list)

    def find_child(self, tag: str, attr_name: Optional[str] = None, attr_val: Optional[str] = None) -> Optional["AxmlNode"]:
        for child in self.children:
            if child.tag == tag or child.tag.split(":")[-1] == tag:
                if attr_name is None:
                    return child
                for a in child.attributes:
                    base_attr = a.name.split(":")[-1]
                    if (a.name == attr_name or base_attr == attr_name) and (a.raw_value == attr_val or a.get_value() == attr_val):
                        return child
        return None

    def get_attr(self, name: str) -> Optional[AxmlAttribute]:
        for a in self.attributes:
            if a.name == name or a.name.split(":")[-1] == name:
                return a
        return None

    def set_attr(self, name: str, value: Any, ns: str = ANDROID_NS):
        existing = self.get_attr(name)
        if isinstance(value, bool):
            data_type = 0x12
            data = 0xFFFFFFFF if value else 0
            raw_val = "true" if value else "false"
        elif isinstance(value, int):
            data_type = 0x10
            data = value
            raw_val = str(value)
        else:
            data_type = 0x03
            data = 0
            raw_val = str(value)

        if existing:
            existing.data_type = data_type
            existing.data = data
            existing.raw_value = raw_val
        else:
            self.attributes.append(AxmlAttribute(ns=ns, name=name, raw_value=raw_val, data_type=data_type, data=data))


class AxmlSurgeon:
    @staticmethod
    def parse(data: bytes) -> AxmlNode:
        if len(data) < 8:
            raise ValueError("Invalid AXML: buffer too small")
        chunk_type, header_size, file_size = struct.unpack_from("<HHI", data, 0)
        if chunk_type != CHUNK_XML:
            raise ValueError(f"Invalid AXML magic chunk: 0x{chunk_type:04x}")
        if header_size < 8 or header_size > len(data):
            raise ValueError(f"Invalid AXML root header size: {header_size}")

        offset = 8
        strings: List[str] = []
        _resource_map: List[int] = []
        root_nodes: List[AxmlNode] = []
        element_stack: List[AxmlNode] = []
        chunk_count = 0
        MAX_CHUNKS = 100_000

        while offset < len(data):
            chunk_count += 1
            if chunk_count > MAX_CHUNKS:
                raise ValueError("AXML chunk count exceeded limit (cyclic chunk loop detected)")

            if offset + 8 > len(data):
                raise ValueError("Invalid AXML: unexpected EOF reading chunk header")

            c_type, c_hsize, c_size = struct.unpack_from("<HHI", data, offset)
            if c_hsize < 8:
                raise ValueError(f"Invalid AXML chunk header size: {c_hsize}")
            if c_size < c_hsize or offset + c_size > len(data):
                raise ValueError(f"Invalid AXML chunk size: {c_size} (offset {offset}, total {len(data)})")

            if c_type == CHUNK_STRING_POOL:
                if offset + 28 > len(data):
                    raise ValueError("String pool header truncated")
                str_count, style_count, flags, str_start, styles_start = struct.unpack_from("<IIIII", data, offset + 8)
                is_utf8 = bool(flags & 0x0100)
                if offset + 28 + (str_count * 4) > offset + c_size:
                    raise ValueError("String pool offset table exceeds chunk bounds")
                offsets = [struct.unpack_from("<I", data, offset + 28 + (i * 4))[0] for i in range(str_count)]

                pool_data_start = offset + str_start
                if pool_data_start > offset + c_size:
                    raise ValueError("String pool data offset out of bounds")
                pool_data = data[pool_data_start : offset + c_size]

                strings = []
                for o in offsets:
                    if o >= len(pool_data):
                        strings.append("")
                        continue
                    if is_utf8:
                        p = o
                        while p < len(pool_data) and (pool_data[p] & 0x80):
                            p += 1
                        p += 1
                        if p >= len(pool_data):
                            strings.append("")
                            continue
                        blen = pool_data[p]
                        if blen & 0x80:
                            if p + 1 >= len(pool_data):
                                strings.append("")
                                continue
                            blen = ((blen & 0x7F) << 8) | pool_data[p + 1]
                            p += 2
                        else:
                            p += 1
                        if p + blen > len(pool_data):
                            strings.append("")
                            continue
                        s = pool_data[p : p + blen].decode("utf-8", errors="replace")
                        strings.append(s)
                    else:
                        p = o
                        if p + 2 > len(pool_data):
                            strings.append("")
                            continue
                        u16_len = struct.unpack_from("<H", pool_data, p)[0]
                        p += 2
                        if p + (u16_len * 2) > len(pool_data):
                            strings.append("")
                            continue
                        raw_bytes = pool_data[p : p + (u16_len * 2)]
                        s = raw_bytes.decode("utf-16le", errors="replace")
                        strings.append(s)

            elif c_type == CHUNK_RESOURCE_MAP:
                res_count = (c_size - 8) // 4
                if offset + 8 + (res_count * 4) <= offset + c_size:
                    _resource_map = [struct.unpack_from("<I", data, offset + 8 + (i * 4))[0] for i in range(res_count)]

            elif c_type == CHUNK_START_ELEMENT:
                if offset + 28 > len(data):
                    raise ValueError("Start element header truncated")
                line_no, comment, ns_idx, name_idx, attr_start, attr_size, attr_count, id_idx, cl_idx, st_idx = struct.unpack_from(
                    "<IIIIHHHHHH", data, offset + 8
                )
                tag_ns = strings[ns_idx] if 0 <= ns_idx < len(strings) else ""
                tag_name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
                node = AxmlNode(tag=tag_name, ns=tag_ns)

                attr_offset = offset + c_hsize + attr_start
                for _ in range(attr_count):
                    if attr_offset + 20 > offset + c_size:
                        break
                    a_ns, a_name, a_raw, a_sz, a_res0, a_type, a_data = struct.unpack_from("<IIIHBB I", data, attr_offset)
                    ans_str = strings[a_ns] if 0 <= a_ns < len(strings) else ""
                    aname_str = strings[a_name] if 0 <= a_name < len(strings) else ""
                    araw_str = strings[a_raw] if 0 <= a_raw < len(strings) else None
                    node.attributes.append(AxmlAttribute(ns=ans_str, name=aname_str, raw_value=araw_str, data_type=a_type, data=a_data))
                    attr_offset += attr_size if attr_size >= 20 else 20

                if element_stack:
                    element_stack[-1].children.append(node)
                else:
                    root_nodes.append(node)
                element_stack.append(node)

            elif c_type == CHUNK_END_ELEMENT:
                if element_stack:
                    element_stack.pop()

            offset += c_size

        if not root_nodes:
            raise ValueError("No root element found in AXML")
        return root_nodes[0]

    @classmethod
    def append_string_to_pool(cls, sp_chunk: bytes, new_strings: List[str]) -> bytes:
        """
        Appends new_strings to an existing binary AXML StringPool chunk.
        Correctly preserves style tables, recalculates styles_start, shifts offsets,
        and maintains 4-byte alignment throughout without corrupting style span indices.
        """
        if not new_strings:
            return sp_chunk

        if len(sp_chunk) < 28:
            raise ValueError("Invalid string pool chunk: truncated header")

        c_type, c_hsize, c_size = struct.unpack_from("<HHI", sp_chunk, 0)
        if c_type != CHUNK_STRING_POOL:
            raise ValueError(f"Invalid chunk type for string pool: 0x{c_type:04x}")

        str_count, style_count, flags, str_start, styles_start = struct.unpack_from("<IIIII", sp_chunk, 8)
        is_utf8 = bool(flags & 0x0100)

        if 28 + (str_count * 4) > len(sp_chunk):
            raise ValueError("String pool offset table exceeds chunk size")
        orig_str_offsets = [struct.unpack_from("<I", sp_chunk, 28 + (i * 4))[0] for i in range(str_count)]

        orig_style_offsets = []
        style_offset_table_start = 28 + (str_count * 4)
        if style_count > 0:
            if style_offset_table_start + (style_count * 4) > len(sp_chunk):
                raise ValueError("Style offset table exceeds chunk size")
            orig_style_offsets = [
                struct.unpack_from("<I", sp_chunk, style_offset_table_start + (i * 4))[0]
                for i in range(style_count)
            ]

        if style_count > 0 and styles_start > 0:
            orig_string_data = sp_chunk[str_start:styles_start]
            orig_style_data = sp_chunk[styles_start:c_size]
        else:
            orig_string_data = sp_chunk[str_start:c_size]
            orig_style_data = b""

        encoded_new_entries = []
        new_str_offsets = []
        curr_offset = len(orig_string_data)

        for s in new_strings:
            new_str_offsets.append(curr_offset)
            if is_utf8:
                enc = s.encode("utf-8")
                c_len = len(s)
                b_len = len(enc)
                prefix = (
                    bytes([c_len & 0x7F, b_len & 0x7F])
                    if b_len < 128 and c_len < 128
                    else struct.pack(">HH", c_len | 0x8000, b_len | 0x8000)
                )
                entry = prefix + enc + b"\x00"
            else:
                u16_enc = s.encode("utf-16le")
                u16_len = len(s)
                if u16_len < 0x8000:
                    prefix = struct.pack("<H", u16_len)
                else:
                    prefix = struct.pack("<HH", (u16_len >> 16) | 0x8000, u16_len & 0xFFFF)
                entry = prefix + u16_enc + b"\x00\x00"

            encoded_new_entries.append(entry)
            curr_offset += len(entry)

        all_string_data = orig_string_data + b"".join(encoded_new_entries)
        pad_len = (4 - (len(all_string_data) % 4)) % 4
        padded_string_data = all_string_data + (b"\x00" * pad_len)

        all_str_offsets = orig_str_offsets + new_str_offsets
        new_str_count = len(all_str_offsets)

        new_str_offsets_bytes = struct.pack(f"<{new_str_count}I", *all_str_offsets)
        new_style_offsets_bytes = (
            struct.pack(f"<{style_count}I", *orig_style_offsets) if style_count > 0 else b""
        )

        new_str_start = 28 + len(new_str_offsets_bytes) + len(new_style_offsets_bytes)

        if style_count > 0 and styles_start > 0:
            new_styles_start = 28 + (new_str_count * 4) + (style_count * 4) + len(padded_string_data)
            style_pad = (4 - (len(orig_style_data) % 4)) % 4
            padded_style_data = orig_style_data + (b"\x00" * style_pad)
            new_c_size = new_styles_start + len(padded_style_data)
        else:
            new_styles_start = 0
            padded_style_data = b""
            new_c_size = new_str_start + len(padded_string_data)

        new_header = struct.pack(
            "<HHI IIIII",
            CHUNK_STRING_POOL, 28, new_c_size,
            new_str_count, style_count, flags,
            new_str_start, new_styles_start,
        )

        return new_header + new_str_offsets_bytes + new_style_offsets_bytes + padded_string_data + padded_style_data

    @classmethod
    def strip_split_locks(cls, manifest_bytes: bytes) -> bytes:
        """
        Strips all split APK lock attributes and meta-data tags from binary AndroidManifest.xml.
        """
        root = cls.parse(manifest_bytes)

        manifest_strip = {"split", "configForSplit", "requiredSplitTypes", "splitTypes"}
        root.attributes = [
            a for a in root.attributes
            if a.name not in manifest_strip and a.name.split(":")[-1] not in manifest_strip
        ]

        app_node = root.find_child("application")
        if app_node:
            app_strip = {"isSplitRequired", "requiredSplitTypes", "splitTypes"}
            app_node.attributes = [
                a for a in app_node.attributes
                if a.name not in app_strip and a.name.split(":")[-1] not in app_strip
            ]

            target_meta_names = {
                "com.android.vending.splits.required",
                "com.android.vending.splits",
                "com.android.vending.derived.apk.id",
            }
            app_node.children = [
                ch for ch in app_node.children
                if not (
                    ch.tag == "meta-data"
                    and any(
                        (a.name in ("name", "android:name") or a.name.split(":")[-1] == "name")
                        and (a.raw_value in target_meta_names or a.get_value() in target_meta_names)
                        for a in ch.attributes
                    )
                )
            ]

        return cls.serialize(root)

    @staticmethod
    def serialize(root: AxmlNode) -> bytes:
        string_list: List[str] = []
        string_map: Dict[str, int] = {}

        def add_str(s: Optional[str]) -> int:
            if s is None:
                return 0xFFFFFFFF
            if s not in string_map:
                string_map[s] = len(string_list)
                string_list.append(s)
            return string_map[s]

        add_str(ANDROID_NS)
        add_str("android")

        for k in KNOWN_RESOURCE_IDS:
            add_str(k)

        def attr_sort_key(attr: AxmlAttribute):
            attr_base_name = attr.name.split(":")[-1]
            res_id = KNOWN_RESOURCE_IDS.get(attr.name, KNOWN_RESOURCE_IDS.get(attr_base_name, 0))
            if res_id > 0:
                return (0, res_id)
            return (1, 0)

        def walk_collect(node: AxmlNode):
            if node.ns: add_str(node.ns)
            add_str(node.tag)
            for a in sorted(node.attributes, key=attr_sort_key):
                if a.ns: add_str(a.ns)
                add_str(a.name)
                if a.raw_value is not None:
                    add_str(a.raw_value)
            for ch in node.children:
                walk_collect(ch)

        walk_collect(root)

        encoded_strings = []
        offsets = []
        curr_offset = 0
        for s in string_list:
            enc = s.encode("utf-8")
            b_len = len(enc)
            c_len = len(s)
            prefix = bytes([c_len & 0x7F, b_len & 0x7F]) if b_len < 128 and c_len < 128 else struct.pack(">HH", c_len | 0x8000, b_len | 0x8000)
            entry = prefix + enc + b"\x00"
            offsets.append(curr_offset)
            encoded_strings.append(entry)
            curr_offset += len(entry)

        raw_strings_data = b"".join(encoded_strings)
        pad = (4 - (len(raw_strings_data) % 4)) % 4
        raw_strings_data += b"\x00" * pad

        str_count = len(string_list)
        offsets_data = struct.pack(f"<{str_count}I", *offsets)
        str_start = 28 + len(offsets_data)
        sp_size = str_start + len(raw_strings_data)
        sp_chunk = struct.pack("<HHI IIIII", CHUNK_STRING_POOL, 28, sp_size, str_count, 0, 0x0100, str_start, 0) + offsets_data + raw_strings_data

        res_ids = []
        for s in string_list:
            res_ids.append(KNOWN_RESOURCE_IDS.get(s, 0))
        rm_size = 8 + (len(res_ids) * 4)
        rm_chunk = struct.pack("<HHI", CHUNK_RESOURCE_MAP, 8, rm_size) + struct.pack(f"<{len(res_ids)}I", *res_ids)

        ns_prefix_idx = string_map["android"]
        ns_uri_idx = string_map[ANDROID_NS]
        start_ns = struct.pack("<HHI II II", CHUNK_START_NS, 16, 24, 1, 0xFFFFFFFF, ns_prefix_idx, ns_uri_idx)
        end_ns = struct.pack("<HHI II II", CHUNK_END_NS, 16, 24, 1, 0xFFFFFFFF, ns_prefix_idx, ns_uri_idx)

        body_bytes = bytearray()

        def serialize_node(node: AxmlNode, line: int):
            nonlocal body_bytes
            ns_idx = add_str(node.ns) if node.ns else 0xFFFFFFFF
            name_idx = add_str(node.tag)

            # Attribute Resource-ID Sorting Invariant:
            # Attributes with valid resource ID (> 0) sorted in strict ascending order.
            # Attributes with no resource ID (res_id == 0) placed after in stable order.
            def attr_sort_key(attr: AxmlAttribute):
                attr_base_name = attr.name.split(":")[-1]
                res_id = KNOWN_RESOURCE_IDS.get(attr.name, KNOWN_RESOURCE_IDS.get(attr_base_name, 0))
                if res_id > 0:
                    return (0, res_id)
                return (1, 0)

            sorted_attributes = sorted(node.attributes, key=attr_sort_key)

            attr_count = len(sorted_attributes)
            elem_size = 36 + (attr_count * 20)
            elem_header = struct.pack(
                "<HHI II II HHH HHH",
                CHUNK_START_ELEMENT, 16, elem_size, line, 0xFFFFFFFF,
                ns_idx, name_idx, 20, 20, attr_count, 0, 0, 0
            )
            body_bytes.extend(elem_header)

            for a in sorted_attributes:
                a_ns = add_str(a.ns) if a.ns else 0xFFFFFFFF
                a_name = add_str(a.name)
                a_raw = add_str(a.raw_value) if a.raw_value is not None else 0xFFFFFFFF
                data_val = a.data
                if a.data_type == 0x03 and a.raw_value is not None:
                    data_val = a_raw
                attr_record = struct.pack("<III HBB I", a_ns, a_name, a_raw, 8, 0, a.data_type, data_val)
                body_bytes.extend(attr_record)

            for ch in node.children:
                serialize_node(ch, line + 1)

            end_elem = struct.pack("<HHI II II", CHUNK_END_ELEMENT, 16, 24, line, 0xFFFFFFFF, ns_idx, name_idx)
            body_bytes.extend(end_elem)

        serialize_node(root, 1)

        total_size = 8 + len(sp_chunk) + len(rm_chunk) + len(start_ns) + len(body_bytes) + len(end_ns)
        xml_header = struct.pack("<HHI", CHUNK_XML, 8, total_size)
        return xml_header + sp_chunk + rm_chunk + start_ns + bytes(body_bytes) + end_ns

    @classmethod
    def patch_manifest(cls, data: bytes, transforms: List[str], options: Optional[Dict[str, Any]] = None) -> bytes:
        options = options or {}
        root = cls.parse(data)

        # 0. Bump targetSdkVersion if requested
        bump_target_sdk = options.get("bump_target_sdk")
        if bump_target_sdk is not None:
            uses_sdk = root.find_child("uses-sdk")
            if not uses_sdk:
                uses_sdk = AxmlNode(tag="uses-sdk")
                root.children.insert(0, uses_sdk)
            uses_sdk.set_attr("targetSdkVersion", int(bump_target_sdk))

        app_node = root.find_child("application")
        if not app_node:
            return cls.serialize(root)

        # 1. SET_HAS_CODE_TRUE
        if "SET_HAS_CODE_TRUE" in transforms or options.get("force_has_code"):
            app_node.set_attr("hasCode", True)

        # 2. INJECT_USES_LIBRARY_APACHE_HTTP
        if "INJECT_USES_LIBRARY_APACHE_HTTP" in transforms:
            existing = app_node.find_child("uses-library", "name", "org.apache.http.legacy")
            if not existing:
                lib_node = AxmlNode(tag="uses-library")
                lib_node.set_attr("name", "org.apache.http.legacy")
                lib_node.set_attr("required", False)
                app_node.children.append(lib_node)

        # 3. EXPAND_ASPECT_RATIO
        if "EXPAND_ASPECT_RATIO" in transforms:
            app_node.set_attr("resizeableActivity", True)
            existing_aspect = app_node.find_child("meta-data", "name", "android.max_aspect")
            if not existing_aspect:
                aspect_node = AxmlNode(tag="meta-data")
                aspect_node.set_attr("name", "android.max_aspect")
                aspect_node.set_attr("value", "2.5")
                app_node.children.append(aspect_node)

        # 4. PAGE_SIZE_COMPAT
        if "PAGE_SIZE_COMPAT" in transforms:
            app_node.set_attr("pageSizeCompat", "enabled")

        # 5. Display Modes & Shim Provider
        enable_60hz = options.get("enable_60hz", "LOCK_60HZ_DISPLAY_MODE" in transforms)
        enable_cutout = options.get("enable_cutout", False)
        standalone_install = options.get("standalone_install", False) or ("STANDALONE_INSTALL" in transforms)
        inject_shim = enable_60hz or enable_cutout or standalone_install or options.get("inject_shim", False)

        if enable_60hz:
            if not app_node.find_child("meta-data", "name", "apkrevive.enable_60hz_lock"):
                meta_60 = AxmlNode(tag="meta-data")
                meta_60.set_attr("name", "apkrevive.enable_60hz_lock")
                meta_60.set_attr("value", "true")
                app_node.children.append(meta_60)

        if enable_cutout:
            if not app_node.find_child("meta-data", "name", "apkrevive.enable_cutout_short_edges"):
                meta_cutout = AxmlNode(tag="meta-data")
                meta_cutout.set_attr("name", "apkrevive.enable_cutout_short_edges")
                meta_cutout.set_attr("value", "true")
                app_node.children.append(meta_cutout)

        if inject_shim:
            app_node.set_attr("hasCode", True)
            pkg_attr = root.get_attr("package")
            pkg_name = pkg_attr.raw_value if pkg_attr and pkg_attr.raw_value else "com.apkrevive.app"
            prov_node = app_node.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider")
            if not prov_node:
                prov_node = AxmlNode(tag="provider")
                prov_node.set_attr("name", "apkrevive.shim.ApkReviveInitProvider")
                app_node.children.append(prov_node)
            prov_node.set_attr("authorities", f"{pkg_name}.apkrevive.init")
            prov_node.set_attr("exported", False)
            prov_node.set_attr("initOrder", 2147483647)

        return cls.serialize(root)
