"""
axml.py - Binary AXML parser, serializer, and idempotent manifest surgeon.
Guarantees AXML(N) == AXML(N+1).
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple


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
    "resource": 0x01010025,
    "installLocation": 0x010102B7,
    "glEsVersion": 0x01010281,
    "maxSdkVersion": 0x01010271,
    "icon": 0x01010002,
    "label": 0x01010001,
    "theme": 0x01010000,
    "screenOrientation": 0x0101001E,
    "configChanges": 0x0101001F,
    "allowBackup": 0x01010280,
    "anyDensity": 0x0101026C,
    "compileSdkVersion": 0x01010572,
    "compileSdkVersionCodename": 0x01010573,
}


class UnsupportedAxmlChunk(ValueError):
    pass


__all__ = [
    "AxmlSurgeon",
    "AxmlNode",
    "AxmlAttribute",
    "UnsupportedAxmlChunk",
    "CHUNK_XML",
    "CHUNK_STRING_POOL",
    "CHUNK_RESOURCE_MAP",
    "CHUNK_START_NS",
    "CHUNK_END_NS",
    "CHUNK_START_ELEMENT",
    "CHUNK_END_ELEMENT",
    "ANDROID_NS",
    "KNOWN_RESOURCE_IDS",
]


@dataclass
class AxmlAttribute:
    ns: str
    name: str
    raw_value: Optional[str]
    data_type: int
    data: int
    resource_id: int = 0

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
    _raw_source_bytes: Optional[bytes] = field(default=None, repr=False, compare=False)
    _ast_signature: Optional[Tuple[Any, ...]] = field(default=None, repr=False, compare=False)
    _orig_resource_map: Dict[str, int] = field(default_factory=dict, repr=False, compare=False)
    _orig_namespaces: List[Tuple[str, str]] = field(default_factory=list, repr=False, compare=False)

    def tree_signature(self) -> Tuple[Any, ...]:
        return (
            self.tag,
            self.ns,
            tuple((a.ns, a.name, a.raw_value, a.data_type, a.data, a.resource_id) for a in self.attributes),
            tuple(c.tree_signature() for c in self.children),
        )

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

    def set_attr(self, name: str, value: Any, ns: Optional[str] = None):
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

        base_name = name.split(":")[-1]
        if ns is None:
            if base_name in ("package", "split", "configForSplit", "featureSplit") or name.startswith("custom_"):
                ns = ""
            else:
                ns = ANDROID_NS

        res_id = KNOWN_RESOURCE_IDS.get(name, KNOWN_RESOURCE_IDS.get(base_name, 0)) if ns else 0

        if existing:
            existing.data_type = data_type
            existing.data = data
            existing.raw_value = raw_val
            if res_id:
                existing.resource_id = res_id
        else:
            self.attributes.append(AxmlAttribute(
                ns=ns,
                name=name,
                raw_value=raw_val,
                data_type=data_type,
                data=data,
                resource_id=res_id
            ))


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
        if file_size > len(data):
            raise ValueError(f"AXML declared size {file_size} exceeds buffer {len(data)}")
        if file_size < header_size:
            raise ValueError(f"Invalid AXML file size: {file_size} is smaller than header size {header_size}")

        offset = 8
        strings: List[str] = []
        _resource_map: List[int] = []
        root_nodes: List[AxmlNode] = []
        element_stack: List[AxmlNode] = []
        orig_namespaces: List[Tuple[str, str]] = []
        chunk_count = 0
        MAX_CHUNKS = 100_000

        while offset < file_size:
            chunk_count += 1
            if chunk_count > MAX_CHUNKS:
                raise ValueError("AXML chunk count exceeded limit (cyclic chunk loop detected)")

            if offset + 8 > file_size:
                raise ValueError("Invalid AXML: unexpected EOF reading chunk header")

            c_type, c_hsize, c_size = struct.unpack_from("<HHI", data, offset)
            if c_hsize < 8:
                raise ValueError(f"Invalid AXML chunk header size: {c_hsize}")
            if c_size < c_hsize:
                raise ValueError(f"Invalid AXML chunk size: {c_size}")
            if offset + c_size > file_size:
                raise ValueError("Invalid AXML chunk size exceeds declared file_size")

            if c_type == CHUNK_STRING_POOL:
                if offset + 28 > offset + c_size:
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

            elif c_type == CHUNK_START_NS:
                if offset + 24 > offset + c_size:
                    raise ValueError("Start namespace chunk truncated")
                line_no, comment, prefix_idx, uri_idx = struct.unpack_from("<IIII", data, offset + 8)
                prefix = strings[prefix_idx] if 0 <= prefix_idx < len(strings) else ""
                uri = strings[uri_idx] if 0 <= uri_idx < len(strings) else ""
                orig_namespaces.append((prefix, uri))

            elif c_type == CHUNK_END_NS:
                pass

            elif c_type == CHUNK_START_ELEMENT:
                if offset + 28 > offset + c_size:
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
                        raise ValueError("Truncated AXML attribute list")
                    a_ns, a_name, a_raw, a_sz, a_res0, a_type, a_data = struct.unpack_from("<IIIHBB I", data, attr_offset)
                    ans_str = strings[a_ns] if 0 <= a_ns < len(strings) else ""
                    aname_str = strings[a_name] if 0 <= a_name < len(strings) else ""
                    araw_str = strings[a_raw] if 0 <= a_raw < len(strings) else None
                    a_res_id = _resource_map[a_name] if 0 <= a_name < len(_resource_map) else 0
                    node.attributes.append(AxmlAttribute(
                        ns=ans_str,
                        name=aname_str,
                        raw_value=araw_str,
                        data_type=a_type,
                        data=a_data,
                        resource_id=a_res_id
                    ))
                    attr_offset += attr_size if attr_size >= 20 else 20

                if element_stack:
                    element_stack[-1].children.append(node)
                else:
                    root_nodes.append(node)
                element_stack.append(node)

            elif c_type == CHUNK_END_ELEMENT:
                if element_stack:
                    element_stack.pop()

            else:
                raise UnsupportedAxmlChunk(f"Unsupported AXML chunk type: 0x{c_type:04x} at offset {offset}")

            offset += c_size

        if not root_nodes:
            raise ValueError("No root element found in AXML")
        root = root_nodes[0]
        root._raw_source_bytes = data
        root._ast_signature = root.tree_signature()
        root._orig_resource_map = {
            strings[i]: _resource_map[i]
            for i in range(len(_resource_map))
            if i < len(strings) and _resource_map[i] != 0
        }
        root._orig_namespaces = orig_namespaces
        return root

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
        if (
            getattr(root, "_raw_source_bytes", None) is not None
            and getattr(root, "_ast_signature", None) == root.tree_signature()
        ):
            return root._raw_source_bytes  # type: ignore[return-value]

        string_list: List[str] = []
        string_map: Dict[str, int] = {}

        # Collect and validate resource map from original manifest + known platform attributes
        res_map: Dict[str, int] = dict(getattr(root, "_orig_resource_map", {}))
        for k, v in KNOWN_RESOURCE_IDS.items():
            if k not in res_map:
                res_map[k] = v

        def validate_node_attributes(node: AxmlNode):
            for a in node.attributes:
                attr_base_name = a.name.split(":")[-1]
                if attr_base_name in ("package", "split", "configForSplit", "featureSplit") or a.name.startswith("custom_"):
                    a.ns = ""
                    a.resource_id = 0
                    continue
                if a.resource_id != 0:
                    res_map[a.name] = a.resource_id
                    res_map[attr_base_name] = a.resource_id
                else:
                    if attr_base_name in res_map:
                        a.resource_id = res_map[attr_base_name]
                    elif a.name in res_map:
                        a.resource_id = res_map[a.name]
                    elif attr_base_name in KNOWN_RESOURCE_IDS:
                        a.resource_id = KNOWN_RESOURCE_IDS[attr_base_name]
                        res_map[attr_base_name] = a.resource_id
                        res_map[a.name] = a.resource_id
                    elif a.ns == ANDROID_NS or a.name.startswith("android:"):
                        raise ValueError(
                            f"Unknown Android manifest attribute '{a.name}' (namespace '{a.ns}'): "
                            f"no resource ID found in original manifest resource map or known platform definitions."
                        )
            for ch in node.children:
                validate_node_attributes(ch)

        validate_node_attributes(root)

        def add_str(s: Optional[str]) -> int:
            if s is None:
                return 0xFFFFFFFF
            if s not in string_map:
                string_map[s] = len(string_list)
                string_list.append(s)
            return string_map[s]

        # Collect distinct namespaces, keeping xmlns:android ("android", ANDROID_NS) first
        declared_namespaces: List[Tuple[str, str]] = [("android", ANDROID_NS)]
        seen_ns = {("android", ANDROID_NS)}
        seen_uris = {ANDROID_NS}
        for pfx, uri in getattr(root, "_orig_namespaces", []):
            if uri and (pfx, uri) not in seen_ns and uri not in seen_uris:
                declared_namespaces.append((pfx, uri))
                seen_ns.add((pfx, uri))
                seen_uris.add(uri)

        def collect_referenced_ns(node: AxmlNode):
            if node.ns and node.ns not in seen_uris:
                pfx = ""
                if ":" in node.tag:
                    pfx = node.tag.split(":")[0]
                elif node.ns == "http://schemas.android.com/tools":
                    pfx = "tools"
                elif node.ns == "http://schemas.android.com/apk/res-auto":
                    pfx = "app"
                else:
                    pfx = f"ns{len(declared_namespaces)}"
                declared_namespaces.append((pfx, node.ns))
                seen_ns.add((pfx, node.ns))
                seen_uris.add(node.ns)
            for a in node.attributes:
                if a.ns and a.ns not in seen_uris:
                    pfx = ""
                    if ":" in a.name:
                        pfx = a.name.split(":")[0]
                    elif a.ns == "http://schemas.android.com/tools":
                        pfx = "tools"
                    elif a.ns == "http://schemas.android.com/apk/res-auto":
                        pfx = "app"
                    else:
                        pfx = f"ns{len(declared_namespaces)}"
                    declared_namespaces.append((pfx, a.ns))
                    seen_ns.add((pfx, a.ns))
                    seen_uris.add(a.ns)
                elif ":" in a.name:
                    pfx, _ = a.name.split(":", 1)
                    if pfx == "tools" and "http://schemas.android.com/tools" not in seen_uris:
                        declared_namespaces.append(("tools", "http://schemas.android.com/tools"))
                        seen_ns.add(("tools", "http://schemas.android.com/tools"))
                        seen_uris.add("http://schemas.android.com/tools")
            for ch in node.children:
                collect_referenced_ns(ch)

        collect_referenced_ns(root)

        def attr_sort_key_indexed(item: Tuple[int, AxmlAttribute]):
            idx, attr = item
            attr_base_name = attr.name.split(":")[-1]
            res_id = attr.resource_id or res_map.get(
                attr.name, res_map.get(attr_base_name, KNOWN_RESOURCE_IDS.get(attr.name, KNOWN_RESOURCE_IDS.get(attr_base_name, 0)))
            )
            if res_id > 0:
                return (0, res_id, idx)
            return (1, 0, idx)

        # Pass 1: Collect all strings
        add_str(ANDROID_NS)
        add_str("android")

        for pfx, uri in declared_namespaces:
            add_str(pfx)
            add_str(uri)

        for k in res_map:
            add_str(k)

        def walk_collect(node: AxmlNode):
            if node.ns:
                add_str(node.ns)
            add_str(node.tag)
            indexed_attrs = list(enumerate(node.attributes))
            sorted_indexed = sorted(indexed_attrs, key=attr_sort_key_indexed)
            for _, a in sorted_indexed:
                if a.ns:
                    add_str(a.ns)
                add_str(a.name)
                if a.raw_value is not None:
                    add_str(a.raw_value)
            for ch in node.children:
                walk_collect(ch)

        walk_collect(root)

        initial_count = len(string_list)

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
            base_s = s.split(":")[-1]
            rid = res_map.get(s, res_map.get(base_s, KNOWN_RESOURCE_IDS.get(s, KNOWN_RESOURCE_IDS.get(base_s, 0))))
            res_ids.append(rid)
        rm_size = 8 + (len(res_ids) * 4)
        rm_chunk = struct.pack("<HHI", CHUNK_RESOURCE_MAP, 8, rm_size) + struct.pack(f"<{len(res_ids)}I", *res_ids)

        start_ns_chunks = bytearray()
        for pfx, uri in declared_namespaces:
            start_ns_chunks.extend(
                struct.pack("<HHI II II", CHUNK_START_NS, 16, 24, 1, 0xFFFFFFFF, string_map[pfx], string_map[uri])
            )

        end_ns_chunks = bytearray()
        for pfx, uri in reversed(declared_namespaces):
            end_ns_chunks.extend(
                struct.pack("<HHI II II", CHUNK_END_NS, 16, 24, 1, 0xFFFFFFFF, string_map[pfx], string_map[uri])
            )

        # Pass 2: Serialize nodes and emit indices
        body_bytes = bytearray()

        def serialize_node(node: AxmlNode, line: int):
            nonlocal body_bytes
            ns_idx = add_str(node.ns) if node.ns else 0xFFFFFFFF
            name_idx = add_str(node.tag)

            # Attribute Resource-ID Sorting Invariant:
            # Attributes with valid resource ID (> 0) sorted in strict ascending order.
            # Attributes with no resource ID (res_id == 0) placed after in stable order.
            indexed_attrs = list(enumerate(node.attributes))
            sorted_indexed = sorted(indexed_attrs, key=attr_sort_key_indexed)
            sorted_attributes = [a for _, a in sorted_indexed]

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
                if a.data_type == 0x03:
                    data_val = a_raw if a.raw_value is not None else 0xFFFFFFFF
                else:
                    data_val = a.data
                attr_record = struct.pack("<III HBB I", a_ns, a_name, a_raw, 8, 0, a.data_type, data_val)
                body_bytes.extend(attr_record)

            for ch in node.children:
                serialize_node(ch, line + 1)

            end_elem = struct.pack("<HHI II II", CHUNK_END_ELEMENT, 16, 24, line, 0xFFFFFFFF, ns_idx, name_idx)
            body_bytes.extend(end_elem)

        serialize_node(root, 1)

        if len(string_list) > initial_count:
            raise AssertionError("String pool grew during node serialization")
        assert len(string_list) == initial_count

        total_size = 8 + len(sp_chunk) + len(rm_chunk) + len(start_ns_chunks) + len(body_bytes) + len(end_ns_chunks)
        xml_header = struct.pack("<HHI", CHUNK_XML, 8, total_size)
        return xml_header + sp_chunk + rm_chunk + bytes(start_ns_chunks) + bytes(body_bytes) + bytes(end_ns_chunks)

    @classmethod
    def patch_manifest(
        cls,
        data: bytes,
        transforms: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        inject_shim: Optional[bool] = None,
    ) -> bytes:
        transforms = transforms or []
        options = options or {}
        root = cls.parse(data)

        # 0. Strip Split-Lock attributes and meta-data tags
        split_attr_names = {"isSplitRequired", "requiredSplitTypes", "splitTypes"}
        split_meta_names = {
            "com.android.vending.splits.required",
            "com.android.vending.splits",
            "com.android.vending.derived.apk.id",
        }

        def strip_splits(node: AxmlNode):
            node.attributes = [
                a for a in node.attributes
                if a.name not in split_attr_names and a.name.split(":")[-1] not in split_attr_names
            ]
            node.children = [
                ch for ch in node.children
                if not (
                    ch.tag.split(":")[-1] == "meta-data"
                    and any(
                        (a.name.split(":")[-1] == "name")
                        and (a.raw_value in split_meta_names or a.get_value() in split_meta_names)
                        for a in ch.attributes
                    )
                )
            ]
            for ch in node.children:
                strip_splits(ch)

        strip_splits(root)

        # 1. Ensure <uses-sdk> exists and set targetSdkVersion / minSdkVersion
        bump_target_sdk = options.get("bump_target_sdk")
        uses_sdk = root.find_child("uses-sdk")
        if not uses_sdk:
            uses_sdk = AxmlNode(tag="uses-sdk")
            root.children.insert(0, uses_sdk)
            uses_sdk.set_attr("minSdkVersion", 14)
            target_val = bump_target_sdk if bump_target_sdk is not None else options.get("target_sdk", 28)
            uses_sdk.set_attr("targetSdkVersion", int(target_val))
        else:
            if bump_target_sdk is not None:
                uses_sdk.set_attr("targetSdkVersion", int(bump_target_sdk))
            if uses_sdk.get_attr("minSdkVersion") is None:
                uses_sdk.set_attr("minSdkVersion", 14)

        app_node = root.find_child("application")
        if not app_node:
            out_bytes = cls.serialize(root)
            check_root = cls.parse(out_bytes)
            def check_no_dup(node: AxmlNode):
                seen = set()
                for a in node.attributes:
                    key = (a.ns, a.name)
                    if key in seen:
                        raise AssertionError(f"Duplicate attribute {key} on node <{node.tag}>")
                    seen.add(key)
                for ch in node.children:
                    check_no_dup(ch)
            check_no_dup(check_root)
            return out_bytes

        # 2. INJECT_USES_LIBRARY_APACHE_HTTP
        if "INJECT_USES_LIBRARY_APACHE_HTTP" in transforms or options.get("inject_apache_http", True):
            existing_http = app_node.find_child("uses-library", "name", "org.apache.http.legacy")
            if not existing_http:
                lib_node = AxmlNode(tag="uses-library")
                lib_node.set_attr("name", "org.apache.http.legacy")
                lib_node.set_attr("required", False)
                app_node.children.append(lib_node)

        # 3. EXPAND_ASPECT_RATIO
        if "EXPAND_ASPECT_RATIO" in transforms:
            app_node.set_attr("resizeableActivity", True)
            app_node.set_attr("maxAspectRatio", "2.5")
            existing_aspect = app_node.find_child("meta-data", "name", "android.max_aspect")
            if existing_aspect:
                existing_aspect.set_attr("value", "2.5")
            else:
                aspect_node = AxmlNode(tag="meta-data")
                aspect_node.set_attr("name", "android.max_aspect")
                aspect_node.set_attr("value", "2.5")
                app_node.children.append(aspect_node)
        else:
            app_node.set_attr("resizeableActivity", True)

        # 4. PAGE_SIZE_COMPAT
        if "PAGE_SIZE_COMPAT" in transforms or options.get("page_size_compat", True):
            app_node.set_attr("pageSizeCompat", "enabled")

        # 5. Native library extraction, Scoped Storage, and Cleartext HTTP
        app_node.set_attr("extractNativeLibs", True)
        app_node.set_attr("requestLegacyExternalStorage", True)
        app_node.set_attr("usesCleartextTraffic", True)

        # 6. Component android:exported safety (targetSdk >= 31 or components with intent-filter)
        component_tags = {"activity", "activity-alias", "service", "receiver"}
        for ch in app_node.children:
            tag_base = ch.tag.split(":")[-1]
            if tag_base in component_tags:
                has_intent_filter = any(
                    (sub.tag == "intent-filter" or sub.tag.split(":")[-1] == "intent-filter")
                    for sub in ch.children
                )
                if has_intent_filter and ch.get_attr("exported") is None:
                    ch.set_attr("exported", True)

        # 7. Shim Provider
        enable_60hz = options.get("enable_60hz", "LOCK_60HZ_DISPLAY_MODE" in transforms)
        enable_cutout = options.get("enable_cutout", False)
        standalone_install = options.get("standalone_install", False) or ("STANDALONE_INSTALL" in transforms)
        if inject_shim is None:
            inject_shim = enable_60hz or enable_cutout or standalone_install or options.get("inject_shim", False)

        if "SET_HAS_CODE_TRUE" in transforms or options.get("force_has_code") or inject_shim:
            app_node.set_attr("hasCode", True)
            pkg_attr = root.get_attr("package")
            pkg_name = pkg_attr.raw_value if pkg_attr and pkg_attr.raw_value else "com.apkrevive.app"
            prov_node = app_node.find_child("provider", "name", "com.apkrevive.shim.ApkReviveInitProvider")
            if not prov_node:
                prov_node = app_node.find_child("provider", "name", "com.apkrevive.runtime.ApkReviveInitProvider")
            if not prov_node:
                prov_node = app_node.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider")
            if not prov_node:
                prov_node = AxmlNode(tag="provider")
                app_node.children.append(prov_node)
            prov_node.set_attr("name", "com.apkrevive.shim.ApkReviveInitProvider")
            prov_node.set_attr("authorities", f"{pkg_name}.apkrevive.init")
            prov_node.set_attr("exported", False)
            prov_node.set_attr("initOrder", 2147483647)

        out_bytes = cls.serialize(root)
        check_root = cls.parse(out_bytes)

        if inject_shim:
            check_app = check_root.find_child("application")
            if not check_app:
                raise AssertionError("inject_shim active but application element missing in serialized manifest")
            providers = [
                ch for ch in check_app.children
                if (ch.tag == "provider" or ch.tag.split(":")[-1] == "provider")
                and any(
                    (a.name == "name" or a.name.split(":")[-1] == "name")
                    and (
                        a.raw_value in (
                            "com.apkrevive.shim.ApkReviveInitProvider",
                            "com.apkrevive.runtime.ApkReviveInitProvider",
                            "apkrevive.shim.ApkReviveInitProvider",
                        )
                        or a.get_value() in (
                            "com.apkrevive.shim.ApkReviveInitProvider",
                            "com.apkrevive.runtime.ApkReviveInitProvider",
                            "apkrevive.shim.ApkReviveInitProvider",
                        )
                    )
                    for a in ch.attributes
                )
            ]
            if len(providers) != 1:
                raise AssertionError(f"Expected provider ApkReviveInitProvider present exactly once, found {len(providers)}")
            has_code_attr = check_app.get_attr("hasCode")
            if not has_code_attr or not has_code_attr.get_value():
                raise AssertionError("Expected hasCode to be True when inject_shim is active")

        if "INJECT_USES_LIBRARY_APACHE_HTTP" in transforms:
            check_app = check_root.find_child("application")
            if not check_app:
                raise AssertionError("INJECT_USES_LIBRARY_APACHE_HTTP active but application element missing in serialized manifest")
            libs = [
                ch for ch in check_app.children
                if (ch.tag == "uses-library" or ch.tag.split(":")[-1] == "uses-library")
                and any(
                    (a.name == "name" or a.name.split(":")[-1] == "name")
                    and (a.raw_value == "org.apache.http.legacy" or a.get_value() == "org.apache.http.legacy")
                    for a in ch.attributes
                )
            ]
            if len(libs) != 1:
                raise AssertionError(f"Expected uses-library org.apache.http.legacy present exactly once, found {len(libs)}")

        def check_no_duplicate_attrs(node: AxmlNode):
            seen = set()
            for a in node.attributes:
                key = (a.ns, a.name)
                if key in seen:
                    raise AssertionError(f"Duplicate attribute {key} on node <{node.tag}>")
                seen.add(key)
            for ch in node.children:
                check_no_duplicate_attrs(ch)

        check_no_duplicate_attrs(check_root)

        return out_bytes
