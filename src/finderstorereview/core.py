import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nofollow, int) or not nofollow or not isinstance(nonblock, int) or not nonblock:
        raise Unsupported("safe_local_read_flags_unavailable")
    fd = os.open(path, os.O_RDONLY | nofollow | nonblock)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except Unsupported as exc:
        report = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        require(n >= 0 and self.pos + n <= len(self.data), "block_field_bounds")
        value = self.data[self.pos : self.pos + n]
        self.pos += n
        return value

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]


def analyze(data):
    magic, cookie, root_offset, root_size, mirror = unpack(">I4sIII", data)
    if magic != 1 or cookie != b"Bud1":
        raise Unsupported("unsupported_buddy_file_header")
    require(
        root_offset == mirror
        and root_offset >= 32
        and root_size >= 8
        and root_offset + 4 + root_size <= len(data),
        "allocator_root_bounds",
    )
    alloc = Cursor(data[root_offset + 4 : root_offset + 4 + root_size])
    count = alloc.number(">I")
    alloc.take(4)
    require(1 <= count <= MAX_RECORDS, "allocator_count")
    slots = [alloc.number(">I") for _ in range((count + 255) & ~255)][:count]
    toc_count = alloc.number(">I")
    require(toc_count <= MAX_RECORDS, "toc_count")
    toc = {}
    for _ in range(toc_count):
        n = alloc.number(">B")
        name = alloc.take(n)
        index = alloc.number(">I")
        require(
            name and name not in toc and index < count and slots[index] != 0,
            "invalid_toc_entry",
        )
        toc[name] = index
    ranges = []
    for index, value in enumerate(slots):
        if not value:
            continue
        position, capacity = value & ~31, 1 << (value & 31)
        require(
            capacity >= 32
            and position >= 32
            and position % capacity == 0
            and position + capacity <= 2**32
            and position + 4 + capacity <= len(data),
            "invalid_allocated_extent",
        )
        ranges.append((position, position + capacity, "allocated", index))
    for width in range(32):
        free_count = alloc.number(">I")
        require(free_count <= MAX_RECORDS, "free_list_limit")
        previous = None
        for _ in range(free_count):
            value = alloc.number(">I")
            require(
                value % (1 << width) == 0
                and value + (1 << width) <= 2**32
                and (previous is None or value > previous),
                "invalid_free_list",
            )
            require(value >= 32 and len(ranges) < MAX_RECORDS, "allocator_extent_limit")
            ranges.append((value, value + (1 << width), "free", width))
            previous = value
    ordered = sorted(ranges)
    require(
        all(ordered[i][1] <= ordered[i + 1][0] for i in range(len(ordered) - 1)),
        "allocator_extents_overlap",
    )
    root_slot = slots[0]
    require(
        root_slot & ~31 == root_offset and (1 << (root_slot & 31)) >= root_size,
        "allocator_header_slot_mismatch",
    )
    require(b"DSDB" in toc, "missing_dsdb")

    def block(index):
        require(0 <= index < count and slots[index] != 0, "invalid_block_reference")
        value = slots[index]
        pos = value & ~31
        size = 1 << (value & 31)
        require(
            size >= 32 and pos >= 32 and pos + 4 + size <= len(data),
            "allocated_block_bounds",
        )
        return Cursor(data[pos + 4 : pos + 4 + size]), pos + 4, size

    superblock, _, _ = block(toc[b"DSDB"])
    tree_root = superblock.number(">I")
    levels = superblock.number(">I")
    declared = superblock.number(">I")
    nodes = superblock.number(">I")
    page = superblock.number(">I")
    require(
        levels <= 64
        and declared <= MAX_RECORDS
        and 0 < nodes <= MAX_RECORDS
        and 512 <= page <= 65536
        and page & (page - 1) == 0,
        "invalid_tree_header",
    )
    visited = set()
    records = []
    keys = []
    leaf_depths = set()

    def record(cursor, base, index):
        require(len(records) < MAX_RECORDS, "record_limit")
        start = cursor.pos
        n = cursor.number(">I")
        require(n <= 32768, "filename_limit")
        name = text(cursor.take(2 * n), "utf-16-be")
        require(name and "\0" not in name, "invalid_filename")
        code = cursor.take(4)
        typ = cursor.take(4)
        require(all(32 <= v <= 126 for v in code), "invalid_record_code")
        if typ == b"bool":
            require(cursor.number(">B") in (0, 1), "invalid_boolean")
        elif typ in (b"long", b"shor"):
            cursor.take(4)
        elif typ in (b"comp", b"dutc"):
            cursor.take(8)
        elif typ == b"type":
            cursor.take(4)
        elif typ in (b"blob", b"ustr"):
            size = cursor.number(">I")
            require(size <= MAX_BYTES, "value_limit")
            value = cursor.take(size * (2 if typ == b"ustr" else 1))
            if typ == b"ustr":
                text(value, "utf-16-be")
        else:
            raise Unsupported("unsupported_dsstore_value_type")
        key = (name.lower(), code)
        keys.append(key)
        records.append(
            {
                "block": index,
                "offset": base + start,
                "name_characters": len(name),
                "code": code.decode("ascii"),
                "type": typ.decode("ascii"),
                "record_bytes": cursor.pos - start,
            }
        )

    def traverse(index, depth):
        require(depth <= 64 and index not in visited, "tree_cycle_or_depth_limit")
        visited.add(index)
        cursor, base, size = block(index)
        require(size >= page, "node_smaller_than_page")
        right = cursor.number(">I")
        n = cursor.number(">I")
        require(n <= MAX_RECORDS, "node_record_limit")
        if not right:
            leaf_depths.add(depth)
        for _ in range(n):
            if right:
                traverse(cursor.number(">I"), depth + 1)
            record(cursor, base, index)
        if right:
            traverse(right, depth + 1)

    traverse(tree_root, 0)
    require(len(records) == declared and len(visited) == nodes, "tree_count_mismatch")
    require(len(leaf_depths) == 1, "unbalanced_tree")
    observed = next(iter(leaf_depths))
    require(
        levels == observed + 1 or (not records and levels == 0), "tree_level_mismatch"
    )
    require(
        all(keys[i] < keys[i + 1] for i in range(len(keys) - 1)),
        "unsorted_or_duplicate_keys",
    )
    return {
        "records": records,
        "record_count": len(records),
        "tree_nodes": len(visited),
        "scope": "Buddy allocator tables and DSDB B-tree/record envelopes; opaque blob internals and unallocated space are outside scope. No filename/value disclosure or writes.",
    }
