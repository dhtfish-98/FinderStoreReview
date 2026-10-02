import struct, unittest
from finderstorereview import inspect


def sample(typ=b"ustr", value=None):
    if value is None:
        value = struct.pack(">I", 3) + "abc".encode("utf-16-be")
    n = "synthetic_private"
    r = struct.pack(">I", len(n)) + n.encode("utf-16-be") + b"cmmt" + typ + value
    data = bytearray(8196)
    struct.pack_into(">I4sIII16s", data, 0, 1, b"Bud1", 2048, 2048, 2048, b"\0" * 16)
    off = 2052
    struct.pack_into(">II", data, off, 3, 0)
    off += 8
    struct.pack_into(">3I", data, off, 2048 | 11, 4096 | 5, 8192 | 5)
    off += 1024
    # Move tree to 4096-byte block at logical 8192; extend storage.
    data.extend(b"\0" * 4096)
    struct.pack_into(">I", data, 2060 + 8, 8192 | 12)
    struct.pack_into(">I", data, off, 1)
    off += 4
    data[off] = 4
    data[off + 1 : off + 5] = b"DSDB"
    struct.pack_into(">I", data, off + 5, 1)
    off += 9
    data[off : off + 128] = b"\0" * 128
    struct.pack_into(">5I", data, 4100, 2, 1, 1, 1, 4096)
    struct.pack_into(">II", data, 8196, 0, 1)
    data[8204 : 8204 + len(r)] = r
    return bytes(data)


class Tests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(inspect(sample())["status"], "PASS")

    def test_types(self):
        for t, v in [
            (b"bool", b"\1"),
            (b"long", b"\0" * 4),
            (b"comp", b"\0" * 8),
            (b"type", b"ABCD"),
            (b"blob", struct.pack(">I", 4) + b"1234"),
        ]:
            self.assertEqual(inspect(sample(t, v))["status"], "PASS")

    def test_private(self):
        self.assertNotIn("synthetic_private", str(inspect(sample())))

    def test_short(self):
        self.assertEqual(inspect(sample()[:6000])["status"], "FAIL")

    def test_count(self):
        d = bytearray(sample())
        struct.pack_into(">I", d, 4108, 2)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_cycle(self):
        d = bytearray(sample())
        struct.pack_into(">I", d, 8196, 2)
        struct.pack_into(">I", d, 8204, 2)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_unknown_type(self):
        self.assertEqual(inspect(sample(b"ZZZZ", b""))["status"], "OPEN")

    def test_bool(self):
        self.assertEqual(inspect(sample(b"bool", b"\2"))["status"], "FAIL")

    def test_mirror(self):
        d = bytearray(sample())
        d[19] ^= 1
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_upstream_writer_multilevel_tree(self):
        from pathlib import Path

        d = (
            Path(__file__).resolve().parents[1] / "examples/upstream_writer_tree.bin"
        ).read_bytes()
        r = inspect(d)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["record_count"], 800)

    def test_allocated_overlap(self):
        d = bytearray(sample())
        struct.pack_into(">I", d, 2060 + 4, 2048 | 11)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_free_live_overlap(self):
        d = bytearray(sample())
        free = 2052 + 8 + 1024 + 4 + 9
        struct.pack_into(">I", d, free + 11 * 4, 1)
        struct.pack_into(">I", d, free + 11 * 4 + 4, 2048)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_unreferenced_allocated_extent_past_eof(self):
        d = bytearray(sample())
        struct.pack_into(">I", d, 2052, 4)
        struct.pack_into(">I", d, 2060 + 12, 16384 | 12)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")
