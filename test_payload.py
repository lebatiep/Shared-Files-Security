"""Chạy python -m unittest -v test_payload; dữ liệu chỉ sinh trong bộ nhớ."""

import json
import unittest

from payload import (MAX_FILE_SIZE, MAX_METADATA_SIZE, MAX_PAYLOAD_SIZE,
                     pack_payload, unpack_payload)


def frame(metadata, raw=b""):
    return len(metadata).to_bytes(4, "big") + metadata + raw


class PayloadTests(unittest.TestCase):
    def test_round_trip(self):
        for name, raw in (("empty", b""), ("../thư mục/日本語.txt", bytes(range(256))),
                          ('quote"\\line\n', b"\0\xff")):
            with self.subTest(name=name):
                packed = pack_payload(name, raw)
                self.assertEqual(unpack_payload(packed), (name, raw))
                size = int.from_bytes(packed[:4], "big")
                self.assertEqual(packed[4:4 + size].decode("utf-8"),
                                 json.dumps({"filename": name},
                                 ensure_ascii=False, separators=(",", ":")))

    def test_size_boundaries(self):
        name = "a" * (MAX_METADATA_SIZE - len(b'{"filename":""}'))
        raw = bytes(MAX_FILE_SIZE)
        packed = pack_payload(name, raw)
        self.assertEqual(len(packed), MAX_PAYLOAD_SIZE)
        self.assertEqual(unpack_payload(packed), (name, raw))
        for bad_name, bad_raw in ((name + "a", b""), ("é" * 2048, b""),
                                  ("x", raw + b"x")):
            with self.assertRaises(ValueError):
                pack_payload(bad_name, bad_raw)
        with self.assertRaises(ValueError):
            unpack_payload(frame(b'{"filename":"x"}', raw + b"x"))
        with self.assertRaises(ValueError):
            unpack_payload(packed + b"x")

    def test_invalid_framing(self):
        for data in (b"", b"\0" * 3, bytes(4), b"\0\0\0\x10{}",
                     (MAX_METADATA_SIZE + 1).to_bytes(4, "big") + bytes(4097),
                     b"\xff" * 4):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                unpack_payload(data)

    def test_invalid_metadata(self):
        invalid = [b"\xff", b"", b"{", b"[]", b"null", b"1", b"true", b'"x"',
                   b"{}", b'{"filename":"x","extra":1}',
                   b'{"filename":"x","filename":"y"}',
                   b'{"filename":"x","file\\u006eame":"y"}',
                   b'{"filename":""}', b'{"filename":"a\\u0000b"}',
                   b'{"filename":"\\ud800"}', b'{"filename":null}',
                   b'{"filename":true}', b'{"filename":1}', b'{"filename":[]}',
                   b'{"filename":{}}', b'{"filename":NaN}',
                   b'{"filename":Infinity}', b'{"filename":-Infinity}',
                   b'{"filename":"x"} trailing', b"[" * 1500 + b"]" * 1500]
        for metadata in invalid:
            with self.subTest(metadata=metadata[:80]), self.assertRaises(ValueError):
                unpack_payload(frame(metadata))

    def test_invalid_input_types_and_names(self):
        for name in (None, 1, b"x", "", "a\0b", "\ud800"):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                pack_payload(name, b"")
        for value in (None, "x", bytearray(b"x"), memoryview(b"x"), 1):
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                pack_payload("x", value)
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                unpack_payload(value)


if __name__ == "__main__":
    unittest.main()
