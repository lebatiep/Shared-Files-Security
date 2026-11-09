"""Kiểm tra bố cục byte và giới hạn đầu vào của envelope."""

import unittest

from envelope import build_aad, build_signature_input, frame


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.header = b' { "v" : 1 }\n'
        self.wrapped_key = bytes(range(128)) * 3
        self.nonce = bytes(range(12))
        self.ciphertext = bytes(range(16))

    def test_frame_known_layout(self):
        self.assertEqual(frame(b""), bytes.fromhex("00000000"))
        self.assertEqual(frame(b"\x00\xffA"), bytes.fromhex("0000000300ff41"))
        self.assertEqual(frame(b"x" * 256)[:4], bytes.fromhex("00000100"))

    def test_aad_preserves_raw_header_and_layout(self):
        expected = (
            bytes.fromhex("5346494c45312d4141440000000d")
            + self.header
            + bytes.fromhex("00000180")
            + self.wrapped_key
        )
        self.assertEqual(build_aad(self.header, self.wrapped_key), expected)

    def test_signature_known_layout(self):
        expected = (
            bytes.fromhex("5346494c45312d5349474e0000000d")
            + self.header
            + bytes.fromhex("00000180")
            + self.wrapped_key
            + bytes.fromhex("0000000c")
            + self.nonce
            + bytes.fromhex("00000010")
            + self.ciphertext
        )
        self.assertEqual(
            build_signature_input(
                self.header, self.wrapped_key, self.nonce, self.ciphertext
            ), expected
        )

    def test_header_and_wrapped_key_invalid_lengths(self):
        for header, key in (
            (b"", self.wrapped_key), (b"h" * 4097, self.wrapped_key),
            (self.header, b"k" * 383), (self.header, b"k" * 385),
        ):
            with self.subTest(header_length=len(header), key_length=len(key)):
                with self.assertRaises(ValueError):
                    build_aad(header, key)
                with self.assertRaises(ValueError):
                    build_signature_input(header, key, self.nonce, self.ciphertext)

    def test_signature_invalid_nonce_and_ciphertext_lengths(self):
        for nonce, ciphertext in (
            (b"n" * 11, self.ciphertext), (b"n" * 13, self.ciphertext),
            (self.nonce, b"c" * 15), (self.nonce, b"c" * 10489877),
        ):
            with self.subTest(nonce_length=len(nonce), ciphertext_length=len(ciphertext)):
                with self.assertRaises(ValueError):
                    build_signature_input(self.header, self.wrapped_key, nonce, ciphertext)

    def test_accepts_boundary_lengths(self):
        for size in (1, 4096):
            self.assertTrue(build_aad(b"h" * size, self.wrapped_key))
        self.assertTrue(build_signature_input(
            self.header, self.wrapped_key, self.nonce, b"c" * 10489876
        ))

    def test_rejects_non_bytes_in_every_position(self):
        for value in (None, "text", 3, bytearray(b"x"), memoryview(b"x")):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    frame(value)
                for index in range(2):
                    arguments = [self.header, self.wrapped_key]
                    arguments[index] = value
                    with self.assertRaises(TypeError):
                        build_aad(*arguments)
                for index in range(4):
                    arguments = [self.header, self.wrapped_key, self.nonce, self.ciphertext]
                    arguments[index] = value
                    with self.assertRaises(TypeError):
                        build_signature_input(*arguments)

    def test_frame_rejects_uint32_overflow_without_large_allocation(self):
        class OversizedBytes(bytes):
            def __len__(self):
                return 0x100000000

        with self.assertRaises(ValueError):
            frame(OversizedBytes())


if __name__ == "__main__":
    unittest.main()
