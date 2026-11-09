"""Kiểm thử envelope: framing, header, JSON ngoài, payload và các giới hạn."""

import pytest
import base64
import json
import unittest

from secure_share import envelope as env
from secure_share.envelope import (
    MAX_FILE, MAX_METADATA, MAX_PAYLOAD, EnvelopeError, RawEnvelope,
    build_aad, build_payload, build_signature_input, frame, parse_payload)

FP = "a" * 64
HEADER = env.build_header("0123456789abcdef0123456789abcdef", FP, "b" * 64)


def parts(**changes):
    values = dict(header_raw=HEADER, wrapped_key=bytes(384), nonce=bytes(12),
                  ciphertext=bytes(16), signature=bytes(384))
    values.update(changes)
    return RawEnvelope(**values)


def outer(**changes):
    fields = {name: base64.b64encode(part).decode() for name, part in
              zip(env._ENVELOPE_KEYS, parts())}
    fields.update(changes)
    return json.dumps(fields).encode()


def header_json(**changes):
    values = {"format": "SFILE", "version": 1, "suite": env.SUITE,
              "transfer_id": "0" * 32, "sender_sig_fp": FP, "recipient_enc_fp": FP}
    values.update(changes)
    return json.dumps(values).encode()




class FramingTests(unittest.TestCase):
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


class EnvelopeTests(unittest.TestCase):
    def test_round_trip_keeps_raw_header(self):
        parsed = env.parse_envelope(env.serialize_envelope(parts()))
        self.assertEqual(parsed, parts())

    def test_header_whitespace_is_not_reformatted(self):
        spaced = b'{ "format" : "SFILE", ' + HEADER[1:].replace(b'"format":"SFILE",', b"", 1)
        raw = parts(header_raw=spaced)
        self.assertEqual(env.parse_envelope(env.serialize_envelope(raw)).header_raw, spaced)

    @pytest.mark.case("R02")
    def test_outer_json_may_be_reformatted(self):
        reordered = json.dumps(dict(reversed(list(json.loads(outer()).items()))), indent=2)
        self.assertEqual(env.parse_envelope(reordered.encode()), parts())

    @pytest.mark.case("P01")
    def test_not_json(self):
        for bad in (b"%PDF-1.7", b"", b'{"a":', outer() + outer(), outer() + b"x",
                    b"[]", b"null", b'{"a":NaN}', b"\xff\xfe"):
            with self.subTest(bad=bad[:20]), self.assertRaises(EnvelopeError) as ctx:
                env.parse_envelope(bad)
            self.assertEqual(ctx.exception.code, "PARSE")

    @pytest.mark.case("P02")
    def test_wrong_fields(self):
        good = json.loads(outer())
        missing = {k: v for k, v in good.items() if k != "nonce_b64"}
        extra = dict(good, extra="x")
        duplicate = outer().replace(b"}", b',"nonce_b64":"AAAAAAAAAAAAAAAA"}')
        wrong_type = dict(good, nonce_b64=5)
        for bad in (json.dumps(missing).encode(), json.dumps(extra).encode(),
                    duplicate, json.dumps(wrong_type).encode()):
            with self.assertRaises(EnvelopeError):
                env.parse_envelope(bad)

    @pytest.mark.case("P03")
    def test_bad_base64(self):
        good = base64.b64encode(bytes(12)).decode()
        for bad in (good[:-1] + "!", good[:-2], good + "=", good[:4] + "\n" + good[4:],
                    "AAAAAAAAAAAAAAAB" if False else "AAAAAAAAAAAAAAB=" , "é" * 16):
            with self.subTest(bad=bad), self.assertRaises(EnvelopeError):
                env.parse_envelope(outer(nonce_b64=bad))

    @pytest.mark.case("P06")
    def test_block_lengths(self):
        for name in ("wrapped_key", "signature"):
            for size in (0, 383, 385):
                with self.subTest(name=name, size=size), self.assertRaises(EnvelopeError):
                    env.serialize_envelope(parts(**{name: bytes(size)}))
        for size in (0, 11, 13):
            with self.assertRaises(EnvelopeError):
                env.serialize_envelope(parts(nonce=bytes(size)))
        for size in (0, 15, env.MAX_CIPHERTEXT + 1):
            with self.assertRaises(EnvelopeError):
                env.serialize_envelope(parts(ciphertext=bytes(size)))
        env.serialize_envelope(parts(ciphertext=bytes(16)))
        env.serialize_envelope(parts(ciphertext=bytes(env.MAX_CIPHERTEXT)))

    @pytest.mark.case("P07")
    def test_outer_cap(self):
        padded = outer() + b" " * (env.MAX_ENVELOPE - len(outer()))
        self.assertEqual(len(padded), env.MAX_ENVELOPE)
        self.assertEqual(env.parse_envelope(padded), parts())
        with self.assertRaises(EnvelopeError):
            env.parse_envelope(padded + b" ")

    def test_oversized_field_rejected_before_decoding(self):
        with self.assertRaises(EnvelopeError):
            env.parse_envelope(outer(nonce_b64="A" * 1000))


class HeaderTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(env.parse_header(header_json())["version"], 1)

    @pytest.mark.case("P04")
    @pytest.mark.case("P05")
    def test_rejected(self):
        bad_headers = {
            "format": header_json(format="SFILE2"),
            "version2": header_json(version=2),
            "version bool": header_json(version=True),
            "version float": header_json(version=1.0),
            "suite": header_json(suite="OTHER"),
            "id short": header_json(transfer_id="0" * 31),
            "id upper": header_json(transfer_id="A" * 32),
            "id non-hex": header_json(transfer_id="g" * 32),
            "fp short": header_json(sender_sig_fp="a" * 63),
            "fp long": header_json(recipient_enc_fp="a" * 65),
            "extra": header_json(extra=1),
            "missing": json.dumps({"format": "SFILE"}).encode(),
            "duplicate": header_json().replace(b'"version": 1', b'"version": 1, "version": 1'),
            "not object": b"[]",
            "truncated": header_json()[:-3],
            "not json": b"%PDF",
        }
        for name, data in bad_headers.items():
            with self.subTest(name), self.assertRaises(EnvelopeError):
                env.parse_header(data)

    @pytest.mark.case("P05")
    def test_size_limit(self):
        padding = b" " * (env.MAX_HEADER - len(header_json()))
        self.assertEqual(len(header_json() + padding), env.MAX_HEADER)
        env.parse_header(header_json() + padding)
        with self.assertRaises(EnvelopeError):
            env.parse_header(header_json() + padding + b" ")




def frame_meta(metadata, raw=b""):
    return len(metadata).to_bytes(4, "big") + metadata + raw


class PayloadTests(unittest.TestCase):
    def test_round_trip(self):
        for name, raw in (("empty", b""), ("../thư mục/日本語.txt", bytes(range(256))),
                          ('quote"\\line\n', b"\0\xff")):
            with self.subTest(name=name):
                packed = build_payload(name, raw)
                self.assertEqual(parse_payload(packed), (name, raw))
                size = int.from_bytes(packed[:4], "big")
                self.assertEqual(packed[4:4 + size].decode("utf-8"),
                                 json.dumps({"filename": name},
                                 ensure_ascii=False, separators=(",", ":")))

    def test_size_boundaries(self):
        name = "a" * (MAX_METADATA - len(b'{"filename":""}'))
        raw = bytes(MAX_FILE)
        packed = build_payload(name, raw)
        self.assertEqual(len(packed), MAX_PAYLOAD)
        self.assertEqual(parse_payload(packed), (name, raw))
        for bad_name, bad_raw in ((name + "a", b""), ("é" * 2048, b""),
                                  ("x", raw + b"x")):
            with self.assertRaises(ValueError):
                build_payload(bad_name, bad_raw)
        with self.assertRaises(ValueError):
            parse_payload(frame_meta(b'{"filename":"x"}', raw + b"x"))
        with self.assertRaises(ValueError):
            parse_payload(packed + b"x")

    @pytest.mark.case("A11")
    def test_invalid_framing(self):
        for data in (b"", b"\0" * 3, bytes(4), b"\0\0\0\x10{}",
                     (MAX_METADATA + 1).to_bytes(4, "big") + bytes(4097),
                     b"\xff" * 4):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                parse_payload(data)

    @pytest.mark.case("A12")
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
                parse_payload(frame_meta(metadata))

    def test_invalid_input_types_and_names(self):
        for name in (None, 1, b"x", "", "a\0b", "\ud800"):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                build_payload(name, b"")
        for value in (None, "x", bytearray(b"x"), memoryview(b"x"), 1):
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                build_payload("x", value)
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                parse_payload(value)

    def test_payload_errors_carry_code(self):
        with self.assertRaises(EnvelopeError) as ctx:
            parse_payload(b"\0\0\0")
        self.assertEqual(ctx.exception.code, "PAYLOAD")


if __name__ == "__main__":
    unittest.main()
