"""Luồng gửi/nhận đi qua envelope và crypto_ops đúng thứ tự đặc tả, với hai cặp khóa.

(N, D) là khóa mã hóa của người nhận; (SIGN_N, SIGN_D) là khóa ký của người gửi.
Fixture lỗi ở đây do bộ test tạo và ký bằng khóa test, không mô phỏng kẻ giả chữ ký.
"""

import base64
import json
import unittest
from os import urandom

from secure_share.crypto_ops import (
    decrypt_payload, encrypt_payload, generate_key_nonce, sha256, sign_package,
    unwrap_key, verify_signature, wrap_key)
from secure_share.envelope import (
    RawEnvelope, build_aad, build_header, build_payload, build_signature_input,
    parse_envelope, parse_header, parse_payload, serialize_envelope)
from tests.rsa_fixtures import D, N, SIGN_D, SIGN_N


def send(raw_file, filename="báo cáo.txt"):
    """Luồng gửi chuẩn, trả về byte .sfile."""
    # Fingerprint thật là SHA-256 của DER SPKI (Nhật); test chỉ cần đúng 64 hex.
    sender_fp = sha256(SIGN_N.to_bytes(384, "big")).hex()
    recipient_fp = sha256(N.to_bytes(384, "big")).hex()
    header = build_header(urandom(16).hex(), sender_fp, recipient_fp)
    aes_key, nonce = generate_key_nonce()
    wrapped = wrap_key(aes_key, N)
    aad = build_aad(header, wrapped)
    ciphertext = encrypt_payload(build_payload(filename, raw_file), aes_key, nonce, aad)
    signature = sign_package(build_signature_input(header, wrapped, nonce, ciphertext),
                             SIGN_N, SIGN_D)
    return serialize_envelope(RawEnvelope(header, wrapped, nonce, ciphertext, signature))


def receive(blob):
    """Luồng nhận chuẩn: parse -> header -> PSS -> OAEP -> GCM -> payload."""
    parts = parse_envelope(blob)
    parse_header(parts.header_raw)
    message = build_signature_input(
        parts.header_raw, parts.wrapped_key, parts.nonce, parts.ciphertext)
    if not verify_signature(message, parts.signature, SIGN_N):
        raise ValueError("SIGNATURE")
    aes_key = unwrap_key(parts.wrapped_key, N, D)
    aad = build_aad(parts.header_raw, parts.wrapped_key)
    return parse_payload(decrypt_payload(parts.ciphertext, aes_key, parts.nonce, aad))


class RoundTripTests(unittest.TestCase):
    def test_send_receive(self):
        for raw in (b"", "Nội dung tệp của Quang".encode(), bytes(range(256)), urandom(5000)):
            with self.subTest(size=len(raw)):
                self.assertEqual(receive(send(raw)), ("báo cáo.txt", raw))

    def test_two_key_pairs_are_different(self):
        self.assertNotEqual((N, D), (SIGN_N, SIGN_D))
        self.assertFalse(verify_signature(b"m", sign_package(b"m", SIGN_N, SIGN_D), N))

    def test_same_file_sent_twice_gives_different_packages(self):
        first, second = send(b"cung mot tep"), send(b"cung mot tep")
        self.assertNotEqual(first, second)
        parts = parse_envelope(first), parse_envelope(second)
        for index in range(1, 4):  # W, N, C
            self.assertNotEqual(parts[0][index], parts[1][index])
        self.assertEqual(receive(first), receive(second))

    def test_tampering_any_part_breaks_signature(self):
        parts = parse_envelope(send(b"du lieu"))
        for index, name in enumerate(RawEnvelope._fields):
            with self.subTest(part=name):
                changed = list(parts)
                changed[index] = bytes([changed[index][0] ^ 1]) + changed[index][1:]
                message = build_signature_input(*changed[:4])
                self.assertFalse(verify_signature(message, changed[4], SIGN_N))

    def test_outer_json_reformatting_stays_valid(self):
        blob = send(b"abc")
        pretty = json.dumps(dict(reversed(list(json.loads(blob).items()))), indent=4)
        self.assertNotEqual(pretty.encode(), blob)
        self.assertEqual(receive(pretty.encode()), ("báo cáo.txt", b"abc"))

    def test_wrong_recipient_cannot_open(self):
        parts = parse_envelope(send(b"bi mat"))
        with self.assertRaises(ValueError):
            unwrap_key(parts.wrapped_key, SIGN_N, SIGN_D)


class SignedBadFixtureTests(unittest.TestCase):
    def test_signed_bad_data_reaches_expected_layer(self):
        # Người kiểm thử ký fixture bằng khóa test; không mô phỏng khả năng giả chữ ký.
        header = b"test header"
        key, nonce = generate_key_nonce()
        wrapped = wrap_key(key, N)
        payload = build_payload("test.bin", b"file bytes")
        aad = build_aad(header, wrapped)
        encrypted = encrypt_payload(payload, key, nonce, aad)

        bad_wrapped = bytes(384)
        message = build_signature_input(header, bad_wrapped, nonce, encrypted)
        self.assertTrue(verify_signature(message, sign_package(message, SIGN_N, SIGN_D), SIGN_N))
        with self.assertRaises(ValueError):
            unwrap_key(bad_wrapped, N, D)

        for bad_encrypted in (
            encrypted[:-1] + bytes([encrypted[-1] ^ 1]),
            encrypt_payload(payload, key, nonce, b"wrong AAD"),
        ):
            message = build_signature_input(header, wrapped, nonce, bad_encrypted)
            self.assertTrue(verify_signature(message, sign_package(message, SIGN_N, SIGN_D), SIGN_N))
            recovered_key = unwrap_key(wrapped, N, D)
            with self.assertRaises(ValueError):
                decrypt_payload(bad_encrypted, recovered_key, nonce, aad)

        for bad_payload in (b"\0\0\x10\x01{}", b'\0\0\0\x0f{"filename":42}'):
            bad_encrypted = encrypt_payload(bad_payload, key, nonce, aad)
            message = build_signature_input(header, wrapped, nonce, bad_encrypted)
            self.assertTrue(verify_signature(message, sign_package(message, SIGN_N, SIGN_D), SIGN_N))
            recovered = decrypt_payload(bad_encrypted, unwrap_key(wrapped, N, D), nonce, aad)
            with self.assertRaises(ValueError):
                parse_payload(recovered)


if __name__ == "__main__":
    unittest.main()
