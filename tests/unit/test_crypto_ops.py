"""Kiểm thử primitive mật mã tự cài. Chạy: python -m pytest tests/unit hoặc python -m unittest discover -s tests -t ."""

import unittest

from secure_share.crypto_ops import (
    _INITIAL, _K, _SBOX, _icbrt, _self_test, decrypt_payload, egcd,
    encrypt_payload, generate_key_nonce, generate_rsa_key, is_probable_prime,
    mgf1, modinv, sha256, sign_package, unwrap_key, verify_signature, wrap_key,
    xor_bytes)
from tests.rsa_fixtures import D, N, SIGN_D, SIGN_N

STANDARD_SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')

STANDARD_H0 = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

STANDARD_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)


class CryptoTests(unittest.TestCase):
    def test_sha256_vectors(self):
        self.assertEqual(sha256(b"").hex(),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(sha256(b"abc").hex(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(sha256(b"a" * 56).hex(),
                         "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")
        self.assertEqual(mgf1(b"seed", 33),
                         sha256(b"seed\0\0\0\0") + sha256(b"seed\0\0\0\1")[:1])
        with self.assertRaises(ValueError):
            mgf1(b"seed", -1)

    def test_aes_standard_vectors(self):
        _self_test()

    def test_gcm_rejects_changes(self):
        key, nonce, aad = bytes(range(32)), bytes(range(12)), b"header"
        for size in (0, 1, 15, 16, 17, 128):
            with self.subTest(size=size):
                message = bytes(size)
                encrypted = encrypt_payload(message, key, nonce, aad)
                self.assertEqual(decrypt_payload(encrypted, key, nonce, aad), message)
                for wrong_key, wrong_nonce, wrong_aad, wrong_data in (
                    (bytes(32), nonce, aad, encrypted),
                    (key, bytes(12), aad, encrypted),
                    (key, nonce, b"changed", encrypted),
                    (key, nonce, aad, bytes([encrypted[0] ^ 1]) + encrypted[1:]),
                ):
                    with self.assertRaises(ValueError):
                        decrypt_payload(wrong_data, wrong_key, wrong_nonce, wrong_aad)

    def test_oaep(self):
        key = bytes(range(32))
        encrypted = wrap_key(key, N)
        self.assertEqual(len(encrypted), 384)
        self.assertEqual(unwrap_key(encrypted, N, D), key)
        self.assertNotEqual(wrap_key(key, N), encrypted)
        for bad in (b"", bytes(384), N.to_bytes(384, "big"), encrypted[:-1]):
            with self.assertRaises(ValueError):
                unwrap_key(bad, N, D)
        with self.assertRaises(ValueError):
            wrap_key(bytes(31), N)

    def test_pss(self):
        message = b"SFILE1-SIGN: test bytes"
        signature = sign_package(message, SIGN_N, SIGN_D)
        self.assertEqual(len(signature), 384)
        self.assertTrue(verify_signature(message, signature, SIGN_N))
        self.assertNotEqual(sign_package(message, SIGN_N, SIGN_D), signature)
        self.assertFalse(verify_signature(message + b"!", signature, SIGN_N))
        self.assertFalse(verify_signature(message, signature, N))
        for bad in (b"", bytes(384), SIGN_N.to_bytes(384, "big"), signature[:-1]):
            self.assertFalse(verify_signature(message, bad, SIGN_N))

    def test_key_nonce_generation(self):
        first, second = generate_key_nonce(), generate_key_nonce()
        self.assertEqual(tuple(map(len, first)), (32, 12))
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1], second[1])

    def test_oaep_rejects_wrong_key_length_after_decode(self):
        # Fixture OAEP hợp lệ nhưng chứa khóa AES sai độ dài, không phải attacker giả chữ ký.
        for length in (0, 16, 31, 33):
            with self.subTest(length=length):
                secret, seed = bytes(length), bytes(32)
                data = sha256(b"") + bytes(384 - length - 66) + b"\x01" + secret
                masked_data = xor_bytes(data, mgf1(seed, len(data)))
                encoded = b"\0" + xor_bytes(seed, mgf1(masked_data, 32)) + masked_data
                wrapped = pow(int.from_bytes(encoded, "big"), 65537, N).to_bytes(384, "big")
                with self.assertRaises(ValueError):
                    unwrap_key(wrapped, N, D)

    def test_wrong_recipient_key_cannot_unwrap(self):
        with self.assertRaises(ValueError):
            unwrap_key(wrap_key(bytes(32), N), SIGN_N, SIGN_D)

    def test_pss_rejects_wrong_salt_length(self):
        for salt_length in (0, 31, 33):
            message, salt = b"test", bytes(salt_length)
            digest = sha256(bytes(8) + sha256(message) + salt)
            data = bytes(350 - salt_length) + b"\x01" + salt
            masked = bytearray(xor_bytes(data, mgf1(digest, 351)))
            masked[0] &= 0x7f
            encoded = bytes(masked) + digest + b"\xbc"
            signature = pow(int.from_bytes(encoded, "big"), SIGN_D, SIGN_N).to_bytes(384, "big")
            self.assertFalse(verify_signature(message, signature, SIGN_N))

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            wrap_key(bytes(32), N, 3)
        with self.assertRaises(ValueError):
            sign_package(b"test", 17, 3)
        with self.assertRaises(ValueError):
            encrypt_payload(b"", bytes(31), bytes(12))
        with self.assertRaises(ValueError):
            encrypt_payload(b"", bytes(32), bytes(11))
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(15), bytes(32), bytes(12))
        with self.assertRaises(TypeError):
            sign_package("not bytes", SIGN_N, SIGN_D)
        with self.assertRaises(TypeError):
            verify_signature("not bytes", bytes(384), SIGN_N)

    def test_oaep_seed_is_reproducible_and_checked(self):
        key, seed = bytes(range(32)), bytes(range(32))
        self.assertEqual(wrap_key(key, N, seed=seed), wrap_key(key, N, seed=seed))
        self.assertEqual(unwrap_key(wrap_key(key, N, seed=seed), N, D), key)
        with self.assertRaises(ValueError):
            wrap_key(key, N, seed=bytes(31))


class GeneratedConstantTests(unittest.TestCase):
    """Hằng số SHA-256 và S-box AES do code sinh bằng toán, so với bảng chuẩn."""

    def test_sbox_matches_standard(self):
        self.assertEqual(_SBOX, STANDARD_SBOX)
        self.assertEqual(sorted(_SBOX), list(range(256)))

    def test_sha256_constants_match_standard(self):
        self.assertEqual(_INITIAL, STANDARD_H0)
        self.assertEqual(_K, STANDARD_K)

    def test_integer_cube_root(self):
        for value in (0, 1, 7, 8, 26, 27, 28, 10 ** 30, 2 ** 100 - 1):
            root = _icbrt(value)
            self.assertLessEqual(root ** 3, value)
            self.assertGreater((root + 1) ** 3, value)


class NumberTheoryTests(unittest.TestCase):
    def test_extended_euclid_and_inverse(self):
        g, x, y = egcd(240, 46)
        self.assertEqual((g, 240 * x + 46 * y), (2, 2))
        self.assertEqual(modinv(3, 11), 4)
        with self.assertRaises(ValueError):
            modinv(6, 9)

    def test_miller_rabin(self):
        for prime in (2, 3, 97, 7919, 2 ** 127 - 1):
            self.assertTrue(is_probable_prime(prime), prime)
        # 561 và 41041 là số Carmichael: hợp số nhưng qua phép thử Fermat.
        for composite in (0, 1, 4, 561, 41041, 7919 * 7907, (2 ** 61 - 1) * (2 ** 89 - 1)):
            self.assertFalse(is_probable_prime(composite), composite)

    def test_generated_key_round_trip(self):
        n, e, d, p, q = generate_rsa_key(512)
        self.assertEqual((n.bit_length(), n), (512, p * q))
        self.assertEqual(pow(pow(0xC0FFEE, e, n), d, n), 0xC0FFEE)


if __name__ == "__main__":
    unittest.main()
