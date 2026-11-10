"""Primitive mật mã tự cài bằng Python: SHA-256, MGF1, AES-256-GCM, RSA-OAEP, RSA-PSS.

Chỉ nhận và trả byte/số nguyên; không đọc danh bạ, không mở hộp thoại, không
lưu tệp và không import envelope. Phục vụ học tập: Python không bảo đảm thời
gian thực thi hằng định, mã chưa được kiểm toán.
"""

from math import gcd, isqrt
from os import urandom

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import AES_KEY_BYTES, NONCE_BYTES, OAEP_LABEL, PSS_SALT_BYTES, RSA_KEY_BITS, RSA_PUBLIC_EXPONENT

from .errors import ErrorCode, ShareError


# ======================================================================
# SHA-256 và MGF1
# ======================================================================

_MASK = 0xFFFFFFFF


def _first_primes(count: int) -> list:
    primes, candidate = [], 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def _icbrt(n: int) -> int:
    """Căn bậc ba nguyên floor(n^(1/3)) bằng Newton, bắt đầu từ cận trên."""
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


# H0[i] = floor(frac(sqrt(p_i)) * 2^32), p_i là 8 số nguyên tố đầu tiên.
# K[t]  = floor(frac(cbrt(p_t)) * 2^32), p_t là 64 số nguyên tố đầu tiên.
# floor(sqrt(p) * 2^32) = isqrt(p * 2^64); 32 bit thấp là phần thập phân.
_INITIAL = tuple(isqrt(p << 64) & _MASK for p in _first_primes(8))
_K = tuple(_icbrt(p << 96) & _MASK for p in _first_primes(64))


def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK


def sha256(data: bytes) -> bytes:
    """Trả về giá trị băm SHA-256 gồm 32 byte."""
    if not isinstance(data, bytes):
        raise TypeError("data phải là bytes")
    bit_length = len(data) * 8
    if bit_length >= 1 << 64:
        raise ValueError("Dữ liệu quá dài cho SHA-256")
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64)
    padded += bit_length.to_bytes(8, "big")
    state = list(_INITIAL)

    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            x, y = words[i - 15], words[i - 2]
            s0 = _rotate_right(x, 7) ^ _rotate_right(x, 18) ^ (x >> 3)
            s1 = _rotate_right(y, 17) ^ _rotate_right(y, 19) ^ (y >> 10)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & _MASK)

        a, b, c, d, e, f, g, h = state
        for constant, word in zip(_K, words):
            sigma1 = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choose = (e & f) ^ (~e & g)
            temp1 = (h + sigma1 + choose + constant + word) & _MASK
            sigma0 = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sigma0 + majority) & _MASK
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & _MASK, c, b, a, (temp1 + temp2) & _MASK
            )
        state = [(old + new) & _MASK for old, new in zip(state, (a, b, c, d, e, f, g, h))]

    return b"".join(word.to_bytes(4, "big") for word in state)


def mgf1(seed: bytes, length: int) -> bytes:
    """Sinh mặt nạ MGF1 dùng SHA-256 và bộ đếm 4 byte."""
    if not isinstance(seed, bytes):
        raise TypeError("seed phải là bytes")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length phải là số nguyên")
    if not 0 <= length <= (1 << 32) * 32:
        raise ValueError("length phải nằm trong [0, 2**32 * 32]")
    mask = bytearray()
    for counter in range((length + 31) // 32):
        mask.extend(sha256(seed + counter.to_bytes(4, "big")))
    return bytes(mask[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR hai chuỗi byte có cùng độ dài."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("Hai toán hạng phải là bytes")
    if len(left) != len(right):
        raise ValueError("Hai toán hạng phải có cùng độ dài")
    return bytes(a ^ b for a, b in zip(left, right))


# ======================================================================
# AES-256-GCM
# ======================================================================

def generate_key_nonce() -> tuple[bytes, bytes]:
    """Tạo khóa AES mới 32 byte và nonce mới 12 byte cho mỗi lần gửi."""
    return urandom(32), urandom(12)




def _xtime(value):
    return ((value << 1) ^ (0x11B if value & 0x80 else 0)) & 255


def _gf_multiply(a, b):
    """Nhân trong GF(2^8) với đa thức x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _gf_inverse(a):
    """a^254 = a^-1 trong GF(2^8); quy ước nghịch đảo của 0 là 0."""
    result, base, exponent = 1, a, 254
    while exponent:
        if exponent & 1:
            result = _gf_multiply(result, base)
        base = _gf_multiply(base, base)
        exponent >>= 1
    return result if a else 0


def _rotate_left8(value, count):
    return ((value << count) | (value >> (8 - count))) & 255


def _build_sbox():
    """S(a) = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63, b = a^-1."""
    box = []
    for a in range(256):
        b = _gf_inverse(a)
        box.append(b ^ _rotate_left8(b, 1) ^ _rotate_left8(b, 2)
                   ^ _rotate_left8(b, 3) ^ _rotate_left8(b, 4) ^ 0x63)
    return bytes(box)


_SBOX = _build_sbox()


def _expand_key(key):
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        temp = words[i - 1][:]
        if i % 8 == 0:
            temp = [_SBOX[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            temp = [_SBOX[x] for x in temp]
        words.append([a ^ b for a, b in zip(words[i - 8], temp)])
    return [sum(words[i:i + 4], []) for i in range(0, 60, 4)]


def _encrypt_block(block, round_keys):
    state = [a ^ b for a, b in zip(block, round_keys[0])]
    for round_number in range(1, 15):
        state = [_SBOX[x] for x in state]
        state = [state[4 * ((column + row) % 4) + row]
                 for column in range(4) for row in range(4)]
        if round_number != 14:
            for offset in range(0, 16, 4):
                a, b, c, d = state[offset:offset + 4]
                total = a ^ b ^ c ^ d
                state[offset:offset + 4] = [
                    a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c),
                    c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a)]
        state = [a ^ b for a, b in zip(state, round_keys[round_number])]
    return bytes(state)


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Mã hóa một khối 16 byte bằng khóa AES-256."""
    if not isinstance(block, bytes) or len(block) != 16:
        raise ValueError('Khối AES phải là bytes dài 16 byte.')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Khóa AES-256 phải là bytes dài 32 byte.')
    return _encrypt_block(block, _expand_key(key))


def _multiply(x, y):
    result = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= y
        y = (y >> 1) ^ (0xE1000000000000000000000000000000 if y & 1 else 0)
    return result


def _ghash(h, aad, ciphertext):
    value = 0
    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16].ljust(16, b'\0')
            value = _multiply(value ^ int.from_bytes(block, 'big'), h)
    lengths = (len(aad) * 8 << 64) | (len(ciphertext) * 8)
    return _multiply(value ^ lengths, h).to_bytes(16, 'big')


def _validate(data, key, nonce, aad):
    if not isinstance(data, bytes) or not isinstance(aad, bytes):
        raise TypeError('Dữ liệu và AAD phải là bytes.')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Khóa AES-256 phải là bytes dài 32 byte.')
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError('Nonce GCM phải là bytes dài 12 byte.')
    if len(aad) > (1 << 61) - 1:
        raise ValueError('AAD vượt giới hạn GCM.')


def _check_length(length):
    if length > (1 << 36) - 32:
        raise ValueError('Dữ liệu vượt giới hạn bộ đếm GCM.')


def _ctr(data, nonce, round_keys):
    output = bytearray()
    for offset in range(0, len(data), 16):
        counter = offset // 16 + 2
        stream = _encrypt_block(nonce + counter.to_bytes(4, 'big'), round_keys)
        output.extend(a ^ b for a, b in zip(data[offset:offset + 16], stream))
    return bytes(output)


def _tag(ciphertext, nonce, aad, round_keys):
    h = int.from_bytes(_encrypt_block(bytes(16), round_keys), 'big')
    mask = _encrypt_block(nonce + b'\0\0\0\1', round_keys)
    return bytes(a ^ b for a, b in zip(mask, _ghash(h, aad, ciphertext)))


def encrypt_payload(payload: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> bytes:
    """Trả về bản mã nối với thẻ xác thực 16 byte."""
    _validate(payload, key, nonce, aad)
    _check_length(len(payload))
    round_keys = _expand_key(key)
    ciphertext = _ctr(payload, nonce, round_keys)
    return ciphertext + _tag(ciphertext, nonce, aad, round_keys)


def decrypt_payload(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> bytes:
    """Xác thực toàn bộ bản mã trước khi giải mã; thẻ sai gây ValueError."""
    _validate(ciphertext, key, nonce, aad)
    if len(ciphertext) < 16:
        raise ValueError('Bản mã thiếu thẻ xác thực GCM.')
    _check_length(len(ciphertext) - 16)
    body, supplied_tag = ciphertext[:-16], ciphertext[-16:]
    round_keys = _expand_key(key)
    expected_tag = _tag(body, nonce, aad, round_keys)
    difference = 0
    for actual, expected in zip(supplied_tag, expected_tag):
        difference |= actual ^ expected
    if difference:
        raise ValueError('Thẻ xác thực GCM không hợp lệ.')
    return _ctr(body, nonce, round_keys)


def _self_test():
    """Kiểm tra vector AES-256 và GCM chuẩn cùng phát hiện sửa đổi."""
    key = bytes(range(32))
    block = bytes.fromhex('00112233445566778899aabbccddeeff')
    assert encrypt_block(block, key).hex() == '8ea2b7ca516745bfeafc49904b496089'
    key, nonce = bytes(32), bytes(12)
    assert encrypt_payload(b'', key, nonce).hex() == '530f8afbc74536b9a963b4f1c4cb738b'
    sealed = encrypt_payload(bytes(16), key, nonce)
    assert sealed.hex() == ('cea7403d4d606b6e074ec5d3baf39d18'
                            'd0d1c8a799996bf0265b98b5d48ab919')
    assert decrypt_payload(sealed, key, nonce) == bytes(16)
    try:
        decrypt_payload(sealed[:-1] + bytes([sealed[-1] ^ 1]), key, nonce)
    except ValueError:
        pass
    else:
        raise AssertionError('Không phát hiện thẻ bị sửa đổi.')




# ======================================================================
# RSA-OAEP
# ======================================================================

def check_key(n: int, exponent: int) -> None:
    """Kiểm tra tham số theo profile RSA-3072 của dự án."""
    if type(n) is not int or n.bit_length() != 3072 or n % 2 == 0:
        raise ValueError("Modulus RSA phải là số lẻ 3072 bit")
    if type(exponent) is not int or not 1 < exponent < n or exponent % 2 == 0:
        raise ValueError("Số mũ RSA không hợp lệ")


def wrap_key(aes_key: bytes, n: int, e: int = 65537, seed: bytes = None) -> bytes:
    """Bọc khóa AES 32 byte bằng public key (n, e), OAEP label rỗng.

    seed chỉ dùng cho test lặp lại được; mặc định lấy 32 byte từ urandom.
    """
    check_key(n, e)
    if e != 65537:
        raise ValueError("Public exponent phải là 65537")
    if not isinstance(aes_key, bytes) or len(aes_key) != 32:
        raise ValueError("Khóa AES phải dài 32 byte")

    # EM = 0x00 || maskedSeed || maskedDB (tổng cộng 384 byte).
    padding = bytes(384 - len(aes_key) - 2 * 32 - 2)
    data_block = sha256(b"") + padding + b"\x01" + aes_key
    if seed is None:
        seed = urandom(32)
    elif not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("Seed OAEP phải dài 32 byte")
    masked_data = xor_bytes(data_block, mgf1(seed, len(data_block)))
    masked_seed = xor_bytes(seed, mgf1(masked_data, 32))
    encoded = b"\x00" + masked_seed + masked_data
    encrypted = pow(int.from_bytes(encoded, "big"), e, n)
    return encrypted.to_bytes(384, "big")


class AESKeyLengthError(ValueError):
    pass


def unwrap_key(wrapped_key: bytes, n: int, d: int) -> bytes:
    """Mở bọc bằng private key (n, d); mọi OAEP lỗi đều bị từ chối."""
    check_key(n, d)
    if not isinstance(wrapped_key, bytes) or len(wrapped_key) != 384:
        raise ValueError("Khóa bọc RSA không hợp lệ")
    encrypted = int.from_bytes(wrapped_key, "big")
    if encrypted >= n:
        raise ValueError("Khóa bọc RSA không hợp lệ")
    encoded = pow(encrypted, d, n).to_bytes(384, "big")
    masked_seed, masked_data = encoded[1:33], encoded[33:]
    seed = xor_bytes(masked_seed, mgf1(masked_data, 32))
    data_block = xor_bytes(masked_data, mgf1(seed, len(masked_data)))

    if encoded[0] != 0 or data_block[:32] != sha256(b""):
        raise ValueError("Khóa bọc RSA không hợp lệ")
    padding_and_key = data_block[32:]
    separator = padding_and_key.find(b"\x01")
    if separator < 0 or any(padding_and_key[:separator]):
        raise ValueError("Khóa bọc RSA không hợp lệ")
    key = padding_and_key[separator + 1:]
    if len(key) != 32:
        raise AESKeyLengthError("AES key must be 32 bytes")
    return key


# ======================================================================
# RSA-PSS
# ======================================================================

def sign_package(message: bytes, n: int, d: int) -> bytes:
    """Ký đúng chuỗi byte message bằng private key ký (n, d)."""
    check_key(n, d)
    if not isinstance(message, bytes):
        raise TypeError("Dữ liệu ký phải là bytes")
    salt = urandom(32)
    digest = sha256(bytes(8) + sha256(message) + salt)
    data_block = bytes(318) + b"\x01" + salt
    masked_data = bytearray(xor_bytes(data_block, mgf1(digest, 351)))
    # emBits = modBits - 1 = 3071: bit đầu tiên phải bằng 0.
    masked_data[0] &= 0x7F
    encoded = bytes(masked_data) + digest + b"\xbc"
    signature = pow(int.from_bytes(encoded, "big"), d, n)
    return signature.to_bytes(384, "big")


def verify_signature(message: bytes, signature: bytes, n: int, e: int = 65537) -> bool:
    """Trả False khi chữ ký sai; khóa sai profile gây ValueError."""
    check_key(n, e)
    if not isinstance(message, bytes):
        raise TypeError("Dữ liệu ký phải là bytes")
    if e != 65537:
        raise ValueError("Public exponent phải là 65537")
    if not isinstance(signature, bytes) or len(signature) != 384:
        return False
    number = int.from_bytes(signature, "big")
    if number >= n:
        return False
    encoded = pow(number, e, n).to_bytes(384, "big")
    if encoded[-1] != 0xBC or encoded[0] & 0x80:
        return False
    masked_data, digest = encoded[:351], encoded[351:383]
    data_block = bytearray(xor_bytes(masked_data, mgf1(digest, 351)))
    data_block[0] &= 0x7F
    if data_block[:319] != bytes(318) + b"\x01":
        return False
    salt = bytes(data_block[-32:])
    return digest == sha256(bytes(8) + sha256(message) + salt)


# ======================================================================
# Số học RSA: Euclid mở rộng, Miller-Rabin, sinh số nguyên tố và khóa
# ======================================================================

_SMALL_PRIMES = tuple(_first_primes(303))  # các số nguyên tố dưới 2000


def egcd(a: int, b: int) -> tuple:
    """Trả (g, x, y) với g = gcd(a, b) = a*x + b*y."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, n: int) -> int:
    """Nghịch đảo a^-1 mod n; ValueError khi gcd(a, n) != 1."""
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError("Không có nghịch đảo modulo")
    return x % n


def _random_below(limit: int) -> int:
    """Số nguyên đều trong [0, limit) bằng lấy mẫu loại bỏ."""
    bits = limit.bit_length()
    while True:
        value = int.from_bytes(urandom((bits + 7) // 8), "big") & ((1 << bits) - 1)
        if value < limit:
            return value


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin: n-1 = 2^s * d, d lẻ; kiểm a^d = 1 hoặc a^(2^r d) = -1."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + _random_below(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, e: int = 65537) -> int:
    """Số nguyên tố đúng `bits` bit, với p-1 nguyên tố cùng nhau với e."""
    while True:
        candidate = int.from_bytes(urandom((bits + 7) // 8), "big") & ((1 << bits) - 1)
        candidate |= (3 << (bits - 2)) | 1  # hai bit cao để p*q đủ bit
        if gcd(candidate - 1, e) == 1 and is_probable_prime(candidate):
            return candidate


def generate_rsa_key(bits: int = 3072, e: int = 65537) -> tuple:
    """Trả (n, e, d, p, q); n đúng `bits` bit, d = e^-1 mod lcm(p-1, q-1)."""
    while True:
        p, q = generate_prime(bits // 2, e), generate_prime(bits // 2, e)
        if p == q or (p * q).bit_length() != bits:
            continue
        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        return p * q, e, modinv(e, lam), p, q


def _public_key(key):
    if (
        not isinstance(key, rsa.RSAPublicKey)
        or key.key_size != RSA_KEY_BITS
        or key.public_numbers().e != RSA_PUBLIC_EXPONENT
    ):
        raise ShareError(ErrorCode.PROFILE_INVALID)
    return key


def _private_key(key):
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ShareError(ErrorCode.PROFILE_INVALID)
    _public_key(key.public_key())
    return key


_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_BYTES)


def _threshold_oaep(label):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def wrap_threshold_secret(secret, public_key, label):
    return _public_key(public_key).encrypt(secret, _threshold_oaep(label))


def unwrap_threshold_secret(wrapped, private_key, label):
    try:
        return _private_key(private_key).decrypt(wrapped, _threshold_oaep(label))
    except (ValueError, TypeError):
        raise ShareError(ErrorCode.INVALID_SHARE) from None


class CryptoOps:
    """Library backend for the desktop app. SFILE v1 packets stay compatible."""

    def generate_aes_key(self):
        return AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)

    def generate_nonce(self):
        return urandom(NONCE_BYTES)

    def wrap_key(self, aes_key, public_key):
        if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_BYTES:
            raise ShareError(ErrorCode.AES_KEY_LENGTH_INVALID)
        return _public_key(public_key).encrypt(aes_key, _OAEP)

    def unwrap_key(self, wrapped_key, private_key):
        try:
            aes_key = _private_key(private_key).decrypt(wrapped_key, _OAEP)
        except (ValueError, TypeError):
            raise ShareError(ErrorCode.UNWRAP_FAILED) from None
        if len(aes_key) != AES_KEY_BYTES:
            raise ShareError(ErrorCode.AES_KEY_LENGTH_INVALID)
        return aes_key

    @staticmethod
    def _check_aead_inputs(key, nonce):
        if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES or not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise ShareError(ErrorCode.INVALID_LENGTH)

    def encrypt_payload(self, key, nonce, payload, aad):
        self._check_aead_inputs(key, nonce)
        try:
            return AESGCM(key).encrypt(nonce, payload, aad)
        except (ValueError, TypeError):
            raise ShareError(ErrorCode.INVALID_LENGTH) from None

    def decrypt_payload(self, key, nonce, ciphertext, aad):
        self._check_aead_inputs(key, nonce)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, TypeError):
            raise ShareError(ErrorCode.GCM_AUTH_FAILED) from None

    def sign_package(self, message, private_key):
        try:
            return _private_key(private_key).sign(message, _PSS, hashes.SHA256())
        except (ValueError, TypeError):
            raise ShareError(ErrorCode.INVALID_REQUEST) from None

    def verify_signature(self, signature, message, public_key):
        try:
            _public_key(public_key).verify(signature, message, _PSS, hashes.SHA256())
        except (InvalidSignature, ValueError, TypeError):
            raise ShareError(ErrorCode.SIGNATURE_INVALID) from None
