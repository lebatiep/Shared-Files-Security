"""RSA key encoding and password protection for Shared-Files-Security profiles."""

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from math import lcm
from os import urandom
from secrets import compare_digest
from textwrap import wrap

from . import crypto_ops
from .config import RSA_KEY_BITS, RSA_PUBLIC_EXPONENT


# DER OID value octets for rsaEncryption, PBES2, PBKDF2, hmacWithSHA256 and aes256-CBC.
_RSA = bytes.fromhex('2a864886f70d010101')
_PBES2 = bytes.fromhex('2a864886f70d01050d')
_PBKDF2 = bytes.fromhex('2a864886f70d01050c')
_HMAC_SHA256 = bytes.fromhex('2a864886f70d0209')
_AES256_CBC = bytes.fromhex('60864801650304012a')
_NULL = b'\x05\x00'
_BLOCK_BYTES = 16
# Keep the profile parameters emitted by the previous application.
_ITERATIONS = 2048
_MAX_ITERATIONS = 100_000
_PUBLIC_LABEL = 'PUBLIC KEY'
_PRIVATE_LABEL = 'ENCRYPTED PRIVATE KEY'


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def key_size(self):
        return self.n.bit_length()

    def public_numbers(self):
        return self


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int = field(repr=False)
    p: int = field(repr=False)
    q: int = field(repr=False)

    @property
    def key_size(self):
        return self.n.bit_length()

    def public_key(self):
        return RSAPublicKey(self.n, self.e)

    def private_numbers(self):
        return self


def _der(tag, value):
    length = len(value)
    if length < 128:
        return bytes((tag, length)) + value
    size = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes((tag, 0x80 | len(size))) + size + value


def _sequence(*fields):
    return _der(0x30, b''.join(fields))


def _integer(value):
    return _der(0x02, value.to_bytes((value.bit_length() + 8) // 8, 'big'))


def _algorithm(oid, params):
    return _sequence(_der(0x06, oid), params)


class _DERReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def peek(self):
        return self.data[self.offset] if self.offset < len(self.data) else None

    def read(self, tag):
        if self.peek() != tag or self.offset + 2 > len(self.data):
            raise ValueError('Invalid DER tag')
        length = self.data[self.offset + 1]
        start = self.offset + 2
        if length >= 128:
            count = length & 0x7f
            if not 1 <= count <= 4 or start + count > len(self.data) or self.data[start] == 0:
                raise ValueError('Invalid DER length')
            length = int.from_bytes(self.data[start:start + count], 'big')
            if length < 128:
                raise ValueError('Noncanonical DER length')
            start += count
        end = start + length
        if end > len(self.data):
            raise ValueError('Truncated DER value')
        self.offset = end
        return self.data[start:end]

    def sequence(self):
        return _DERReader(self.read(0x30))

    def integer(self):
        value = self.read(0x02)
        if not value or value[0] & 0x80 or (len(value) > 1 and value[0] == 0 and value[1] < 0x80):
            raise ValueError('Invalid unsigned DER integer')
        return int.from_bytes(value, 'big')

    def algorithm(self, oid):
        algorithm = self.sequence()
        if algorithm.read(0x06) != oid:
            raise ValueError('Unsupported key algorithm')
        return algorithm

    def optional_null(self):
        if self.peek() == 0x05 and self.read(0x05):
            raise ValueError('Invalid DER NULL')
        self.finish()

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError('Trailing DER data')


def _root(data):
    reader = _DERReader(data)
    sequence = reader.sequence()
    reader.finish()
    return sequence


def _pem(label, data):
    lines = '\n'.join(wrap(b64encode(data).decode('ascii'), 64))
    return f'-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n'


def _read_pem(pem, label):
    if not isinstance(pem, str) or len(pem) > 8192:
        raise ValueError('Invalid PEM')
    lines = pem.replace('\r\n', '\n').removesuffix('\n').split('\n')
    if len(lines) < 3 or lines[0] != f'-----BEGIN {label}-----' or lines[-1] != f'-----END {label}-----':
        raise ValueError('Invalid PEM markers')
    return b64decode(''.join(lines[1:-1]), validate=True)


def public_der(key):
    numbers = key.public_numbers()
    pkcs1 = _sequence(_integer(numbers.n), _integer(numbers.e))
    return _sequence(_algorithm(_RSA, _NULL), _der(0x03, b'\x00' + pkcs1))


def public_pem(key):
    return _pem(_PUBLIC_LABEL, public_der(key))


def load_public(pem):
    spki = _root(_read_pem(pem, _PUBLIC_LABEL))
    spki.algorithm(_RSA).optional_null()
    key = spki.read(0x03)
    spki.finish()
    if not key or key[0] != 0:
        raise ValueError('Invalid RSA public key bit string')
    pkcs1 = _root(key[1:])
    public = RSAPublicKey(pkcs1.integer(), pkcs1.integer())
    pkcs1.finish()
    if public.key_size != RSA_KEY_BITS or public.e != RSA_PUBLIC_EXPONENT or public.n % 2 == 0:
        raise ValueError('Invalid RSA public key parameters')
    return public


def _private_der(key):
    pkcs1 = _sequence(*map(_integer, (
        0, key.n, key.e, key.d, key.p, key.q,
        key.d % (key.p - 1), key.d % (key.q - 1), pow(key.q, -1, key.p),
    )))
    return _sequence(_integer(0), _algorithm(_RSA, _NULL), _der(0x04, pkcs1))


def _load_private_der(data):
    pkcs8 = _root(data)
    if pkcs8.integer() != 0:
        raise ValueError('Unsupported PKCS#8 version')
    pkcs8.algorithm(_RSA).optional_null()
    pkcs1 = _root(pkcs8.read(0x04))
    pkcs8.finish()
    if pkcs1.integer() != 0:
        raise ValueError('Unsupported RSA private key version')
    n, e, d, p, q, dp, dq, coefficient = (pkcs1.integer() for _ in range(8))
    pkcs1.finish()
    if (
        n.bit_length() != RSA_KEY_BITS or e != RSA_PUBLIC_EXPONENT or not 0 < d < n
        or p < 3 or q < 3 or p == q or p % 2 == 0 or q % 2 == 0 or p * q != n
        or e * d % lcm(p - 1, q - 1) != 1
        or dp != d % (p - 1) or dq != d % (q - 1)
        or not 0 < coefficient < p or q * coefficient % p != 1
    ):
        raise ValueError('Inconsistent RSA private key')
    return RSAPrivateKey(n, e, d, p, q)


def _password_key(passphrase, salt, iterations):
    # The 32-byte AES key needs one PBKDF2 block when the PRF is HMAC-SHA256.
    if not isinstance(passphrase, bytes) or not 1 <= len(passphrase) <= 1024:
        raise ValueError('Invalid passphrase')
    key = crypto_ops.sha256(passphrase) if len(passphrase) > 64 else passphrase
    key = key.ljust(64, b'\x00')
    inner = crypto_ops.SHA256(bytes(value ^ 0x36 for value in key))
    outer = crypto_ops.SHA256(bytes(value ^ 0x5c for value in key))

    def hmac_sha256(message):
        state = inner.copy()
        state.update(message)
        outer_state = outer.copy()
        outer_state.update(state.digest())
        return outer_state.digest()

    block = hmac_sha256(salt + b'\x00\x00\x00\x01')
    result = int.from_bytes(block, 'big')
    for _ in range(iterations - 1):
        block = hmac_sha256(block)
        result ^= int.from_bytes(block, 'big')
    return result.to_bytes(32, 'big')


def _encrypt_cbc(data, key, iv):
    padding = _BLOCK_BYTES - len(data) % _BLOCK_BYTES
    padded = data + bytes((padding,)) * padding
    round_keys = crypto_ops._expand_key(key)
    previous = iv
    ciphertext = bytearray()
    for offset in range(0, len(padded), _BLOCK_BYTES):
        block = padded[offset:offset + _BLOCK_BYTES]
        previous = crypto_ops._encrypt_block(crypto_ops.xor_bytes(block, previous), round_keys)
        ciphertext.extend(previous)
    return bytes(ciphertext)


def _decrypt_cbc(data, key, iv):
    if not data or len(data) % _BLOCK_BYTES:
        raise ValueError('Invalid encrypted key length')
    round_keys = crypto_ops._expand_key(key)
    previous = iv
    plaintext = bytearray()
    for offset in range(0, len(data), _BLOCK_BYTES):
        block = data[offset:offset + _BLOCK_BYTES]
        plaintext.extend(crypto_ops.xor_bytes(crypto_ops._decrypt_block(block, round_keys), previous))
        previous = block
    padding = plaintext[-1]
    if not 1 <= padding <= _BLOCK_BYTES or not compare_digest(plaintext[-padding:], bytes((padding,)) * padding):
        raise ValueError('Invalid private key padding')
    return bytes(plaintext[:-padding])


def encrypted_private_pem(key, passphrase):
    salt, iv = urandom(16), urandom(_BLOCK_BYTES)
    aes_key = _password_key(passphrase, salt, _ITERATIONS)
    ciphertext = _encrypt_cbc(_private_der(key), aes_key, iv)
    kdf = _algorithm(_PBKDF2, _sequence(_der(0x04, salt), _integer(_ITERATIONS), _algorithm(_HMAC_SHA256, _NULL)))
    cipher = _algorithm(_AES256_CBC, _der(0x04, iv))
    pkcs8 = _sequence(_algorithm(_PBES2, _sequence(kdf, cipher)), _der(0x04, ciphertext))
    return _pem(_PRIVATE_LABEL, pkcs8)


def load_private(pem, passphrase):
    pkcs8 = _root(_read_pem(pem, _PRIVATE_LABEL))
    algorithm = pkcs8.algorithm(_PBES2)
    params = algorithm.sequence()
    algorithm.finish()
    derivation = params.algorithm(_PBKDF2)
    kdf = derivation.sequence()
    derivation.finish()
    salt, iterations = kdf.read(0x04), kdf.integer()
    if not 8 <= len(salt) <= 64 or not 1 <= iterations <= _MAX_ITERATIONS:
        raise ValueError('Unsupported private key derivation parameters')
    if kdf.peek() == 0x02 and kdf.integer() != 32:
        raise ValueError('Unsupported private key length')
    kdf.algorithm(_HMAC_SHA256).optional_null()
    kdf.finish()
    cipher = params.algorithm(_AES256_CBC)
    iv = cipher.read(0x04)
    cipher.finish()
    params.finish()
    if len(iv) != _BLOCK_BYTES:
        raise ValueError('Invalid private key IV')
    ciphertext = pkcs8.read(0x04)
    pkcs8.finish()
    aes_key = _password_key(passphrase, salt, iterations)
    return _load_private_der(_decrypt_cbc(ciphertext, aes_key, iv))
