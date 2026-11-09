"""Chữ ký RSA-PSS: SHA-256, MGF1-SHA256, salt đúng 32 byte."""

from os import urandom

from rsa import check_key
from sha256 import mgf1, sha256, xor_bytes


def sign(message: bytes, n: int, d: int) -> bytes:
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


def verify(message: bytes, signature: bytes, n: int, e: int = 65537) -> bool:
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
