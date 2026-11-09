"""RSA-3072/OAEP-SHA256 tự cài; nhận khóa số nguyên từ phần quản lý khóa.

Không chứa sinh khóa hay đọc PEM. Không dùng cho dữ liệu thật: Python không
bảo đảm các phép toán khóa riêng chạy trong thời gian hằng.
"""

from os import urandom

from sha256 import mgf1, sha256, xor_bytes


def check_key(n: int, exponent: int) -> None:
    """Kiểm tra tham số theo profile RSA-3072 của dự án."""
    if type(n) is not int or n.bit_length() != 3072 or n % 2 == 0:
        raise ValueError("Modulus RSA phải là số lẻ 3072 bit")
    if type(exponent) is not int or not 1 < exponent < n or exponent % 2 == 0:
        raise ValueError("Số mũ RSA không hợp lệ")


def wrap(aes_key: bytes, n: int, e: int = 65537) -> bytes:
    """Bọc khóa AES 32 byte bằng public key (n, e), OAEP label rỗng."""
    check_key(n, e)
    if e != 65537:
        raise ValueError("Public exponent phải là 65537")
    if not isinstance(aes_key, bytes) or len(aes_key) != 32:
        raise ValueError("Khóa AES phải dài 32 byte")

    # EM = 0x00 || maskedSeed || maskedDB (tổng cộng 384 byte).
    padding = bytes(384 - len(aes_key) - 2 * 32 - 2)
    data_block = sha256(b"") + padding + b"\x01" + aes_key
    seed = urandom(32)
    masked_data = xor_bytes(data_block, mgf1(seed, len(data_block)))
    masked_seed = xor_bytes(seed, mgf1(masked_data, 32))
    encoded = b"\x00" + masked_seed + masked_data
    encrypted = pow(int.from_bytes(encoded, "big"), e, n)
    return encrypted.to_bytes(384, "big")


def unwrap(wrapped_key: bytes, n: int, d: int) -> bytes:
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

    # Profile chỉ bọc 32 byte nên vị trí dấu 0x01 là cố định.
    expected_prefix = sha256(b"") + bytes(286) + b"\x01"
    if encoded[0] != 0 or data_block[:-32] != expected_prefix:
        raise ValueError("Khóa bọc RSA không hợp lệ")
    return data_block[-32:]
