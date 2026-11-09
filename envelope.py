"""Đóng khung byte và tạo đầu vào xác thực cho định dạng SFILE1."""


def _validate_bytes(name: str, data: bytes, minimum: int, maximum: int) -> None:
    if not isinstance(data, bytes):
        raise TypeError(f"{name} phải là bytes")
    if not minimum <= len(data) <= maximum:
        raise ValueError(f"Độ dài {name} phải từ {minimum} đến {maximum} byte")


def frame(data: bytes) -> bytes:
    """Thêm độ dài uint32 big-endian trước dữ liệu, giữ nguyên byte gốc."""
    _validate_bytes("data", data, 0, 0xFFFFFFFF)
    return len(data).to_bytes(4, "big") + data


def build_aad(header: bytes, wrapped_key: bytes) -> bytes:
    """Tạo AAD từ header thô và khóa đã bọc; không phân tích header."""
    _validate_bytes("header", header, 1, 4096)
    _validate_bytes("wrapped_key", wrapped_key, 384, 384)
    return b"SFILE1-AAD" + frame(header) + frame(wrapped_key)


def build_signature_input(
    header: bytes, wrapped_key: bytes, nonce: bytes, ciphertext: bytes
) -> bytes:
    """Tạo thông điệp ký, gồm ciphertext có kèm thẻ xác thực."""
    _validate_bytes("header", header, 1, 4096)
    _validate_bytes("wrapped_key", wrapped_key, 384, 384)
    _validate_bytes("nonce", nonce, 12, 12)
    _validate_bytes("ciphertext", ciphertext, 16, 10489876)
    return (
        b"SFILE1-SIGN"
        + frame(header)
        + frame(wrapped_key)
        + frame(nonce)
        + frame(ciphertext)
    )
