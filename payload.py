"""Đóng/gỡ payload: u32be độ dài JSON UTF-8 || JSON || nội dung tệp.

Tên tệp chỉ là metadata; module không truy cập hay chuẩn hóa đường dẫn.
"""

import json

# Giới hạn cục bộ; cần giữ đồng bộ khi dự án bổ sung config chung.
MAX_FILE_SIZE = 10_485_760
MAX_METADATA_SIZE = 4096
MAX_PAYLOAD_SIZE = 4 + MAX_METADATA_SIZE + MAX_FILE_SIZE


def _validate_filename(filename):
    if not isinstance(filename, str) or not filename or "\0" in filename:
        raise ValueError("Tên tệp phải là chuỗi không rỗng, không chứa NUL")
    if len(filename) > MAX_METADATA_SIZE:
        raise ValueError("Tên tệp vượt giới hạn metadata")
    try:
        filename.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Tên tệp không hợp lệ UTF-8") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Metadata có khóa trùng lặp")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Hằng JSON không hợp lệ: " + value)


def pack_payload(filename: str, raw_file: bytes) -> bytes:
    """Đóng tên và bytes; báo TypeError/ValueError nếu sai kiểu/giới hạn."""
    if not isinstance(raw_file, bytes):
        raise TypeError("Nội dung tệp phải là bytes")
    if len(raw_file) > MAX_FILE_SIZE:
        raise ValueError("Tệp vượt 10 MiB")
    _validate_filename(filename)
    metadata = json.dumps({"filename": filename}, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
    if len(metadata) > MAX_METADATA_SIZE:
        raise ValueError("Metadata vượt 4096 bytes")
    return len(metadata).to_bytes(4, "big") + metadata + raw_file


def unpack_payload(payload: bytes) -> tuple[str, bytes]:
    """Kiểm tra khung, JSON và giới hạn trước khi trả tên cùng nội dung."""
    if not isinstance(payload, bytes):
        raise TypeError("Payload phải là bytes")
    if not 4 <= len(payload) <= MAX_PAYLOAD_SIZE:
        raise ValueError("Độ dài payload không hợp lệ")
    metadata_size = int.from_bytes(payload[:4], "big")
    if not 1 <= metadata_size <= MAX_METADATA_SIZE:
        raise ValueError("Độ dài metadata không hợp lệ")
    content_offset = 4 + metadata_size
    if content_offset > len(payload) or len(payload) - content_offset > MAX_FILE_SIZE:
        raise ValueError("Payload bị cắt hoặc tệp vượt 10 MiB")
    try:
        metadata = json.loads(payload[4:content_offset].decode("utf-8"),
                              object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Metadata không hợp lệ") from exc
    if not isinstance(metadata, dict) or set(metadata) != {"filename"}:
        raise ValueError("Metadata phải chỉ chứa filename")
    _validate_filename(metadata["filename"])
    return metadata["filename"], payload[content_offset:]
