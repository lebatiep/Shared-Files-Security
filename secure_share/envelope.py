"""Định dạng gói .sfile: header, payload, framing, AAD, dữ liệu ký và JSON ngoài.

Chỉ xử lý byte và kiểm tra cấu trúc; không có mật mã, không đọc danh bạ, không
ghi tệp, không import crypto_ops. Parse thành công chưa có nghĩa là gói đã được
xác thực: service phải verify chữ ký trước khi tin bất kỳ giá trị nào.
"""

import base64
import binascii
import json
import re
from typing import NamedTuple

from dataclasses import asdict

from .config import (
    MAX_FILE_BYTES as MAX_FILE, MAX_PACKAGE_BYTES as MAX_ENVELOPE,
    MAX_HEADER_BYTES as MAX_HEADER, MAX_METADATA_BYTES as MAX_METADATA,
    WRAPPED_KEY_BYTES as WRAPPED_LEN, SIGNATURE_BYTES as SIGNATURE_LEN,
    NONCE_BYTES as NONCE_LEN, GCM_TAG_BYTES as TAG_LEN,
    MIN_CIPHERTEXT_BYTES as MIN_CIPHERTEXT, MAX_CIPHERTEXT_BYTES as MAX_CIPHERTEXT,
    FORMAT_NAME as FORMAT, FORMAT_VERSION as VERSION, CIPHER_SUITE as SUITE,
    AAD_CONTEXT, SIGNATURE_CONTEXT as SIGN_CONTEXT,
)
from .errors import ErrorCode, ShareError
from .models import PackageHeader, Payload, RawEnvelope as ModelEnvelope

MAX_PAYLOAD = 4 + MAX_METADATA + MAX_FILE

_HEADER_KEYS = {"format", "version", "suite", "transfer_id",
                "sender_sig_fp", "recipient_enc_fp"}
_ENVELOPE_KEYS = ("header_b64", "wrapped_key_b64", "nonce_b64",
                  "ciphertext_b64", "signature_b64")
_ID_RE = re.compile(r"[0-9a-f]{32}")
_FP_RE = re.compile(r"[0-9a-f]{64}")


class EnvelopeError(ValueError):
    """Lỗi cấu trúc; code là PARSE (gói/header) hoặc PAYLOAD (sau giải mã)."""

    def __init__(self, code: str, message: str, domain_code=None):
        super().__init__(message)
        self.code = code
        self.domain_code = domain_code or (ErrorCode.PAYLOAD_INVALID if code == "PAYLOAD" else ErrorCode.INVALID_SCHEMA)


class RawEnvelope(NamedTuple):
    """Năm phần của gói; header_raw là byte thô, không được định dạng lại."""
    header_raw: bytes
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes
    signature: bytes


# ----------------------------------------------------------------------
# Framing, AAD và dữ liệu ký
# ----------------------------------------------------------------------

def _validate_bytes(name: str, data: bytes, minimum: int, maximum: int) -> None:
    if not isinstance(data, bytes):
        raise TypeError(f"{name} phải là bytes")
    if not minimum <= len(data) <= maximum:
        raise ValueError(f"Độ dài {name} phải từ {minimum} đến {maximum} byte")


def frame(data: bytes) -> bytes:
    """frame(X) = u32be(len(X)) || X; giữ nguyên byte gốc."""
    _validate_bytes("data", data, 0, 0xFFFFFFFF)
    return len(data).to_bytes(4, "big") + data


def build_aad(header: bytes, wrapped_key: bytes) -> bytes:
    """AAD = 'SFILE1-AAD' || frame(H) || frame(W); không phân tích header."""
    _validate_bytes("header", header, 1, MAX_HEADER)
    _validate_bytes("wrapped_key", wrapped_key, WRAPPED_LEN, WRAPPED_LEN)
    return AAD_CONTEXT + frame(header) + frame(wrapped_key)


def build_signature_input(header: bytes, wrapped_key: bytes,
                          nonce: bytes, ciphertext: bytes) -> bytes:
    """M = 'SFILE1-SIGN' || frame(H) || frame(W) || frame(N) || frame(C)."""
    _validate_bytes("header", header, 1, MAX_HEADER)
    _validate_bytes("wrapped_key", wrapped_key, WRAPPED_LEN, WRAPPED_LEN)
    _validate_bytes("nonce", nonce, NONCE_LEN, NONCE_LEN)
    _validate_bytes("ciphertext", ciphertext, MIN_CIPHERTEXT, MAX_CIPHERTEXT)
    return (SIGN_CONTEXT + frame(header) + frame(wrapped_key)
            + frame(nonce) + frame(ciphertext))


# ----------------------------------------------------------------------
# JSON nghiêm ngặt
# ----------------------------------------------------------------------

def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("Khóa JSON bị trùng")
    return dict(pairs)


def _reject_constant(name):
    raise ValueError("Hằng JSON không hợp lệ: " + name)


def _strict_json(data: bytes, code: str):
    """JSON UTF-8: không khóa trùng, không NaN/Infinity, không dữ liệu dư."""
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise EnvelopeError(code, "JSON không hợp lệ", ErrorCode.INVALID_JSON if code == "PARSE" else ErrorCode.PAYLOAD_INVALID) from None


# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------

def build_header(transfer_id: str, sender_sig_fp: str, recipient_enc_fp: str) -> bytes:
    """Tạo byte header H (JSON gọn, UTF-8) và tự kiểm tra bằng parse_header."""
    header = json.dumps({
        "format": FORMAT, "version": VERSION, "suite": SUITE,
        "transfer_id": transfer_id, "sender_sig_fp": sender_sig_fp,
        "recipient_enc_fp": recipient_enc_fp,
    }, separators=(",", ":")).encode("utf-8")
    parse_header(header)
    return header


def parse_header(header_raw: bytes) -> dict:
    """Kiểm tra schema header. Giá trị chưa được xác thực cho tới khi PSS đạt."""
    if not isinstance(header_raw, bytes) or len(header_raw) > MAX_HEADER:
        raise EnvelopeError("PARSE", "Header vượt giới hạn")
    header = _strict_json(header_raw, "PARSE")
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS:
        raise EnvelopeError("PARSE", "Trường header không đúng")
    if header["format"] != FORMAT:
        raise EnvelopeError("PARSE", "Định dạng hoặc bộ thuật toán không hỗ trợ")
    if header["suite"] != SUITE:
        raise EnvelopeError("PARSE", "Unsupported suite", ErrorCode.UNSUPPORTED_SUITE)
    if type(header["version"]) is not int or header["version"] != VERSION:
        raise EnvelopeError("PARSE", "Phiên bản không hỗ trợ", ErrorCode.UNSUPPORTED_VERSION)
    for name, pattern in (("transfer_id", _ID_RE), ("sender_sig_fp", _FP_RE),
                          ("recipient_enc_fp", _FP_RE)):
        value = header[name]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise EnvelopeError("PARSE", "Giá trị " + name + " không hợp lệ")
    return header


# ----------------------------------------------------------------------
# JSON ngoài (.sfile)
# ----------------------------------------------------------------------

def _check_parts(envelope: RawEnvelope) -> None:
    if len(envelope.header_raw) > MAX_HEADER:
        raise EnvelopeError("PARSE", "Header vượt giới hạn")
    if len(envelope.wrapped_key) != WRAPPED_LEN:
        raise EnvelopeError("PARSE", "Độ dài khóa bọc không đúng", ErrorCode.INVALID_LENGTH)
    if len(envelope.signature) != SIGNATURE_LEN:
        raise EnvelopeError("PARSE", "Độ dài chữ ký không đúng", ErrorCode.INVALID_LENGTH)
    if len(envelope.nonce) != NONCE_LEN:
        raise EnvelopeError("PARSE", "Độ dài nonce không đúng", ErrorCode.INVALID_LENGTH)
    if not MIN_CIPHERTEXT <= len(envelope.ciphertext) <= MAX_CIPHERTEXT:
        raise EnvelopeError("PARSE", "Độ dài bản mã không đúng", ErrorCode.INVALID_LENGTH)


def serialize_envelope(envelope: RawEnvelope) -> bytes:
    """Xuất JSON ngoài với đúng 5 trường Base64."""
    if any(not isinstance(part, bytes) for part in envelope):
        raise TypeError("Các phần của gói phải là bytes")
    _check_parts(envelope)
    fields = {name: base64.b64encode(part).decode("ascii")
              for name, part in zip(_ENVELOPE_KEYS, envelope)}
    data = json.dumps(fields, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_ENVELOPE:
        raise EnvelopeError("PARSE", "Gói vượt giới hạn")
    return data


def _decode_base64(value, limit: int) -> bytes:
    """Base64 nghiêm ngặt: đúng bảng chữ, đúng padding, không bit thừa."""
    if not isinstance(value, str) or not value.isascii():
        raise EnvelopeError("PARSE", "Base64 không hợp lệ", ErrorCode.INVALID_BASE64)
    if len(value) > (limit + 2) // 3 * 4:
        raise EnvelopeError("PARSE", "Trường vượt giới hạn", ErrorCode.INVALID_LENGTH)
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise EnvelopeError("PARSE", "Base64 không hợp lệ", ErrorCode.INVALID_BASE64) from None
    if base64.b64encode(data).decode("ascii") != value:
        raise EnvelopeError("PARSE", "Base64 không chuẩn", ErrorCode.INVALID_BASE64)
    return data


def parse_envelope(data: bytes) -> RawEnvelope:
    """Đọc gói ngoài. Kiểm cap trước khi parse; H giữ nguyên byte thô."""
    if not isinstance(data, bytes):
        raise TypeError("Gói phải là bytes")
    if len(data) > MAX_ENVELOPE:
        raise EnvelopeError("PARSE", "Gói vượt giới hạn")
    root = _strict_json(data, "PARSE")
    if not isinstance(root, dict) or set(root) != set(_ENVELOPE_KEYS):
        raise EnvelopeError("PARSE", "Trường của gói không đúng")
    limits = (MAX_HEADER, WRAPPED_LEN, NONCE_LEN, MAX_CIPHERTEXT, SIGNATURE_LEN)
    envelope = RawEnvelope(*[_decode_base64(root[name], limit)
                             for name, limit in zip(_ENVELOPE_KEYS, limits)])
    _check_parts(envelope)
    return envelope


# ----------------------------------------------------------------------
# Payload: u32be(meta_len) || metadata JSON UTF-8 || raw_file
# ----------------------------------------------------------------------

def _validate_filename(filename) -> None:
    if not isinstance(filename, str) or not filename or "\0" in filename:
        raise EnvelopeError("PAYLOAD", "Tên tệp phải là chuỗi không rỗng, không chứa NUL")
    if len(filename) > MAX_METADATA:
        raise EnvelopeError("PAYLOAD", "Tên tệp vượt giới hạn metadata")
    try:
        filename.encode("utf-8")
    except UnicodeError:
        raise EnvelopeError("PAYLOAD", "Tên tệp không hợp lệ UTF-8") from None


def build_payload(filename: str, raw_file: bytes) -> bytes:
    """Đóng tên và nội dung; filename chỉ là metadata, không phải đường dẫn."""
    if not isinstance(raw_file, bytes):
        raise TypeError("Nội dung tệp phải là bytes")
    if len(raw_file) > MAX_FILE:
        raise EnvelopeError("PAYLOAD", "Tệp vượt 10 MiB")
    _validate_filename(filename)
    metadata = json.dumps({"filename": filename}, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
    if len(metadata) > MAX_METADATA:
        raise EnvelopeError("PAYLOAD", "Metadata vượt 4096 byte")
    return len(metadata).to_bytes(4, "big") + metadata + raw_file


def _unpack_payload(payload: bytes) -> tuple[str, bytes]:
    if not isinstance(payload, bytes):
        raise TypeError("Payload phải là bytes")
    if not 4 <= len(payload) <= MAX_PAYLOAD:
        raise EnvelopeError("PAYLOAD", "Độ dài payload không hợp lệ")
    meta_len = int.from_bytes(payload[:4], "big")
    if not 1 <= meta_len <= MAX_METADATA:
        raise EnvelopeError("PAYLOAD", "Độ dài metadata không hợp lệ")
    offset = 4 + meta_len
    if offset > len(payload) or len(payload) - offset > MAX_FILE:
        raise EnvelopeError("PAYLOAD", "Payload bị cắt hoặc tệp vượt 10 MiB")
    metadata = _strict_json(payload[4:offset], "PAYLOAD")
    if not isinstance(metadata, dict) or set(metadata) != {"filename"}:
        raise EnvelopeError("PAYLOAD", "Metadata phải chỉ chứa filename")
    filename = metadata["filename"]
    if not isinstance(filename, str):
        raise EnvelopeError("PAYLOAD", "Tên tệp phải là chuỗi")
    return filename, payload[offset:]


def parse_payload(payload: bytes) -> tuple[str, bytes]:
    """Kiểm tra khung, JSON và giới hạn; trả (filename, raw_file)."""
    filename, raw_file = _unpack_payload(payload)
    _validate_filename(filename)
    return filename, raw_file


def read_json(data, limit):
    if not isinstance(data, bytes) or len(data) > limit:
        raise ShareError(ErrorCode.INPUT_TOO_LARGE)
    try:
        return _strict_json(data, "PARSE")
    except EnvelopeError as error:
        raise ShareError(error.domain_code) from None


def encode_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _safe_filename(name):
    if not isinstance(name, str) or not name or len(name) > 255:
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    try:
        encoded_name = name.encode("utf-8")
    except UnicodeError:
        raise ShareError(ErrorCode.PAYLOAD_INVALID) from None
    if len(encoded_name) > 255:
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    if any(ord(c) < 32 or ord(c) == 127 or c in '<>:"/\\|?*' for c in name):
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    stem = name.split(".")[0].rstrip(" ").upper()
    if name.endswith((" ", ".")) or stem in _WINDOWS_DEVICE_NAMES:
        raise ShareError(ErrorCode.PAYLOAD_INVALID)


_WINDOWS_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³"
}


def _domain_call(function, *args):
    try:
        return function(*args)
    except EnvelopeError as error:
        raise ShareError(error.domain_code) from None
    except (TypeError, ValueError):
        raise ShareError(ErrorCode.INVALID_LENGTH) from None


class EnvelopeCodec:
    fields = _ENVELOPE_KEYS

    def build_header(self, header):
        raw = encode_json(asdict(header))
        _domain_call(parse_header, raw)
        return raw

    def build_payload(self, filename, data):
        _safe_filename(filename)
        if not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise ShareError(ErrorCode.INPUT_TOO_LARGE)
        return _domain_call(build_payload, filename, data)

    def parse_payload(self, data):
        if not isinstance(data, bytes):
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        filename, raw = _domain_call(_unpack_payload, data)
        try:
            _safe_filename(filename)
        except ShareError:
            filename = "recovered.bin"
        return Payload(filename, raw)

    def build_aad(self, header_bytes, wrapped_key):
        return _domain_call(build_aad, header_bytes, wrapped_key)

    def build_signature_input(self, header_bytes, wrapped_key, nonce, ciphertext):
        return _domain_call(build_signature_input, header_bytes, wrapped_key, nonce, ciphertext)

    def serialize_envelope(self, envelope):
        raw = RawEnvelope(envelope.header_bytes, envelope.wrapped_key, envelope.nonce,
                          envelope.ciphertext, envelope.signature)
        data = _domain_call(serialize_envelope, raw)
        if self.parse_envelope(data).header != envelope.header:
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        return data

    def parse_envelope(self, data):
        if not isinstance(data, bytes) or len(data) > MAX_ENVELOPE:
            raise ShareError(ErrorCode.INPUT_TOO_LARGE)
        raw = _domain_call(parse_envelope, data)
        header = PackageHeader(**_domain_call(parse_header, raw.header_raw))
        return ModelEnvelope(header, *raw)
