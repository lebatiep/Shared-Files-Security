"""Shamir 2-of-3 shares and the SFILE v2 wire formats."""

import base64
from dataclasses import dataclass, field
import re
import secrets

from .config import (
    AES_KEY_BYTES,
    FINGERPRINT_HEX_LENGTH,
    FORMAT_NAME,
    MAX_CIPHERTEXT_BYTES,
    MAX_HEADER_BYTES,
    MAX_PACKAGE_BYTES,
    MIN_CIPHERTEXT_BYTES,
    NONCE_BYTES,
    SIGNATURE_BYTES,
    TRANSFER_ID_HEX_LENGTH,
    WRAPPED_KEY_BYTES,
)
from .crypto_ops import sha256
from .envelope import _decode_base64, _domain_call, encode_json, frame, read_json
from .errors import ErrorCode, ShareError


FIELD_PRIME = (1 << 521) - 1
FIELD_BYTES = (FIELD_PRIME.bit_length() + 7) // 8
SHARE_BYTES = 1 + FIELD_BYTES
SHARE_COUNT = 3
MAX_CONTRIBUTION_BYTES = 2_048
THRESHOLD_VERSION = 2
THRESHOLD_SUITE = "A256GCM_RSA3072OAEP256_PSS256_SHAMIR2OF3"
CONTRIBUTION_FORMAT = "SFILE-CONTRIBUTION"

_AAD_CONTEXT = b"SFILE2-AAD"
_SIGN_CONTEXT = b"SFILE2-SIGN"
_SHARE_CONTEXT = b"SFILE2-SHARE"
_TRANSFER_ID = re.compile(rf"[0-9a-f]{{{TRANSFER_ID_HEX_LENGTH}}}")
_FINGERPRINT = re.compile(rf"[0-9a-f]{{{FINGERPRINT_HEX_LENGTH}}}")

_HEADER_FIELDS = {"format", "version", "suite", "transfer_id", "sender_sig_fp", "recipients"}
_RECIPIENT_FIELDS = {"fingerprint", "commitment"}
_PACKAGE_FIELDS = {"header_b64", "wrapped_shares_b64", "nonce_b64", "ciphertext_b64", "signature_b64"}
_CONTRIBUTION_FIELDS = {"format", "version", "package_id", "source_fp", "target_fp", "wrapped_share_b64"}


@dataclass(frozen=True, slots=True)
class ThresholdRecipient:
    fingerprint: str
    commitment: str


@dataclass(frozen=True, slots=True)
class ThresholdHeader:
    transfer_id: str
    sender_sig_fp: str
    recipients: tuple[ThresholdRecipient, ThresholdRecipient, ThresholdRecipient]


@dataclass(frozen=True, slots=True)
class ThresholdEnvelope:
    header: ThresholdHeader
    header_bytes: bytes = field(repr=False)
    wrapped_shares: tuple[bytes, bytes, bytes] = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    signature: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class Contribution:
    package_id: str
    source_fp: str
    target_fp: str
    wrapped_share: bytes = field(repr=False)


def split_key(secret: bytes) -> tuple[bytes, bytes, bytes]:
    """Create the three evaluations of a random line through the AES key."""
    if not isinstance(secret, bytes) or len(secret) != AES_KEY_BYTES:
        raise ShareError(ErrorCode.INVALID_SHARE)
    intercept = int.from_bytes(secret, "big")
    slope = secrets.randbelow(FIELD_PRIME)

    def evaluate(index: int) -> bytes:
        value = (intercept + slope * index) % FIELD_PRIME
        return bytes([index]) + value.to_bytes(FIELD_BYTES, "big")

    return evaluate(1), evaluate(2), evaluate(3)


def _decode_share(share: bytes) -> tuple[int, int]:
    if not isinstance(share, bytes) or len(share) != SHARE_BYTES:
        raise ShareError(ErrorCode.INVALID_SHARE)
    index = share[0]
    value = int.from_bytes(share[1:], "big")
    if not 1 <= index <= SHARE_COUNT or value >= FIELD_PRIME:
        raise ShareError(ErrorCode.INVALID_SHARE)
    return index, value


def share_index(share: bytes) -> int:
    """Validate the field encoding and return its signed recipient position."""
    return _decode_share(share)[0]


def combine_shares(shares: tuple[bytes, bytes] | list[bytes]) -> bytes:
    """Interpolate at zero using two distinct, caller-authenticated shares."""
    if not isinstance(shares, (tuple, list)) or len(shares) != 2:
        raise ShareError(ErrorCode.INVALID_SHARE)
    left_index, left_value = _decode_share(shares[0])
    right_index, right_value = _decode_share(shares[1])
    if left_index == right_index:
        raise ShareError(ErrorCode.INVALID_SHARE)
    inverse = pow(right_index - left_index, -1, FIELD_PRIME)
    intercept = (left_value * right_index - right_value * left_index) * inverse % FIELD_PRIME
    if intercept.bit_length() > AES_KEY_BYTES * 8:
        raise ShareError(ErrorCode.INVALID_SHARE)
    return intercept.to_bytes(AES_KEY_BYTES, "big")


def _check_hex(value: str, pattern: re.Pattern, *, error=ErrorCode.INVALID_SCHEMA) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ShareError(error)


def share_commitment(transfer_id: str, share: bytes) -> str:
    """Commit to a share's bytes and index within the given transfer."""
    _check_hex(transfer_id, _TRANSFER_ID, error=ErrorCode.INVALID_SHARE)
    _decode_share(share)
    return sha256(_SHARE_CONTEXT + frame(bytes.fromhex(transfer_id)) + frame(share)).hex()


def _check_header(header: ThresholdHeader) -> None:
    if not isinstance(header, ThresholdHeader):
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    _check_hex(header.transfer_id, _TRANSFER_ID)
    _check_hex(header.sender_sig_fp, _FINGERPRINT)
    if not isinstance(header.recipients, tuple) or len(header.recipients) != SHARE_COUNT:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    fingerprints = set()
    for recipient in header.recipients:
        if not isinstance(recipient, ThresholdRecipient):
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        _check_hex(recipient.fingerprint, _FINGERPRINT)
        _check_hex(recipient.commitment, _FINGERPRINT)
        fingerprints.add(recipient.fingerprint)
    if len(fingerprints) != SHARE_COUNT:
        raise ShareError(ErrorCode.INVALID_SCHEMA)


def _check_object(value, fields) -> None:
    if not isinstance(value, dict) or value.keys() != fields:
        raise ShareError(ErrorCode.INVALID_SCHEMA)


def _check_format(value, name) -> None:
    if value["format"] != name:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    if type(value["version"]) is not int or value["version"] != THRESHOLD_VERSION:
        raise ShareError(ErrorCode.UNSUPPORTED_VERSION)


def build_header(header: ThresholdHeader) -> bytes:
    _check_header(header)
    return encode_json({
        "format": FORMAT_NAME,
        "version": THRESHOLD_VERSION,
        "suite": THRESHOLD_SUITE,
        "transfer_id": header.transfer_id,
        "sender_sig_fp": header.sender_sig_fp,
        "recipients": [
            {"fingerprint": item.fingerprint, "commitment": item.commitment}
            for item in header.recipients
        ],
    })


def _parse_header(raw: bytes) -> ThresholdHeader:
    value = read_json(raw, MAX_HEADER_BYTES)
    _check_object(value, _HEADER_FIELDS)
    _check_format(value, FORMAT_NAME)
    if value["suite"] != THRESHOLD_SUITE:
        raise ShareError(ErrorCode.UNSUPPORTED_SUITE)
    entries = value["recipients"]
    if not isinstance(entries, list) or len(entries) != SHARE_COUNT:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    for item in entries:
        _check_object(item, _RECIPIENT_FIELDS)
    first, second, third = (ThresholdRecipient(**item) for item in entries)
    header = ThresholdHeader(value["transfer_id"], value["sender_sig_fp"], (first, second, third))
    _check_header(header)
    return header


def _check_length(value, minimum: int, maximum: int) -> None:
    if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
        raise ShareError(ErrorCode.INVALID_LENGTH)


def _check_wrapped_shares(wrapped_shares: tuple[bytes, bytes, bytes]) -> None:
    if not isinstance(wrapped_shares, tuple) or len(wrapped_shares) != SHARE_COUNT:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    for wrapped in wrapped_shares:
        _check_length(wrapped, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES)


def _frame_header_and_shares(header_bytes: bytes, wrapped_shares: tuple[bytes, bytes, bytes]) -> bytes:
    _check_length(header_bytes, 1, MAX_HEADER_BYTES)
    _check_wrapped_shares(wrapped_shares)
    return frame(header_bytes) + b"".join(frame(wrapped) for wrapped in wrapped_shares)


def build_aad(header_bytes: bytes, wrapped_shares: tuple[bytes, bytes, bytes]) -> bytes:
    return _AAD_CONTEXT + _frame_header_and_shares(header_bytes, wrapped_shares)


def build_signature_input(
    header_bytes: bytes,
    wrapped_shares: tuple[bytes, bytes, bytes],
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    _check_length(nonce, NONCE_BYTES, NONCE_BYTES)
    _check_length(ciphertext, MIN_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_BYTES)
    return _SIGN_CONTEXT + _frame_header_and_shares(header_bytes, wrapped_shares) + frame(nonce) + frame(ciphertext)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value, minimum: int, maximum: int) -> bytes:
    decoded = _domain_call(_decode_base64, value, maximum)
    _check_length(decoded, minimum, maximum)
    return decoded


def serialize_package(envelope: ThresholdEnvelope) -> bytes:
    if not isinstance(envelope, ThresholdEnvelope) or _parse_header(envelope.header_bytes) != envelope.header:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    _check_wrapped_shares(envelope.wrapped_shares)
    _check_length(envelope.nonce, NONCE_BYTES, NONCE_BYTES)
    _check_length(envelope.ciphertext, MIN_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_BYTES)
    _check_length(envelope.signature, SIGNATURE_BYTES, SIGNATURE_BYTES)
    data = encode_json({
        "header_b64": _b64(envelope.header_bytes),
        "wrapped_shares_b64": [_b64(wrapped) for wrapped in envelope.wrapped_shares],
        "nonce_b64": _b64(envelope.nonce),
        "ciphertext_b64": _b64(envelope.ciphertext),
        "signature_b64": _b64(envelope.signature),
    })
    if len(data) > MAX_PACKAGE_BYTES:
        raise ShareError(ErrorCode.INPUT_TOO_LARGE)
    return data


def parse_package(data: bytes) -> ThresholdEnvelope:
    """Validate bounded structure and retain exactly the signed header bytes."""
    value = read_json(data, MAX_PACKAGE_BYTES)
    _check_object(value, _PACKAGE_FIELDS)
    entries = value["wrapped_shares_b64"]
    if not isinstance(entries, list) or len(entries) != SHARE_COUNT:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    header_bytes = _unb64(value["header_b64"], 1, MAX_HEADER_BYTES)
    header = _parse_header(header_bytes)
    first, second, third = (_unb64(wrapped, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES) for wrapped in entries)
    return ThresholdEnvelope(
        header, header_bytes, (first, second, third),
        _unb64(value["nonce_b64"], NONCE_BYTES, NONCE_BYTES),
        _unb64(value["ciphertext_b64"], MIN_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_BYTES),
        _unb64(value["signature_b64"], SIGNATURE_BYTES, SIGNATURE_BYTES),
    )


def _check_contribution(value: Contribution) -> None:
    if not isinstance(value, Contribution):
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    for identity in (value.package_id, value.source_fp, value.target_fp):
        _check_hex(identity, _FINGERPRINT)
    if value.source_fp == value.target_fp:
        raise ShareError(ErrorCode.INVALID_SCHEMA)
    _check_length(value.wrapped_share, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES)


def serialize_contribution(value: Contribution) -> bytes:
    _check_contribution(value)
    data = encode_json({
        "format": CONTRIBUTION_FORMAT,
        "version": THRESHOLD_VERSION,
        "package_id": value.package_id,
        "source_fp": value.source_fp,
        "target_fp": value.target_fp,
        "wrapped_share_b64": _b64(value.wrapped_share),
    })
    if len(data) > MAX_CONTRIBUTION_BYTES:
        raise ShareError(ErrorCode.INPUT_TOO_LARGE)
    return data


def parse_contribution(data: bytes) -> Contribution:
    """Read a contribution; the caller must verify its share against the package."""
    value = read_json(data, MAX_CONTRIBUTION_BYTES)
    _check_object(value, _CONTRIBUTION_FIELDS)
    _check_format(value, CONTRIBUTION_FORMAT)
    contribution = Contribution(
        value["package_id"], value["source_fp"], value["target_fp"],
        _unb64(value["wrapped_share_b64"], WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES),
    )
    _check_contribution(contribution)
    return contribution
