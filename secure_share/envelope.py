import base64
import binascii
from dataclasses import asdict
import json
import re

from .config import (
    AAD_CONTEXT, SIGNATURE_CONTEXT, CIPHER_SUITE, MAX_FILE_BYTES,
    MAX_HEADER_BYTES, MAX_METADATA_BYTES, MAX_PACKAGE_BYTES, MAX_CIPHERTEXT_BYTES,
)
from .errors import ErrorCode, ShareError
from .models import PackageHeader, Payload, RawEnvelope


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError


def read_json(data, limit):
    if not isinstance(data, bytes) or len(data) > limit:
        raise ShareError(ErrorCode.INPUT_TOO_LARGE)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ShareError(ErrorCode.INVALID_JSON) from None


def encode_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def frame(data):
    return len(data).to_bytes(4, 'big') + data


def _filename(name):
    # A filename is metadata, never a destination supplied by the sender.
    if not isinstance(name, str) or not name or len(name) > 255:
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    if any(ord(c) < 32 or ord(c) == 127 or c in '<>:"/\\|?*' for c in name):
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    stem = name.split('.')[0].upper()
    if name.endswith((' ', '.')) or stem in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}:
        raise ShareError(ErrorCode.PAYLOAD_INVALID)
    try:
        name.encode('utf-8')
    except UnicodeError:
        raise ShareError(ErrorCode.PAYLOAD_INVALID) from None
    return name


class EnvelopeCodec:
    fields = ('header_b64', 'wrapped_key_b64', 'nonce_b64', 'ciphertext_b64', 'signature_b64')

    def _header(self, raw):
        obj = read_json(raw, MAX_HEADER_BYTES)
        if not isinstance(obj, dict) or set(obj) != set(PackageHeader.__dataclass_fields__):
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        if obj['format'] != 'SFILE':
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        if type(obj['version']) is not int or obj['version'] != 1:
            raise ShareError(ErrorCode.UNSUPPORTED_VERSION)
        if obj['suite'] != CIPHER_SUITE:
            raise ShareError(ErrorCode.UNSUPPORTED_SUITE)
        for field, length in [('transfer_id', 32), ('sender_sig_fp', 64), ('recipient_enc_fp', 64)]:
            if not isinstance(obj[field], str) or not re.fullmatch('[0-9a-f]{%d}' % length, obj[field]):
                raise ShareError(ErrorCode.INVALID_SCHEMA)
        return PackageHeader(**obj)

    def build_header(self, header):
        raw = encode_json(asdict(header))
        self._header(raw)
        return raw

    def build_payload(self, filename, data):
        _filename(filename)
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise ShareError(ErrorCode.INPUT_TOO_LARGE)
        metadata = encode_json({'filename': filename})
        if len(metadata) > MAX_METADATA_BYTES:
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        return frame(metadata) + data

    def parse_payload(self, data):
        if not isinstance(data, bytes) or not 5 <= len(data) <= 4 + MAX_METADATA_BYTES + MAX_FILE_BYTES:
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        size = int.from_bytes(data[:4], 'big')
        if not 1 <= size <= MAX_METADATA_BYTES or 4 + size > len(data) or len(data) - 4 - size > MAX_FILE_BYTES:
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        try:
            obj = read_json(data[4:4 + size], MAX_METADATA_BYTES)
        except ShareError:
            raise ShareError(ErrorCode.PAYLOAD_INVALID) from None
        if not isinstance(obj, dict) or set(obj) != {'filename'}:
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        return Payload(_filename(obj['filename']), data[4 + size:])

    def build_aad(self, header_bytes, wrapped_key):
        return AAD_CONTEXT + frame(header_bytes) + frame(wrapped_key)

    def build_signature_input(self, header_bytes, wrapped_key, nonce, ciphertext):
        return SIGNATURE_CONTEXT + b''.join(frame(v) for v in (header_bytes, wrapped_key, nonce, ciphertext))

    def serialize_envelope(self, envelope):
        values = (envelope.header_bytes, envelope.wrapped_key, envelope.nonce, envelope.ciphertext, envelope.signature)
        encoded = encode_json(dict(zip(self.fields, (base64.b64encode(v).decode('ascii') for v in values))))
        parsed = self.parse_envelope(encoded)
        if parsed.header != envelope.header:
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        return encoded

    def parse_envelope(self, data):
        obj = read_json(data, MAX_PACKAGE_BYTES)
        if not isinstance(obj, dict) or set(obj) != set(self.fields):
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        values = []
        for field, low, high in zip(self.fields, (1, 384, 12, 16, 384), (MAX_HEADER_BYTES, 384, 12, MAX_CIPHERTEXT_BYTES, 384)):
            value = obj[field]
            if not isinstance(value, str) or len(value) > 4 * ((high + 2) // 3):
                raise ShareError(ErrorCode.INVALID_LENGTH)
            try:
                raw = base64.b64decode(value, validate=True)
                if base64.b64encode(raw).decode('ascii') != value:
                    raise ValueError
            except (ValueError, binascii.Error):
                raise ShareError(ErrorCode.INVALID_BASE64) from None
            if not low <= len(raw) <= high:
                raise ShareError(ErrorCode.INVALID_LENGTH)
            values.append(raw)
        return RawEnvelope(self._header(values[0]), *values)
