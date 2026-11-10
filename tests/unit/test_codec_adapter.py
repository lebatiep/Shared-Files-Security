import json
from dataclasses import asdict, replace

import pytest

from secure_share import envelope
from secure_share.config import CIPHER_SUITE
from secure_share.errors import ErrorCode, ShareError
from secure_share.models import PackageHeader, RawEnvelope
from secure_share.ports import EnvelopeCodec as CodecPort


def package():
    header = PackageHeader("SFILE", 1, CIPHER_SUITE, "a" * 32, "b" * 64, "c" * 64)
    raw = json.dumps(asdict(header), indent=2).encode()
    return RawEnvelope(header, raw, b"w" * 384, b"n" * 12, b"c" * 16, b"s" * 384)


def test_adapter_preserves_header_bytes_and_shared_framing():
    codec = envelope.EnvelopeCodec()
    value = package()
    assert isinstance(codec, CodecPort)
    assert codec.parse_envelope(codec.serialize_envelope(value)) == value
    assert codec.build_aad(value.header_bytes, value.wrapped_key) == envelope.build_aad(value.header_bytes, value.wrapped_key)
    assert codec.parse_payload(codec.build_payload("report.bin", b"\x00\xff")).data == b"\x00\xff"
    with pytest.raises(ShareError) as error:
        codec.serialize_envelope(replace(value, header=replace(value.header, transfer_id="d" * 32)))
    assert error.value.code is ErrorCode.INVALID_SCHEMA


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff", b"[" * 2000])
def test_json_boundary_rejects_invalid_values(data):
    with pytest.raises(ShareError) as error:
        envelope.read_json(data, 4096)
    assert error.value.code is ErrorCode.INVALID_JSON


def test_json_cap_and_encoder():
    with pytest.raises(ShareError) as error:
        envelope.read_json(b"{}", 1)
    assert error.value.code is ErrorCode.INPUT_TOO_LARGE
    with pytest.raises(ValueError):
        envelope.encode_json({"a": float("nan")})


@pytest.mark.parametrize("name", ["../evil", "a/b", "a\\b", "C:evil", "CON", "NUL.txt", "COM1", "trailing.", "trailing ", "\n", ""])
def test_adapter_rejects_unsafe_send_names_and_recovers_safe_receive_names(name):
    codec = envelope.EnvelopeCodec()
    with pytest.raises(ShareError) as error:
        codec.build_payload(name, b"data")
    assert error.value.code is ErrorCode.PAYLOAD_INVALID
    payload = envelope.frame(envelope.encode_json({"filename": name})) + b"data"
    result = codec.parse_payload(payload)
    assert result.filename == "recovered.bin"
    assert result.data == b"data"


@pytest.mark.parametrize("field,value,code", [("version", 2, ErrorCode.UNSUPPORTED_VERSION), ("suite", "unknown", ErrorCode.UNSUPPORTED_SUITE)])
def test_adapter_maps_header_errors(field, value, code):
    codec = envelope.EnvelopeCodec()
    item = package()
    with pytest.raises(ShareError) as error:
        codec.build_header(replace(item.header, **{field: value}))
    assert error.value.code is code
