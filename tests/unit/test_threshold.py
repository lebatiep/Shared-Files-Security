import base64
from dataclasses import replace
import hashlib
from itertools import combinations
import json

import pytest

from secure_share.config import MAX_PACKAGE_BYTES
from secure_share.envelope import frame
from secure_share.errors import ErrorCode, ShareError
from secure_share import threshold
from secure_share.threshold import (
    Contribution,
    FIELD_BYTES,
    FIELD_PRIME,
    MAX_CONTRIBUTION_BYTES,
    SHARE_BYTES,
    ThresholdEnvelope,
    ThresholdHeader,
    ThresholdRecipient,
    build_aad,
    build_header,
    build_signature_input,
    combine_shares,
    parse_contribution,
    parse_package,
    serialize_contribution,
    serialize_package,
    share_commitment,
    share_index,
    split_key,
)


TRANSFER_ID = "a" * 32
SPEC_FIELD_PRIME = 2**521 - 1


@pytest.mark.parametrize("secret", [bytes(32), bytes(range(32)), b"\xff" * 32])
@pytest.mark.parametrize("slope", [0, 1, FIELD_PRIME - 1])
def test_every_distinct_pair_recovers_exact_key(secret, slope, monkeypatch):
    def sample(modulus):
        assert modulus == FIELD_PRIME
        return slope

    monkeypatch.setattr(threshold.secrets, "randbelow", sample)
    shares = split_key(secret)
    assert tuple(share_index(share) for share in shares) == (1, 2, 3)
    assert all(len(share) == SHARE_BYTES == 67 for share in shares)
    for left, right in combinations(shares, 2):
        assert combine_shares((left, right)) == secret
        assert combine_shares([right, left]) == secret


@pytest.mark.parametrize(
    ("slope", "expected_values"),
    [
        pytest.param(3, (8, 11, 14), id="ordinary"),
        pytest.param(SPEC_FIELD_PRIME - 2, (3, 1, SPEC_FIELD_PRIME - 1), id="modular-wraparound"),
    ],
)
def test_shamir_matches_hand_calculated_points(slope, expected_values, monkeypatch):
    # For s = 5, f(x) = 5 + 3x gives 8, 11 and 14.
    # With a = p - 2, f(x) ≡ 5 - 2x mod p, giving 3, 1 and p - 1.
    # For x = 1 and x = 3, the interpolation numerator 3*y1 - y3
    # is 10 mod p in both cases. Multiplying by the inverse (p + 1)/2 gives 5.
    def sample(modulus):
        assert modulus == SPEC_FIELD_PRIME
        return slope

    monkeypatch.setattr(threshold.secrets, "randbelow", sample)
    key = bytes(31) + b"\x05"
    expected_shares = tuple(
        bytes([index]) + value.to_bytes(66, "big")
        for index, value in enumerate(expected_values, start=1)
    )

    assert split_key(key) == expected_shares
    for pair in combinations(expected_shares, 2):
        assert combine_shares(pair) == key
        assert combine_shares(pair[::-1]) == key


@pytest.mark.parametrize("value", [b"", bytes(31), bytes(33), bytearray(32), "a" * 32])
def test_split_rejects_non_aes256_key(value):
    with pytest.raises(ShareError) as error:
        split_key(value)
    assert error.value.code is ErrorCode.INVALID_SHARE


def _point(index, value):
    return bytes([index]) + value.to_bytes(FIELD_BYTES, "big")


@pytest.mark.parametrize(
    "shares",
    [
        (),
        (_point(1, 7),),
        (_point(1, 7), _point(2, 9), _point(3, 11)),
        (_point(1, 7), _point(1, 9)),
        (_point(0, 7), _point(2, 9)),
        (_point(4, 7), _point(2, 9)),
        (_point(1, FIELD_PRIME), _point(2, 9)),
        (_point(1, 7)[:-1], _point(2, 9)),
        (_point(1, 1 << 256), _point(2, 1 << 256)),
    ],
)
def test_combine_rejects_bad_count_index_value_and_result(shares):
    with pytest.raises(ShareError) as error:
        combine_shares(shares)
    assert error.value.code is ErrorCode.INVALID_SHARE


def test_commitment_binds_domain_transfer_index_and_value():
    share = _point(1, 7)
    expected = hashlib.sha256(b"SFILE2-SHARE" + frame(bytes.fromhex(TRANSFER_ID)) + frame(share)).hexdigest()
    assert share_commitment(TRANSFER_ID, share) == expected
    assert share_commitment("b" * 32, share) != expected
    assert share_commitment(TRANSFER_ID, _point(2, 7)) != expected
    assert share_commitment(TRANSFER_ID, _point(1, 8)) != expected


@pytest.fixture
def envelope():
    recipients = tuple(ThresholdRecipient(char * 64, "d" * 64) for char in "123")
    header = ThresholdHeader(TRANSFER_ID, "b" * 64, recipients)
    return ThresholdEnvelope(
        header, build_header(header), (b"1" * 384, b"2" * 384, b"3" * 384),
        bytes(12), bytes(16), bytes(384),
    )


def test_package_retains_raw_header_and_wrap_order(envelope):
    formatted = json.dumps(json.loads(envelope.header_bytes), indent=2, sort_keys=True).encode()
    original = replace(envelope, header_bytes=formatted)
    data = serialize_package(original)

    assert parse_package(data) == original
    assert serialize_package(parse_package(data)) == data
    framed = frame(formatted) + b"".join(frame(wrapped) for wrapped in envelope.wrapped_shares)
    assert build_aad(formatted, original.wrapped_shares) == b"SFILE2-AAD" + framed
    assert build_signature_input(formatted, original.wrapped_shares, original.nonce, original.ciphertext) == (
        b"SFILE2-SIGN" + framed + frame(original.nonce) + frame(original.ciphertext)
    )
    assert build_aad(formatted, original.wrapped_shares[::-1]) != build_aad(formatted, original.wrapped_shares)


def test_serialize_rejects_header_model_mismatch(envelope):
    different_header = replace(envelope.header, transfer_id="f" * 32)
    with pytest.raises(ShareError) as error:
        serialize_package(replace(envelope, header=different_header))
    assert error.value.code is ErrorCode.INVALID_SCHEMA


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("version", True, ErrorCode.UNSUPPORTED_VERSION),
        ("version", 1, ErrorCode.UNSUPPORTED_VERSION),
        ("suite", "A256GCM_RSA3072OAEP256_PSS256", ErrorCode.UNSUPPORTED_SUITE),
        ("transfer_id", "A" * 32, ErrorCode.INVALID_SCHEMA),
        ("sender_sig_fp", "a" * 63, ErrorCode.INVALID_SCHEMA),
        ("recipients", [], ErrorCode.INVALID_SCHEMA),
        ("recipients", [None] * 3, ErrorCode.INVALID_SCHEMA),
        ("recipients", [{"fingerprint": "a" * 64, "commitment": "b" * 64}] * 3, ErrorCode.INVALID_SCHEMA),
    ],
)
def test_package_rejects_invalid_threshold_header(envelope, field, value, expected):
    data = json.loads(serialize_package(envelope))
    header = json.loads(envelope.header_bytes)
    header[field] = value
    data["header_b64"] = base64.b64encode(json.dumps(header).encode()).decode()

    with pytest.raises(ShareError) as error:
        parse_package(json.dumps(data).encode())
    assert error.value.code is expected


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("wrapped_key_b64", "", ErrorCode.INVALID_SCHEMA),
        ("wrapped_shares_b64", [""] * 2, ErrorCode.INVALID_SCHEMA),
        ("wrapped_shares_b64", [""] * 3, ErrorCode.INVALID_LENGTH),
        ("nonce_b64", "%%%%", ErrorCode.INVALID_BASE64),
        ("ciphertext_b64", "A" * 21 + "B==", ErrorCode.INVALID_BASE64),
        ("signature_b64", "AAAA", ErrorCode.INVALID_LENGTH),
    ],
)
def test_package_rejects_wrong_fields_or_noncanonical_base64(envelope, field, value, expected):
    obj = json.loads(serialize_package(envelope))
    obj[field] = value

    with pytest.raises(ShareError) as error:
        parse_package(json.dumps(obj).encode())
    assert error.value.code is expected


def test_package_rejects_duplicate_keys_and_oversized_input(envelope):
    duplicate = b'{"nonce_b64":"",' + serialize_package(envelope)[1:]
    with pytest.raises(ShareError) as error:
        parse_package(duplicate)
    assert error.value.code is ErrorCode.INVALID_JSON
    with pytest.raises(ShareError) as error:
        parse_package(b" " * (MAX_PACKAGE_BYTES + 1))
    assert error.value.code is ErrorCode.INPUT_TOO_LARGE


@pytest.fixture
def contribution():
    return Contribution("1" * 64, "2" * 64, "3" * 64, bytes(384))


def test_contribution_is_a_distinct_bounded_wire_format(contribution):
    raw = serialize_contribution(contribution)
    assert len(raw) <= MAX_CONTRIBUTION_BYTES
    assert parse_contribution(raw) == contribution
    assert set(json.loads(raw)) == {"format", "version", "package_id", "source_fp", "target_fp", "wrapped_share_b64"}


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("source_fp", "3" * 64, ErrorCode.INVALID_SCHEMA),
        ("package_id", "C" * 64, ErrorCode.INVALID_SCHEMA),
        ("version", 1, ErrorCode.UNSUPPORTED_VERSION),
        ("wrapped_share_b64", "AAAA", ErrorCode.INVALID_LENGTH),
        ("share", "raw", ErrorCode.INVALID_SCHEMA),
    ],
)
def test_contribution_rejects_invalid_fields(contribution, field, value, expected):
    obj = json.loads(serialize_contribution(contribution))
    obj[field] = value

    with pytest.raises(ShareError) as error:
        parse_contribution(json.dumps(obj).encode())
    assert error.value.code is expected


def test_contribution_rejects_oversize_before_decoding():
    with pytest.raises(ShareError) as error:
        parse_contribution(b" " * (MAX_CONTRIBUTION_BYTES + 1))
    assert error.value.code is ErrorCode.INPUT_TOO_LARGE
