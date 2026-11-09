"""Run with: python -m tools.make_fixtures --out DIR

Builds test packages that stop at a chosen layer, plus manifest.json that records
the replaced field, the expected stopping layer and the SHA-256 of every package.

Deep faults (UNWRAP, GCM, PAYLOAD) are re-signed with the TEST signing key, so the
signature check passes and the receiver reaches the inner layer. That is a test
fixture made by the tester. It is not a forged signature by someone without the key.
Keys come from tests.rsa_fixtures (public, test-only); never use them for real data.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from secure_share import envelope as env
from secure_share.crypto_ops import (
    AESKeyLengthError, decrypt_payload, encrypt_payload, mgf1, sha256, sign_package,
    unwrap_key, verify_signature, wrap_key, xor_bytes)
from tests.rsa_fixtures import D as ENC_D, N as ENC_N, SIGN_D, SIGN_N

KEY, NONCE = bytes(range(32)), bytes(range(12))
SENDER_FP = sha256(SIGN_N.to_bytes(384, 'big')).hex()
RECIPIENT_FP = sha256(ENC_N.to_bytes(384, 'big')).hex()
OUTER = ('header_b64', 'wrapped_key_b64', 'nonce_b64', 'ciphertext_b64', 'signature_b64')


def classify(blob):
    """Receive pipeline up to the payload; returns the layer where the package stops."""
    try:
        parts = env.parse_envelope(blob)
        env.parse_header(parts.header_raw)
    except env.EnvelopeError:
        return 'PARSE'
    message = env.build_signature_input(parts.header_raw, parts.wrapped_key, parts.nonce, parts.ciphertext)
    if not verify_signature(message, parts.signature, SIGN_N):
        return 'SIGNATURE'
    try:
        key = unwrap_key(parts.wrapped_key, ENC_N, ENC_D)
    except AESKeyLengthError:
        return 'UNWRAP_KEY_LENGTH'
    except ValueError:
        return 'UNWRAP'
    try:
        payload = decrypt_payload(parts.ciphertext, key, parts.nonce, env.build_aad(parts.header_raw, parts.wrapped_key))
    except ValueError:
        return 'GCM'
    try:
        env.parse_payload(payload)
    except env.EnvelopeError:
        return 'PAYLOAD'
    return 'OK'


def _header(transfer_id='00112233445566778899aabbccddeeff'):
    return env.build_header(transfer_id, SENDER_FP, RECIPIENT_FP)


def _wrap_raw(secret):
    """OAEP-encode a secret of any length; wrap_key only accepts exactly 32 bytes."""
    block = sha256(b'') + bytes(384 - len(secret) - 66) + b'\x01' + secret
    masked = xor_bytes(block, mgf1(bytes(32), len(block)))
    em = b'\x00' + xor_bytes(bytes(32), mgf1(masked, 32)) + masked
    return pow(int.from_bytes(em, 'big'), 65537, ENC_N).to_bytes(384, 'big')


def _seal(payload, wrapped=None, key=KEY, aad_wrapped=None, header=None):
    """Valid package around `payload`; every inner part can be overridden and is re-signed."""
    header = header or _header()
    wrapped = wrapped or wrap_key(key, ENC_N)
    aad = env.build_aad(header, aad_wrapped or wrapped)
    ciphertext = encrypt_payload(payload, key, NONCE, aad)
    return _sign(env.RawEnvelope(header, wrapped, NONCE, ciphertext, bytes(384)))


def _sign(parts):
    message = env.build_signature_input(parts.header_raw, parts.wrapped_key, parts.nonce, parts.ciphertext)
    return parts._replace(signature=sign_package(message, SIGN_N, SIGN_D))


def _flip(data, index=-1):
    raw = bytearray(data)
    raw[index] ^= 1
    return bytes(raw)


def _outer(parts, **changes):
    fields = dict(zip(OUTER, (base64.b64encode(p).decode() for p in parts)))
    fields.update(changes)
    return json.dumps(fields, separators=(',', ':')).encode()


def build_cases():
    """Return [(file name, case id, bytes, replaced field, expected layer, note)]."""
    good_payload = env.build_payload('report.txt', b'fixture content')
    good = _seal(good_payload)
    other = _seal(env.build_payload('other.txt', b'second package'), header=_header('ffeeddccbbaa99887766554433221100'))
    cases = [('good.sfile', 'R01', env.serialize_envelope(good), '-', 'OK', 'valid package')]

    def add(name, case, parts, field, expected, note):
        cases.append((name, case, env.serialize_envelope(parts), field, expected, note))

    add('a02_flip_signature.sfile', 'A02', good._replace(signature=_flip(good.signature)), 'S', 'SIGNATURE', 'one bit of S flipped')
    # A03: H keeps a valid schema (a hex digit of transfer_id changes), so it reaches the signature check.
    changed_header = good.header_raw.replace(b'"transfer_id":"0', b'"transfer_id":"1', 1)
    assert changed_header != good.header_raw
    for field, label, value in (('header_raw', 'H', changed_header), ('wrapped_key', 'W', _flip(good.wrapped_key)),
                                ('nonce', 'N', _flip(good.nonce)), ('ciphertext', 'C', _flip(good.ciphertext))):
        add(f'a03_flip_{label.lower()}.sfile', 'A03', good._replace(**{field: value}),
            label, 'SIGNATURE', 'protected field changed, not re-signed')
    add('a05_splice_ciphertext.sfile', 'A05', good._replace(ciphertext=other.ciphertext), 'C', 'SIGNATURE', 'C taken from another valid package')

    seal = lambda **kw: _seal(good_payload, **kw)
    add('a07_random_wrapped_key.sfile', 'A07', _sign(good._replace(wrapped_key=bytes(range(1, 255)) + bytes(130))), 'W', 'UNWRAP', 'W is not an OAEP block; re-signed with test key')
    for size in (31, 33):
        add(f'a08_aes_key_{size}_bytes.sfile', 'A08', seal(wrapped=_wrap_raw(bytes(size))), 'W', 'UNWRAP_KEY_LENGTH', f'valid OAEP carrying a {size}-byte key; re-signed')
    add('a09_gcm_tag.sfile', 'A09', _sign(good._replace(ciphertext=_flip(good.ciphertext))), 'C', 'GCM', 'tag changed; re-signed with test key')
    add('a10_wrong_aad.sfile', 'A10', _seal(good_payload, aad_wrapped=bytes(384)), 'AAD', 'GCM', 'encrypted under different AAD; re-signed')
    for name, payload, note in (
            ('a11_payload_short.sfile', b'\x00\x00', 'payload shorter than 4 bytes'),
            ('a11_meta_len_over_cap.sfile', (env.MAX_METADATA + 1).to_bytes(4, 'big') + bytes(5000), 'meta_len above 4096'),
            ('a11_meta_len_over_rest.sfile', (99).to_bytes(4, 'big') + b'{}', 'meta_len beyond the data')):
        add(name, 'A11', _seal(payload), 'P', 'PAYLOAD', note)
    for name, meta, note in (
            ('a12_no_filename.sfile', b'{}', 'metadata without filename'),
            ('a12_extra_key.sfile', b'{"filename":"x","a":1}', 'extra metadata key'),
            ('a12_duplicate_key.sfile', b'{"filename":"x","filename":"y"}', 'duplicate metadata key'),
            ('a12_filename_not_text.sfile', b'{"filename":42}', 'filename is not a string')):
        add(name, 'A12', _seal(len(meta).to_bytes(4, 'big') + meta), 'P', 'PAYLOAD', note)

    raw = lambda name, case, data, field, note: cases.append((name, case, data, field, 'PARSE', note))
    ok_json = outer = _outer(good)
    raw('p01_not_json.sfile', 'P01', b'%PDF-1.7 not a package', 'outer', 'plain document')
    raw('p01_two_documents.sfile', 'P01', ok_json + ok_json, 'outer', 'two JSON documents')
    raw('p02_missing_field.sfile', 'P02', json.dumps({k: v for k, v in json.loads(ok_json).items() if k != 'nonce_b64'}).encode(), 'outer', 'nonce_b64 missing')
    raw('p02_extra_field.sfile', 'P02', _outer(good, extra='x'), 'outer', 'unknown field')
    raw('p02_duplicate_field.sfile', 'P02', ok_json.replace(b'}', b',"nonce_b64":"AAAAAAAAAAAAAAAA"}'), 'outer', 'nonce_b64 twice')
    raw('p03_bad_base64.sfile', 'P03', _outer(good, nonce_b64='!' * 16), 'outer', 'characters outside the alphabet')
    raw('p04_version_2.sfile', 'P04', env.serialize_envelope(good._replace(
        header_raw=json.dumps({**json.loads(good.header_raw), 'version': 2}, separators=(',', ':')).encode())), 'H', 'unsupported version')
    raw('p06_wrapped_key_383.sfile', 'P06', _outer(good, wrapped_key_b64=base64.b64encode(bytes(383)).decode()), 'W', 'W shorter than 384')
    raw('p06_nonce_11.sfile', 'P06', _outer(good, nonce_b64=base64.b64encode(bytes(11)).decode()), 'N', 'N shorter than 12')
    return cases


def write_cases(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, case, data, field, expected, note in build_cases():
        (out / name).write_bytes(data)
        manifest.append({'file': name, 'case': case, 'replaced': field, 'expected_stop': expected,
                         'note': note, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, help='empty or new directory for the fixtures')
    args = parser.parse_args(argv)
    manifest = write_cases(args.out)
    print(f'{len(manifest)} fixtures written to {args.out}')


if __name__ == '__main__':
    main()
