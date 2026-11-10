import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import time

import pytest

from secure_share.application import create_application
from secure_share.config import MAX_FILE_BYTES
from secure_share.crypto_ops import CryptoOps
from secure_share.envelope import EnvelopeCodec, encode_json
from secure_share.errors import ErrorCode, ShareError
from secure_share.models import KeyRole, OperationStatus, ReceiveRequest, SendRequest, TrustStatus, WarningCode
from secure_share.storage import LocalStorage

PASSWORD = b'demo-password-only-123'


def trust(app, owner, contact):
    app.trust.import_contact(owner, contact, app.keys.public_bundle(contact))
    profile = app.keys.get_profile(contact)
    app.trust.verify_contact(owner, contact, profile.encryption_fingerprint, profile.signing_fingerprint)


@pytest.fixture(scope='module')
def seed(tmp_path_factory):
    root = tmp_path_factory.mktemp('profiles')
    app = create_application(root)
    for name in ('alice', 'bob', 'mallory'):
        app.keys.create_profile(name, name.title(), PASSWORD)
    for owner, contact in [('alice', 'bob'), ('bob', 'alice'), ('mallory', 'alice')]:
        trust(app, owner, contact)
    return root


@pytest.fixture
def app(seed, tmp_path):
    root = tmp_path / 'private'
    shutil.copytree(seed, root)
    instance = create_application(root)
    yield instance
    instance.service.close()


def send(app, tmp_path, data=b'Private survey\x00\xff'):
    source = tmp_path / 'Khảo sát.bin'
    source.write_bytes(data)
    package = tmp_path / 'transfer.sfile'
    result = app.service.send_file(SendRequest('alice', 'bob', source, package, PASSWORD))
    assert result.status is OperationStatus.SUCCESS, result
    return source, package


# Explicit ids: pytest puts the id in PYTEST_CURRENT_TEST, and a 10 MiB id
# exceeds the 32,767-character environment limit on Windows.
@pytest.mark.parametrize('data', [
    pytest.param(b'', marks=pytest.mark.case('S01'), id='empty'),
    pytest.param(b'a', id='one-byte'),
    pytest.param('Tiếng Việt 日本語'.encode(), id='unicode-text'),
    pytest.param(bytes(range(256)) * 10, id='binary-2560-bytes'),
    pytest.param(b'x' * MAX_FILE_BYTES, marks=pytest.mark.case('S04'), id='max-10MiB'),
])
@pytest.mark.case("S03")
@pytest.mark.case("R01")
def test_real_disk_roundtrip(app, tmp_path, data):
    source, package = send(app, tmp_path, data)
    # Reload every provider to prove persistence rather than shared in-memory keys.
    receiver = create_application(app.keys.root)
    result = receiver.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert result.status is OperationStatus.PREPARED, result
    assert result.prepared.filename == source.name
    output = tmp_path / 'restored.bin'
    saved = receiver.service.save_received(result.prepared.handle, output)
    assert saved.status is OperationStatus.SUCCESS
    assert output.read_bytes() == data
    assert not saved.warnings
    again = receiver.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert WarningCode.DUPLICATE_TRANSFER in again.warnings
    receiver.service.discard_prepared(again.prepared.handle)


@pytest.mark.case("S04")
def test_oversized_file_never_creates_package(app, tmp_path):
    source = tmp_path / 'large.bin'
    source.write_bytes(b'x' * (MAX_FILE_BYTES + 1))
    output = tmp_path / 'out.sfile'
    result = app.service.send_file(SendRequest('alice', 'bob', source, output, PASSWORD))
    assert result.error.code is ErrorCode.INPUT_TOO_LARGE
    assert not output.exists()


@pytest.mark.parametrize('profile,password,code', [
    pytest.param('mallory', PASSWORD, ErrorCode.RECIPIENT_KEY_NOT_FOUND, marks=pytest.mark.case('A06'), id='wrong-recipient'),
    pytest.param('bob', b'wrong', ErrorCode.KEY_UNLOCK_FAILED, marks=pytest.mark.case('I07'), id='wrong-passphrase'),
])
def test_wrong_recipient_or_password(app, tmp_path, profile, password, code):
    _, package = send(app, tmp_path)
    result = app.service.prepare_receive(ReceiveRequest(profile, package, password))
    assert result.error.code is code
    assert not app.service.has_prepared


@pytest.mark.parametrize('field', [
    pytest.param(field, marks=pytest.mark.case('A02' if field == 'signature_b64' else 'A03'))
    for field in EnvelopeCodec.fields
])
def test_each_authenticated_component_rejects_tampering(app, tmp_path, field):
    _, package = send(app, tmp_path)
    obj = json.loads(package.read_bytes())
    raw = bytearray(base64.b64decode(obj[field]))
    if field == 'header_b64':
        header = json.loads(raw)
        original = header['transfer_id']
        header['transfer_id'] = ('1' if original[0] == '0' else '0') + original[1:]
        raw = encode_json(header)
    else:
        raw[-1] ^= 1
    obj[field] = base64.b64encode(raw).decode()
    package.write_bytes(encode_json(obj))
    result = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert result.error.code is ErrorCode.SIGNATURE_INVALID
    assert not app.service.has_prepared


@pytest.mark.parametrize('field,expected', [
    pytest.param('wrapped_key', ErrorCode.UNWRAP_FAILED, marks=pytest.mark.case('A07'), id='invalid-oaep'),
    pytest.param('ciphertext', ErrorCode.GCM_AUTH_FAILED, marks=pytest.mark.case('A09'), id='invalid-gcm-tag'),
])
def test_signed_but_invalid_crypto_is_rejected(app, tmp_path, field, expected):
    _, package = send(app, tmp_path)
    codec, crypto = EnvelopeCodec(), CryptoOps()
    envelope = codec.parse_envelope(package.read_bytes())
    raw = bytearray(getattr(envelope, field))
    raw[-1] ^= 1
    envelope = replace(envelope, **{field: bytes(raw)})
    signing = app.keys.unlock_private_key('alice', KeyRole.SIGNING, envelope.header.sender_sig_fp, PASSWORD)
    signature = crypto.sign_package(codec.build_signature_input(envelope.header_bytes, envelope.wrapped_key, envelope.nonce, envelope.ciphertext), signing)
    package.write_bytes(codec.serialize_envelope(replace(envelope, signature=signature)))
    result = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert result.error.code is expected
    assert not app.service.has_prepared


@pytest.mark.case("S06")
@pytest.mark.case("L02")
def test_unverified_and_disabled_contacts_are_not_usable(app, tmp_path):
    app.trust.import_contact('alice', 'mallory', app.keys.public_bundle('mallory'))
    with pytest.raises(ShareError):
        app.trust.resolve_recipient('alice', 'mallory')
    with pytest.raises(ShareError):
        app.trust.verify_contact('alice', 'mallory', '0' * 64, '0' * 64)
    app.trust.disable_contact('alice', 'bob')
    source = tmp_path / 'input.txt'
    source.write_text('hello')
    result = app.service.send_file(SendRequest('alice', 'bob', source, tmp_path / 'out.sfile', PASSWORD))
    assert result.error.code is ErrorCode.UNTRUSTED_RECIPIENT


@pytest.mark.case("A01")
def test_untrusted_sender_is_rejected_before_password(app, tmp_path):
    _, package = send(app, tmp_path)
    app.trust.disable_contact('bob', 'alice')
    result = app.service.prepare_receive(ReceiveRequest('bob', package, b'wrong'))
    assert result.error.code is ErrorCode.UNTRUSTED_SENDER


@pytest.mark.case("I06")
def test_key_replacement_requires_new_verification(app):
    with pytest.raises(ShareError) as error:
        app.trust.import_contact('alice', 'bob', app.keys.public_bundle('mallory'))
    assert error.value.code is ErrorCode.DESTINATION_EXISTS
    contact = app.trust.import_contact('alice', 'bob', app.keys.public_bundle('mallory'), replace=True)
    assert contact.status is TrustStatus.UNVERIFIED


@pytest.mark.case("L01")
def test_rotation_retains_old_decryption_keys(app, tmp_path):
    _, package = send(app, tmp_path)
    previous = app.keys.get_profile('bob')
    current = app.keys.rotate_keys('bob', PASSWORD)
    assert previous.encryption_fingerprint != current.encryption_fingerprint
    result = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert result.status is OperationStatus.PREPARED
    app.service.discard_prepared(result.prepared.handle)


def test_private_keys_are_encrypted_and_exports_public_only(app):
    data = (app.keys.profiles / 'alice.json').read_bytes()
    assert b'BEGIN ENCRYPTED PRIVATE KEY' in data
    assert b'BEGIN PRIVATE KEY' not in data
    assert PASSWORD not in data
    exported = app.keys.public_bundle('alice')
    assert b'PRIVATE' not in exported
    assert PASSWORD not in exported


@pytest.mark.case("L03")
def test_backup_restore_validates_password_and_keeps_fingerprints(app, tmp_path):
    backup = app.keys.backup_profile('bob', PASSWORD)
    assert PASSWORD not in backup
    restored = create_application(tmp_path / 'new-machine')
    with pytest.raises(ShareError):
        restored.keys.restore_profile(backup, b'wrong')
    assert restored.keys.list_profiles() == []
    profile = restored.keys.restore_profile(backup, PASSWORD)
    assert profile == app.keys.get_profile('bob')
    assert restored.trust.list_contacts('bob') == []
    with pytest.raises(ShareError) as error:
        restored.keys.restore_profile(backup, PASSWORD)
    assert error.value.code is ErrorCode.DESTINATION_EXISTS


@pytest.mark.parametrize('profile', ['../alice', 'Alice', 'a/b', 'con', 'nul', '', 'a:b', 'a.' ])
def test_profile_identifiers_cannot_escape_store(app, profile):
    with pytest.raises(ShareError):
        app.keys.create_profile(profile, 'Name', PASSWORD)


@pytest.mark.case("I02")
@pytest.mark.parametrize('password', [b'', b'short', b'\xff' * 12, b'a' * 1025])
def test_bad_creation_password_leaves_no_profile(app, password):
    with pytest.raises(ShareError):
        app.keys.create_profile('new', 'New', password)
    assert not (app.keys.profiles / 'new.json').exists()


@pytest.mark.case("I09")
@pytest.mark.case("I10")
@pytest.mark.parametrize('change', ['same_key', 'small_rsa', 'ec_key', 'garbage', 'duplicate_json', 'extra_field'])
def test_invalid_public_bundles_are_never_imported(app, change):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    obj = json.loads(app.keys.public_bundle('bob'))
    if change == 'same_key':
        obj['signing_public_key'] = obj['encryption_public_key']
    elif change in ('small_rsa', 'ec_key'):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048) if change == 'small_rsa' else ec.generate_private_key(ec.SECP256R1())
        obj['encryption_public_key'] = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    elif change == 'garbage':
        obj['encryption_public_key'] = 'not a key'
    elif change == 'extra_field':
        obj['trusted'] = True
    data = encode_json(obj)
    if change == 'duplicate_json':
        data = b'{"version":1,' + data[1:]
    with pytest.raises(ShareError):
        app.trust.import_contact('alice', 'new', data)
    assert not (app.keys.root / 'contacts' / 'alice' / 'new.json').exists()


@pytest.mark.case("R02")
@pytest.mark.case("R03")
def test_outer_formatting_and_package_filename_do_not_change_signature(app, tmp_path):
    _, package = send(app, tmp_path)
    renamed = tmp_path / 'other-name.sfile'
    renamed.write_text(json.dumps(json.loads(package.read_bytes()), indent=4, sort_keys=True), encoding='utf-8')
    result = app.service.prepare_receive(ReceiveRequest('bob', renamed, PASSWORD))
    assert result.status is OperationStatus.PREPARED
    app.service.discard_prepared(result.prepared.handle)


@pytest.mark.case("S08")
def test_repeated_send_uses_fresh_randomness(app, tmp_path):
    source, package = send(app, tmp_path)
    second = tmp_path / 'second.sfile'
    sent = app.service.send_file(SendRequest('alice', 'bob', source, second, PASSWORD))
    assert sent.status is OperationStatus.SUCCESS
    a, b = (EnvelopeCodec().parse_envelope(path.read_bytes()) for path in (package, second))
    assert a.header.transfer_id != b.header.transfer_id
    assert a.nonce != b.nonce
    assert a.wrapped_key != b.wrapped_key
    assert a.ciphertext != b.ciphertext


@pytest.mark.case("R07")
def test_cancel_prepared_does_not_write_plaintext(app, tmp_path):
    _, package = send(app, tmp_path)
    before = set(tmp_path.iterdir())
    prepared = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD)).prepared
    assert app.service.discard_prepared(prepared.handle).status is OperationStatus.CANCELLED
    assert set(tmp_path.iterdir()) == before
    assert not app.service.has_prepared


@pytest.mark.case("A11")
@pytest.mark.parametrize('data', [b'', b'\x00\x00\x10\x01', b'\x00\x00\x00\x0a{}', b'\x00\x00\x00\x02[]'])
def test_payload_framing_errors(data):
    with pytest.raises(ShareError):
        EnvelopeCodec().parse_payload(data)


@pytest.mark.case("R06")
@pytest.mark.case("O02")
@pytest.mark.case("O03")
def test_protected_path_and_retry_after_failed_save(app, tmp_path):
    _, package = send(app, tmp_path)
    prepared = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD)).prepared
    original = (app.keys.profiles / 'bob.json').read_bytes()
    result = app.service.save_received(prepared.handle, app.keys.profiles / 'bob.json', overwrite_confirmed=True)
    assert result.error.code is ErrorCode.PROTECTED_PATH
    assert app.service.has_prepared
    assert (app.keys.profiles / 'bob.json').read_bytes() == original
    output = tmp_path / 'result'
    output.write_bytes(b'existing')
    result = app.service.save_received(prepared.handle, output)
    assert result.error.code is ErrorCode.DESTINATION_EXISTS
    assert output.read_bytes() == b'existing'
    assert app.service.save_received(prepared.handle, output, overwrite_confirmed=True).status is OperationStatus.SUCCESS
    assert app.service.save_received(prepared.handle, output).error.code is ErrorCode.INVALID_HANDLE


def test_history_failure_does_not_undo_saved_file(app, tmp_path):
    _, package = send(app, tmp_path)
    (app.keys.root / 'history' / 'bob.json').write_bytes(b'invalid')
    result = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert WarningCode.HISTORY_UNAVAILABLE in result.warnings
    output = tmp_path / 'restored'
    result = app.service.save_received(result.prepared.handle, output)
    assert result.status is OperationStatus.SUCCESS
    assert WarningCode.HISTORY_NOT_SAVED in result.warnings
    assert output.exists()


@pytest.mark.parametrize('name', [
    pytest.param('../outside', marks=pytest.mark.case('R04')),
    pytest.param('..\\outside', marks=pytest.mark.case('R04')),
    pytest.param('C:\\outside', marks=pytest.mark.case('R04')),
    pytest.param('file:stream', marks=pytest.mark.case('R04')),
    *[pytest.param(name, marks=pytest.mark.case('R05')) for name in
      ('CON', 'NUL.txt', 'COM1', 'COM¹.txt', 'trailing.', 'trailing ', '\x00', '\n', '', 'a' * 256)],
])
def test_authenticated_unsafe_filename_gets_safe_save_suggestion(app, tmp_path, name):
    source, package = send(app, tmp_path)
    codec, crypto = EnvelopeCodec(), CryptoOps()
    envelope = codec.parse_envelope(package.read_bytes())
    receiving_key = app.keys.unlock_private_key('bob', KeyRole.ENCRYPTION, envelope.header.recipient_enc_fp, PASSWORD)
    signing_key = app.keys.unlock_private_key('alice', KeyRole.SIGNING, envelope.header.sender_sig_fp, PASSWORD)
    key = crypto.unwrap_key(envelope.wrapped_key, receiving_key)
    nonce = crypto.generate_nonce()
    metadata = encode_json({'filename': name})
    payload = len(metadata).to_bytes(4, 'big') + metadata + source.read_bytes()
    aad = codec.build_aad(envelope.header_bytes, envelope.wrapped_key)
    ciphertext = crypto.encrypt_payload(key, nonce, payload, aad)
    message = codec.build_signature_input(envelope.header_bytes, envelope.wrapped_key, nonce, ciphertext)
    signature = crypto.sign_package(message, signing_key)
    package.write_bytes(codec.serialize_envelope(replace(envelope, nonce=nonce, ciphertext=ciphertext, signature=signature)))

    received = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD))
    assert received.status is OperationStatus.PREPARED
    assert received.prepared.filename == 'recovered.bin'
    assert not (tmp_path / 'recovered.bin').exists()
    output = tmp_path / 'chosen.bin'
    saved = app.service.save_received(received.prepared.handle, output)
    assert saved.status is OperationStatus.SUCCESS
    assert output.read_bytes() == source.read_bytes()


@pytest.mark.case("P01")
@pytest.mark.parametrize('data', [b'{}', b'[]', b'null', b'{', b'\xff', b'{"a":1,"a":2}', b'{"a":NaN}', b'[' * 2000])
def test_malformed_envelopes(data):
    with pytest.raises(ShareError):
        EnvelopeCodec().parse_envelope(data)


@pytest.mark.parametrize('mutation', ['extra', 'missing', 'whitespace_base64', 'short_nonce', 'bool_version', 'unknown_suite', 'unknown_version', 'duplicate_header', 'header_mismatch'])
def test_strict_envelope_schema(app, tmp_path, mutation):
    _, package = send(app, tmp_path)
    obj = json.loads(package.read_bytes())
    if mutation == 'extra':
        obj['extra'] = ''
    elif mutation == 'missing':
        obj.pop('signature_b64')
    elif mutation == 'whitespace_base64':
        obj['nonce_b64'] += '\n'
    elif mutation == 'short_nonce':
        obj['nonce_b64'] = base64.b64encode(b'123').decode()
    else:
        header = json.loads(base64.b64decode(obj['header_b64']))
        if mutation == 'bool_version':
            header['version'] = True
        elif mutation == 'unknown_suite':
            header['suite'] = 'unknown'
        elif mutation == 'unknown_version':
            header['version'] = 2
        elif mutation == 'header_mismatch':
            header['sender_sig_fp'] = 'g' * 64
        raw = encode_json(header)
        if mutation == 'duplicate_header':
            raw = b'{"version":1,' + raw[1:]
        obj['header_b64'] = base64.b64encode(raw).decode()
    with pytest.raises(ShareError):
        EnvelopeCodec().parse_envelope(encode_json(obj))


@pytest.mark.case("O03")
def test_storage_no_clobber_race(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    publish_new = LocalStorage._publish_new
    def race(source, destination):
        Path(destination).write_bytes(b'other writer')
        publish_new(source, destination)
    monkeypatch.setattr(LocalStorage, '_publish_new', staticmethod(race))
    with pytest.raises(ShareError) as error:
        LocalStorage().save_atomic(b'new data', output)
    assert error.value.code is ErrorCode.DESTINATION_EXISTS
    assert output.read_bytes() == b'other writer'
    assert not list(tmp_path.glob('.sfile-*'))


@pytest.mark.case("O05")
def test_storage_failure_preserves_existing_file(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    output.write_bytes(b'old')
    def fail(*args):
        raise OSError
    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(ShareError):
        LocalStorage().save_atomic(b'new', output, overwrite_confirmed=True)
    assert output.read_bytes() == b'old'
    assert not list(tmp_path.glob('.sfile-*'))


@pytest.mark.case("O02")
def test_hardlink_alias_to_private_key_is_protected(app, tmp_path):
    source = app.keys.profiles / 'bob.json'
    alias = tmp_path / 'alias'
    os.link(source, alias)
    with pytest.raises(ShareError) as error:
        app.storage.save_atomic(b'overwrite', alias, overwrite_confirmed=True, protected_paths=app.keys.protected_paths('bob'))
    assert error.value.code is ErrorCode.PROTECTED_PATH


@pytest.mark.case("R01")
def test_tk_send_and_receive_with_real_workers(app, tmp_path, monkeypatch):
    import tkinter as tk
    from secure_share.ui import app as ui
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip('Tk display is not available')
    root.withdraw()
    window = ui.App(root, app)
    errors = []
    monkeypatch.setattr(ui.messagebox, 'showerror', lambda *args, **kwargs: errors.append(args))
    monkeypatch.setattr(ui.messagebox, 'askyesno', lambda *args, **kwargs: True)
    monkeypatch.setattr(ui.messagebox, 'showwarning', lambda *args, **kwargs: None)
    monkeypatch.setattr(window, 'password', lambda **kwargs: PASSWORD)
    source, package, output = tmp_path / 'test.txt', tmp_path / 'ui.sfile', tmp_path / 'restored.txt'
    source.write_bytes(b'Tk real crypto roundtrip')
    paths = iter([str(source), str(package)])
    destinations = iter([str(package), str(output)])
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', lambda **kwargs: next(paths))
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', lambda **kwargs: next(destinations))
    def wait():
        deadline = time.monotonic() + 15
        while window.busy and time.monotonic() < deadline:
            root.update()
            time.sleep(.01)
        assert not window.busy
    try:
        window.profile.set('alice')
        window.refresh_contacts()
        window.contact.set('bob')
        window.send()
        wait()
        assert package.exists(), errors
        window.profile.set('bob')
        window.refresh_contacts()
        window.receive()
        wait()
        assert output.read_bytes() == source.read_bytes(), errors
        assert not errors
    finally:
        window.close()


def _zip_bytes():
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('inside.txt', 'archive member')
    return buffer.getvalue()


@pytest.mark.case('P08')
@pytest.mark.parametrize('data', [_zip_bytes(), b'@echo off\r\necho should never run\r\n', b'MZ\x90\x00 pretend executable'],
                         ids=['zip-archive', 'batch-script', 'executable-header'])
def test_executable_looking_content_is_saved_as_plain_bytes(app, tmp_path, data):
    _, package = send(app, tmp_path, data)
    prepared = app.service.prepare_receive(ReceiveRequest('bob', package, PASSWORD)).prepared
    before = {path.name for path in tmp_path.iterdir()}
    output = tmp_path / 'restored.bin'
    assert app.service.save_received(prepared.handle, output).status is OperationStatus.SUCCESS
    assert output.read_bytes() == data
    # Nothing was extracted, executed or opened: only the chosen output appeared.
    assert {path.name for path in tmp_path.iterdir()} == before | {'restored.bin'}
