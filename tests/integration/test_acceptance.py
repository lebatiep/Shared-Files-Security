"""Acceptance variants using only synthetic content and temporary test profiles."""

import base64
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import shutil
import struct
from types import SimpleNamespace
import zipfile
import zlib

import pytest

from secure_share.application import create_application
from secure_share.config import MAX_FILE_BYTES
from secure_share.crypto_ops import CryptoOps
from secure_share.envelope import EnvelopeCodec, encode_json
from secure_share.errors import ErrorCode
from secure_share.models import OperationStatus, ProcessingStage, ReceiveRequest, SendRequest
from tests.integration.test_desktop_app import PASSWORD, app, seed


def _send(app, tmp_path, data, *, name="source.bin", recipient="bob"):
    source = tmp_path / name
    source.write_bytes(data)
    package = tmp_path / "transfer.sfile"
    result = app.service.send_file(SendRequest("alice", recipient, source, package, PASSWORD))
    assert result.status is OperationStatus.SUCCESS, result
    return source, package


def _restore(app, profile, package, output):
    prepared = app.service.prepare_receive(ReceiveRequest(profile, package, PASSWORD))
    assert prepared.status is OperationStatus.PREPARED, prepared
    saved = app.service.save_received(prepared.prepared.handle, output)
    assert saved.status is OperationStatus.SUCCESS, saved
    return prepared


def _archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _pdf():
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
    ]
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n")
    xref = len(data)
    data.extend(b"xref\n0 4\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    data.extend(f"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(data)


def _docx():
    return _archive({
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Target="word/document.xml" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"/>'
            '</Relationships>'
        ),
        "word/document.xml": (
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>QA fixture</w:t></w:r></w:p></w:body></w:document>'
        ),
    })


def _png():
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"\0\x7f")) + chunk(b"IEND", b"")


@pytest.mark.case("S02")
@pytest.mark.parametrize(
    "name,make_data",
    [
        ("text.txt", lambda: "Tiếng Việt có dấu\r\n".encode("utf-8")),
        ("sample.pdf", _pdf),
        ("image.png", _png),
        ("sample.docx", _docx),
        ("archive.zip", lambda: _archive({"inside.txt": "QA fixture"})),
        ("random.bin", lambda: os.urandom(521)),
    ],
    ids=["vietnamese-txt", "pdf", "png", "docx", "zip", "random-binary"],
)
def test_file_formats_roundtrip_as_opaque_bytes(app, tmp_path, name, make_data):
    data = make_data()
    source, package = _send(app, tmp_path, data, name=name)
    output = tmp_path / f"restored-{name}"
    prepared = _restore(app, "bob", package, output)
    assert prepared.prepared.filename == name
    assert source.read_bytes() == output.read_bytes() == data
    assert set(tmp_path.iterdir()) == {source, package, output, app.keys.root}


@pytest.mark.case("S04")
def test_one_byte_below_file_cap_roundtrips(app, tmp_path):
    data = b"\x00" * (MAX_FILE_BYTES - 1)
    _, package = _send(app, tmp_path, data)
    output = tmp_path / "restored.bin"
    _restore(app, "bob", package, output)
    assert output.read_bytes() == data


@pytest.mark.case("S05")
@pytest.mark.parametrize("problem", ["vanished", "read-error", "grew-past-cap"])
def test_source_failure_creates_no_package(app, tmp_path, monkeypatch, problem):
    source = tmp_path / "selected.txt"
    original = b"selected contents"
    source.write_bytes(original)
    destination = tmp_path / "transfer.sfile"
    real_open = Path.open
    if problem == "vanished":
        source.unlink()
    else:
        @contextmanager
        def interrupted_read():
            with real_open(source, "rb") as stream:
                def read(limit):
                    assert limit == MAX_FILE_BYTES + 1
                    if problem == "read-error":
                        raise OSError("synthetic read failure")
                    # Grow the selected file after its descriptor is open.
                    with real_open(source, "r+b") as writer:
                        writer.seek(MAX_FILE_BYTES)
                        writer.write(b"!")
                    return stream.read(limit)

                yield SimpleNamespace(fileno=stream.fileno, read=read)

        def open_with_fault(path, mode="r", *args, **kwargs):
            if path == source and mode == "rb":
                return interrupted_read()
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_with_fault)

    result = app.service.send_file(SendRequest("alice", "bob", source, destination, PASSWORD))
    assert result.status is OperationStatus.FAILED
    assert result.error.stage is ProcessingStage.READ
    expected = ErrorCode.INPUT_TOO_LARGE if problem == "grew-past-cap" else ErrorCode.READ_FAILED
    assert result.error.code is expected
    assert not destination.exists()
    assert not list(tmp_path.glob(".sfile-*.tmp"))
    if problem == "vanished":
        assert not source.exists()
    else:
        with real_open(source, "rb") as stream:
            assert stream.read(len(original)) == original
        expected_size = MAX_FILE_BYTES + 1 if problem == "grew-past-cap" else len(original)
        assert source.stat().st_size == expected_size


@pytest.mark.case("S07")
@pytest.mark.parametrize(
    "variant,code",
    [("missing-private-pem", ErrorCode.PROFILE_INVALID), ("mismatched-private-pem", ErrorCode.KEY_UNLOCK_FAILED)],
)
def test_signing_key_must_exist_and_match_profile(app, tmp_path, variant, code):
    alice_path = app.keys.profiles / "alice.json"
    alice = json.loads(alice_path.read_bytes())
    signing = alice["generations"][0]["signing"]
    if variant == "missing-private-pem":
        del signing["private"]
    else:
        mallory = json.loads((app.keys.profiles / "mallory.json").read_bytes())
        signing["private"] = mallory["generations"][0]["signing"]["private"]
    tampered_profile = encode_json(alice)
    alice_path.write_bytes(tampered_profile)
    source = tmp_path / "source.txt"
    source.write_bytes(b"test document")
    output = tmp_path / "output.sfile"

    result = app.service.send_file(SendRequest("alice", "bob", source, output, PASSWORD))
    assert result.status is OperationStatus.FAILED
    assert result.error.code is code
    assert not output.exists()
    assert alice_path.read_bytes() == tampered_profile


@pytest.mark.case("O07")
@pytest.mark.parametrize("variant", ["success", "receive-error", "save-error"])
def test_runtime_artifacts_keep_secrets_out_of_ui_and_logs(app, tmp_path, monkeypatch, capsys, caplog, variant):
    from secure_share.ui import app as ui

    generated = []
    generate = CryptoOps.generate_aes_key

    def observe_key(instance):
        key = generate(instance)
        generated.append(key)
        return key

    monkeypatch.setattr(CryptoOps, "generate_aes_key", observe_key)
    messages = []
    window = ui.App.__new__(ui.App)
    window.root = None
    window.status = SimpleNamespace(set=messages.append)
    for name in ("showerror", "showwarning"):
        monkeypatch.setattr(ui.messagebox, name, lambda *args, **kwargs: messages.extend(args))
    plaintext = b"QA-SYNTHETIC-PRIVATE-CONTENT-4932720"
    source, package = _send(app, tmp_path, plaintext)
    destination = tmp_path / "recovered.bin"
    package_bytes = package.read_bytes()
    assert len(generated) == 1

    if variant == "receive-error":
        prepared = app.service.prepare_receive(ReceiveRequest("bob", package, b"qa-wrong-passphrase-8339"))
        assert prepared.error.code is ErrorCode.KEY_UNLOCK_FAILED
        result = prepared
    else:
        prepared = app.service.prepare_receive(ReceiveRequest("bob", package, PASSWORD))
        assert prepared.status is OperationStatus.PREPARED
        if variant == "save-error":
            destination = tmp_path / "missing-folder" / destination.name
        result = app.service.save_received(prepared.prepared.handle, destination)
        if variant == "save-error":
            assert result.error.code is ErrorCode.SAVE_FAILED
            app.service.discard_prepared(prepared.prepared.handle)
    window.result(result)
    assert messages

    expected_plaintext_files = {source}
    if variant == "success":
        assert result.status is OperationStatus.SUCCESS
        assert destination.read_bytes() == plaintext
        expected_plaintext_files.add(destination)
    else:
        assert not destination.exists()
    assert not list(tmp_path.rglob(".sfile-*.tmp"))
    assert package.read_bytes() == package_bytes
    output = capsys.readouterr()
    visible = "\n".join([*messages, str(prepared), str(result), output.out, output.err, caplog.text]).encode()
    secret_tokens = (plaintext, PASSWORD, b"qa-wrong-passphrase-8339",
                     generated[0], generated[0].hex().encode(), base64.b64encode(generated[0]))
    for path in tmp_path.rglob("*"):
        if not path.is_file() or path in expected_plaintext_files:
            continue
        contents = path.read_bytes()
        assert all(secret not in contents for secret in secret_tokens), path.name
        assert b"BEGIN PRIVATE KEY" not in contents, path.name
        assert b"BEGIN RSA PRIVATE KEY" not in contents, path.name
        if path.parent != app.keys.profiles:
            assert b"PRIVATE KEY" not in contents, path.name
    assert all(secret not in visible for secret in secret_tokens)
    assert b"PRIVATE KEY" not in visible


@pytest.mark.case("L05")
def test_authorized_plaintext_can_be_forwarded(app, tmp_path):
    data = b"Synthetic text can be copied after legitimate recovery."
    _, package = _send(app, tmp_path, data)
    recovered = tmp_path / "bob-recovered.bin"
    _restore(app, "bob", package, recovered)
    rejected = app.service.prepare_receive(ReceiveRequest("mallory", package, PASSWORD))
    assert rejected.error.code is ErrorCode.RECIPIENT_KEY_NOT_FOUND
    forwarded = tmp_path / "mallory-copy.bin"
    shutil.copyfile(recovered, forwarded)
    assert forwarded.read_bytes() == data


def _pin(receiver, profile, sender, identity):
    summary = sender.keys.get_profile(identity)
    receiver.trust.import_contact(profile, identity, sender.keys.public_bundle(identity))
    receiver.trust.verify_contact(profile, identity, summary.encryption_fingerprint, summary.signing_fingerprint)


@pytest.mark.case("L06")
def test_wrong_verified_fingerprint_controls_the_recipient(app, tmp_path):
    mislabeled = json.loads(app.keys.public_bundle("mallory"))
    mislabeled["display_name"] = "Bob"
    imported = app.trust.import_contact("alice", "bob", encode_json(mislabeled), replace=True)
    app.trust.verify_contact("alice", "bob", imported.encryption_fingerprint, imported.signing_fingerprint)
    data = b"Intended only for the correctly verified test recipient."
    _, package = _send(app, tmp_path, data)
    envelope = EnvelopeCodec().parse_envelope(package.read_bytes())
    assert envelope.header.recipient_enc_fp == app.keys.get_profile("mallory").encryption_fingerprint
    assert app.service.prepare_receive(ReceiveRequest("bob", package, PASSWORD)).error.code is (
        ErrorCode.RECIPIENT_KEY_NOT_FOUND
    )
    output = tmp_path / "wrongly-pinned-recipient.bin"
    _restore(app, "mallory", package, output)
    assert output.read_bytes() == data


@pytest.mark.case("L06")
def test_copied_recipient_key_can_open_an_old_package(app, tmp_path):
    data = b"Synthetic package predating the test backup disclosure."
    _, package = _send(app, tmp_path, data)
    backup = app.keys.backup_profile("bob", PASSWORD)
    clone = create_application(tmp_path / "isolated-copy")
    try:
        assert clone.keys.restore_profile(backup, PASSWORD) == app.keys.get_profile("bob")
        _pin(clone, "bob", app, "alice")
        recovered = tmp_path / "old-package-recovered.bin"
        _restore(clone, "bob", package, recovered)
        assert recovered.read_bytes() == data
    finally:
        clone.service.close()


@pytest.mark.case("L06")
def test_copied_signing_key_still_matches_bobs_pin(app, tmp_path):
    backup = app.keys.backup_profile("alice", PASSWORD)
    clone = create_application(tmp_path / "isolated-copy")
    try:
        assert clone.keys.restore_profile(backup, PASSWORD) == app.keys.get_profile("alice")
        _pin(clone, "alice", app, "bob")
        data = b"Synthetic document generated on the isolated key copy."
        _, package = _send(clone, tmp_path, data)
        output = tmp_path / "bob-received-from-copy.bin"
        prepared = _restore(app, "bob", package, output)
        assert prepared.prepared.sender_fingerprint == app.keys.get_profile("alice").signing_fingerprint
        assert output.read_bytes() == data
    finally:
        clone.service.close()
