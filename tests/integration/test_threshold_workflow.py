"""Exercise the threshold workflow with real providers and isolated test devices."""

import base64
from dataclasses import dataclass
import hashlib
from itertools import permutations
import json
from pathlib import Path
import shutil

import pytest

from secure_share.application import Application, create_application
from secure_share.config import MAX_FILE_BYTES
from secure_share.errors import ErrorCode
from secure_share.models import (
    ContributionRequest,
    OperationStatus,
    ReceiveRequest,
    ThresholdReceiveRequest,
    ThresholdSendRequest,
    WarningCode,
)

HOLDERS = ("bob", "carol", "david")
NAMES = ("alice", *HOLDERS, "eve")
DATA = "Khảo sát giả lập".encode("utf-8") + b"\x00\x80\xff"
FILENAME = "Hồ sơ mẫu.bin"


@dataclass
class Device:
    name: str
    files: Path
    app: Application

    @property
    def passphrase(self):
        return f"qa-only-passphrase-for-{self.name}".encode("ascii")

    def receive_artifact(self, path):
        incoming = self.files / path.name
        assert not incoming.exists()
        shutil.copyfile(path, incoming)
        return incoming


def _device(root, name):
    files = root / "files"
    files.mkdir(exist_ok=True)
    return Device(name, files, create_application(root / "private"))


def _pin(owner, peer, *, contact_id=None, replace=False):
    contact_id = contact_id or peer.name
    bundle = peer.app.keys.public_bundle(peer.name)
    profile = peer.app.keys.get_profile(peer.name)
    owner.app.trust.import_contact(owner.name, contact_id, bundle, replace=replace)
    owner.app.trust.verify_contact(
        owner.name, contact_id, profile.encryption_fingerprint, profile.signing_fingerprint
    )


@pytest.fixture(scope="module")
def seeded_devices(tmp_path_factory):
    root = tmp_path_factory.mktemp("threshold-device-seed")
    devices = {}
    for name in NAMES:
        (root / name).mkdir()
        device = _device(root / name, name)
        device.app.keys.create_profile(name, name.title(), device.passphrase)
        devices[name] = device
    for owner in devices.values():
        for peer in devices.values():
            if owner is not peer:
                _pin(owner, peer)
        owner.app.service.close()
    return root


@pytest.fixture
def devices(seeded_devices, tmp_path):
    root = tmp_path / "devices"
    shutil.copytree(seeded_devices, root)
    instances = {name: _device(root / name, name) for name in NAMES}
    yield instances
    for device in instances.values():
        device.app.service.close()


def _send(device, *, tag="threshold", data=DATA, holders=HOLDERS, passphrase=None, expected_fingerprints=None):
    source = device.files / FILENAME
    source.write_bytes(data)
    output = device.files / f"{tag}.sfile2"
    request = ThresholdSendRequest(
        device.name, holders, source, output,
        device.passphrase if passphrase is None else passphrase,
        expected_recipient_fingerprints=expected_fingerprints,
    )
    return device.app.service.send_threshold(request), output


def _export(contributor, opener_name, package, *, tag="contribution", passphrase=None, expected_fingerprint=None):
    output = contributor.files / f"{tag}.sapproval"
    request = ContributionRequest(
        contributor.name, opener_name, package, output,
        contributor.passphrase if passphrase is None else passphrase,
        expected_recipient_fingerprint=expected_fingerprint,
    )
    return contributor.app.service.export_contribution(request), output


def _prepare(opener, package, contribution, *, passphrase=None):
    request = ThresholdReceiveRequest(
        opener.name, package, contribution,
        opener.passphrase if passphrase is None else passphrase,
    )
    return opener.app.service.prepare_threshold_receive(request)


def _sent(device, **kwargs):
    result, package = _send(device, **kwargs)
    assert result.status is OperationStatus.SUCCESS, result
    assert result.receipt.destination == package
    assert package.is_file()
    return package


def _exported(contributor, opener_name, package):
    result, path = _export(contributor, opener_name, package)
    assert result.status is OperationStatus.SUCCESS, result
    assert result.receipt.destination == path
    assert path.is_file()
    return path


def _transfer(devices, opener_name="bob", contributor_name="carol", **kwargs):
    package = _sent(devices["alice"], **kwargs)
    opener, contributor = devices[opener_name], devices[contributor_name]
    member_package = contributor.receive_artifact(package)
    contribution = _exported(contributor, opener.name, member_package)
    return opener, opener.receive_artifact(package), opener.receive_artifact(contribution)


def _failed(device, result, *codes):
    assert result.status is OperationStatus.FAILED, result
    assert result.error.code in codes
    assert result.receipt is None
    assert result.prepared is None
    assert not device.app.service.has_prepared


@pytest.mark.parametrize(
    "opener_name,contributor_name",
    [pytest.param(opener, contributor, id=f"{contributor}-to-{opener}")
     for opener, contributor in permutations(HOLDERS, 2)],
)
def test_any_pair_can_open_across_independent_devices(devices, opener_name, contributor_name):
    opener, package, contribution = _transfer(devices, opener_name, contributor_name)
    for device in devices.values():
        assert [profile.profile_id for profile in device.app.keys.list_profiles()] == [device.name]
    assert DATA not in package.read_bytes()
    assert DATA not in contribution.read_bytes()
    expected_files = {package, contribution}
    result = _prepare(opener, package, contribution)
    assert result.status is OperationStatus.PREPARED, result
    assert result.prepared.filename == FILENAME
    assert result.prepared.byte_count == len(DATA)
    assert set(opener.files.iterdir()) == expected_files

    output = opener.files / "recovered.bin"
    saved = opener.app.service.save_received(result.prepared.handle, output)
    assert saved.status is OperationStatus.SUCCESS, saved
    assert saved.receipt.destination == output
    assert output.read_bytes() == DATA
    assert set(opener.files.iterdir()) == expected_files | {output}
    assert not opener.app.service.has_prepared


def test_missing_contribution_leaves_a_holder_with_only_one_share(devices):
    package = _sent(devices["alice"])
    opener = devices["bob"]
    incoming = opener.receive_artifact(package)
    missing = opener.files / "missing.sapproval"

    _failed(opener, _prepare(opener, incoming, missing), ErrorCode.READ_FAILED)
    _failed(opener, _prepare(opener, incoming, incoming), ErrorCode.INPUT_TOO_LARGE)
    legacy = opener.app.service.prepare_receive(ReceiveRequest(opener.name, incoming, opener.passphrase))
    _failed(opener, legacy, ErrorCode.INVALID_SCHEMA, ErrorCode.UNSUPPORTED_VERSION, ErrorCode.UNSUPPORTED_SUITE)
    assert set(opener.files.iterdir()) == {incoming}


def test_threshold_roundtrip_at_file_limit(devices):
    data = bytes(range(256)) * (MAX_FILE_BYTES // 256)
    assert len(data) == MAX_FILE_BYTES
    opener, package, contribution = _transfer(devices, data=data)
    result = _prepare(opener, package, contribution)
    assert result.status is OperationStatus.PREPARED, result
    assert result.prepared.byte_count == MAX_FILE_BYTES
    output = opener.files / "maximum.bin"
    assert opener.app.service.save_received(result.prepared.handle, output).status is OperationStatus.SUCCESS
    assert output.read_bytes() == data


def test_threshold_rejects_file_one_byte_over_limit(devices):
    sender = devices["alice"]
    result, output = _send(sender, data=bytes(MAX_FILE_BYTES + 1))
    _failed(sender, result, ErrorCode.INPUT_TOO_LARGE)
    assert not output.exists()


@pytest.mark.parametrize(
    "holders",
    [
        pytest.param(("bob", "bob", "david"), id="duplicate-contact"),
        pytest.param(("bob", "bob-alias", "david"), id="duplicate-key-under-alias"),
        pytest.param(("bob", "carol"), id="two-holders"),
        pytest.param(("bob", "carol", "david", "eve"), id="four-holders"),
    ],
)
def test_send_requires_exactly_three_distinct_holders(devices, holders):
    sender = devices["alice"]
    _pin(sender, devices["bob"], contact_id="bob-alias")
    result, output = _send(sender, holders=holders)
    _failed(sender, result, ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
    assert not output.exists()


def test_holder_cannot_contribute_to_same_share_under_an_alias(devices):
    holder = devices["bob"]
    _pin(holder, holder, contact_id="my-alias")
    package = holder.receive_artifact(_sent(devices["alice"]))

    result, output = _export(holder, "my-alias", package)
    _failed(holder, result, ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
    assert not output.exists()


@pytest.mark.parametrize("replace_public_package_id", [False, True], ids=["original-id", "changed-id"])
def test_contribution_cannot_be_used_for_a_different_package(devices, replace_public_package_id):
    opener, _, contribution = _transfer(devices, tag="first")
    another = opener.receive_artifact(_sent(devices["alice"], tag="second"))
    if replace_public_package_id:
        fields = json.loads(contribution.read_bytes())
        signature = base64.b64decode(json.loads(another.read_bytes())["signature_b64"])
        fields["package_id"] = hashlib.sha256(signature).hexdigest()
        contribution.write_text(json.dumps(fields), encoding="utf-8")
    _failed(opener, _prepare(opener, another, contribution), ErrorCode.INVALID_SHARE)


def test_contribution_cannot_be_reused_by_another_valid_holder(devices):
    _, package, contribution = _transfer(devices)
    wrong_opener = devices["david"]
    result = _prepare(
        wrong_opener,
        wrong_opener.receive_artifact(package),
        wrong_opener.receive_artifact(contribution),
    )
    _failed(wrong_opener, result, ErrorCode.INVALID_SHARE)


@pytest.mark.parametrize(
    "variant,code",
    [
        ("duplicate-source", ErrorCode.INVALID_SCHEMA),
        ("altered-source", ErrorCode.INVALID_SHARE),
        ("altered-wrapped-share", ErrorCode.INVALID_SHARE),
    ],
)
def test_contribution_integrity_failure_is_rejected(devices, variant, code):
    opener, package, contribution = _transfer(devices)
    fields = json.loads(contribution.read_bytes())
    if variant == "duplicate-source":
        fields["source_fp"] = fields["target_fp"]
    elif variant == "altered-source":
        fields["source_fp"] = devices["david"].app.keys.get_profile("david").encryption_fingerprint
    else:
        wrapped = bytearray(base64.b64decode(fields["wrapped_share_b64"]))
        wrapped[-1] ^= 1
        fields["wrapped_share_b64"] = base64.b64encode(wrapped).decode("ascii")
    contribution.write_text(json.dumps(fields), encoding="utf-8")
    _failed(opener, _prepare(opener, package, contribution), code)


@pytest.mark.parametrize("phase", ["send", "export", "open"])
def test_wrong_passphrase_returns_safe_failure(devices, phase):
    bad_passphrase = b"incorrect-test-passphrase"
    sender, contributor = devices["alice"], devices["carol"]
    if phase == "send":
        result, output = _send(sender, passphrase=bad_passphrase)
        _failed(sender, result, ErrorCode.KEY_UNLOCK_FAILED)
        assert not output.exists()
    elif phase == "export":
        package = contributor.receive_artifact(_sent(sender))
        result, output = _export(contributor, "bob", package, passphrase=bad_passphrase)
        _failed(contributor, result, ErrorCode.KEY_UNLOCK_FAILED)
        assert not output.exists()
    else:
        opener, package, contribution = _transfer(devices)
        _failed(
            opener, _prepare(opener, package, contribution, passphrase=bad_passphrase),
            ErrorCode.KEY_UNLOCK_FAILED,
        )


@pytest.mark.parametrize("boundary", ["sender-to-holder", "contributor-to-opener", "contributor-to-sender", "opener-to-sender"])
def test_each_required_trust_boundary_is_enforced(devices, boundary):
    sender, contributor = devices["alice"], devices["carol"]
    if boundary == "sender-to-holder":
        sender.app.trust.disable_contact("alice", "bob")
        result, output = _send(sender)
        _failed(sender, result, ErrorCode.UNTRUSTED_RECIPIENT)
        assert not output.exists()
    elif boundary == "opener-to-sender":
        opener, package, contribution = _transfer(devices)
        opener.app.trust.disable_contact("bob", "alice")
        _failed(opener, _prepare(opener, package, contribution), ErrorCode.UNTRUSTED_SENDER)
    else:
        peer = "bob" if boundary == "contributor-to-opener" else "alice"
        expected = ErrorCode.UNTRUSTED_RECIPIENT if peer == "bob" else ErrorCode.UNTRUSTED_SENDER
        contributor.app.trust.disable_contact("carol", peer)
        package = contributor.receive_artifact(_sent(sender))
        result, output = _export(contributor, "bob", package)
        _failed(contributor, result, expected)
        assert not output.exists()


def test_verified_outsider_cannot_contribute_or_be_targeted(devices):
    _, bob_package, contribution = _transfer(devices)
    outsider, holder = devices["eve"], devices["carol"]
    outsider_package = outsider.receive_artifact(bob_package)
    wrong_opener = _prepare(outsider, outsider_package, outsider.receive_artifact(contribution))
    _failed(outsider, wrong_opener, ErrorCode.RECIPIENT_KEY_NOT_FOUND)
    outgoing, output = _export(outsider, "bob", outsider_package, tag="from-eve")
    _failed(outsider, outgoing, ErrorCode.RECIPIENT_KEY_NOT_FOUND)
    assert not output.exists()

    to_outsider, output = _export(holder, "eve", holder.files / bob_package.name, tag="to-eve")
    _failed(holder, to_outsider, ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
    assert not output.exists()


def test_contact_keys_changed_after_confirmation_do_not_get_used(devices):
    alice, bob, carol = (devices[name] for name in ("alice", "bob", "carol"))
    contacts = [alice.app.trust.resolve_recipient("alice", holder) for holder in HOLDERS]
    confirmed = tuple((contact.encryption_fingerprint, contact.signing_fingerprint) for contact in contacts)
    old_bob_fp = confirmed[0][0]
    original = _sent(alice, tag="original", expected_fingerprints=confirmed)

    bob.app.keys.rotate_keys("bob", bob.passphrase)
    _pin(alice, bob, replace=True)
    _pin(carol, bob, replace=True)
    result, output = _send(alice, tag="changed", expected_fingerprints=confirmed)
    _failed(alice, result, ErrorCode.UNTRUSTED_RECIPIENT)
    assert not output.exists()

    old_package = carol.receive_artifact(original)
    result, output = _export(carol, "bob", old_package, expected_fingerprint=old_bob_fp)
    _failed(carol, result, ErrorCode.UNTRUSTED_RECIPIENT)
    assert not output.exists()


@pytest.mark.parametrize("artifact", ["package", "contribution"])
def test_malformed_artifact_creates_no_pending_plaintext(devices, artifact):
    opener, package, contribution = _transfer(devices)
    path = package if artifact == "package" else contribution
    path.write_bytes(b'{"broken"')
    _failed(
        opener, _prepare(opener, package, contribution),
        ErrorCode.INVALID_JSON, ErrorCode.INVALID_SCHEMA, ErrorCode.INVALID_SHARE,
    )


def test_tampered_ciphertext_fails_signature_on_both_devices(devices):
    opener, package, contribution = _transfer(devices)
    document = json.loads(package.read_bytes())
    data = bytearray(base64.b64decode(document["ciphertext_b64"]))
    data[0] ^= 1
    document["ciphertext_b64"] = base64.b64encode(data).decode("ascii")
    changed = json.dumps(document).encode("utf-8")
    package.write_bytes(changed)
    contributor = devices["carol"]
    contributor_package = contributor.files / package.name
    contributor_package.write_bytes(changed)

    _failed(opener, _prepare(opener, package, contribution), ErrorCode.SIGNATURE_INVALID)
    result, output = _export(contributor, "bob", contributor_package, tag="tampered")
    _failed(contributor, result, ErrorCode.SIGNATURE_INVALID)
    assert not output.exists()


def test_cancel_reopen_and_save_reuses_existing_receive_behavior(devices):
    opener, package, contribution = _transfer(devices, data=b"")
    first = _prepare(opener, package, contribution)
    assert first.status is OperationStatus.PREPARED, first
    assert first.prepared.byte_count == 0
    assert opener.app.service.discard_prepared(first.prepared.handle).status is OperationStatus.CANCELLED
    output = opener.files / "empty.bin"
    _failed(opener, opener.app.service.save_received(first.prepared.handle, output), ErrorCode.INVALID_HANDLE)
    assert not output.exists()

    second = _prepare(opener, package, contribution)
    assert second.status is OperationStatus.PREPARED, second
    assert WarningCode.DUPLICATE_TRANSFER not in second.warnings
    output.write_bytes(b"keep existing")
    collision = opener.app.service.save_received(second.prepared.handle, output)
    assert collision.error.code is ErrorCode.DESTINATION_EXISTS
    assert output.read_bytes() == b"keep existing"
    chosen = opener.files / "empty-new-name.bin"
    assert opener.app.service.save_received(second.prepared.handle, chosen).status is OperationStatus.SUCCESS
    assert chosen.read_bytes() == b""

    repeat = _prepare(opener, package, contribution)
    assert repeat.status is OperationStatus.PREPARED, repeat
    assert WarningCode.DUPLICATE_TRANSFER in repeat.warnings
    opener.app.service.discard_prepared(repeat.prepared.handle)


def test_plaintext_save_cannot_overwrite_either_input_artifact(devices):
    opener, package, contribution = _transfer(devices)
    result = _prepare(opener, package, contribution)
    assert result.status is OperationStatus.PREPARED, result
    for path in (package, contribution):
        original = path.read_bytes()
        attempted = opener.app.service.save_received(result.prepared.handle, path, overwrite_confirmed=True)
        assert attempted.error.code is ErrorCode.PROTECTED_PATH
        assert path.read_bytes() == original
        assert opener.app.service.has_prepared
    output = opener.files / "chosen.bin"
    assert opener.app.service.save_received(result.prepared.handle, output).status is OperationStatus.SUCCESS
    assert output.read_bytes() == DATA


def test_rotated_holders_can_open_preexisting_packages_with_retained_keys(devices):
    package = _sent(devices["alice"])
    opener, contributor = devices["bob"], devices["carol"]
    for holder in (opener, contributor):
        old = holder.app.keys.get_profile(holder.name)
        updated = holder.app.keys.rotate_keys(holder.name, holder.passphrase)
        assert old.encryption_fingerprint != updated.encryption_fingerprint

    share = _exported(contributor, opener.name, contributor.receive_artifact(package))
    prepared = _prepare(opener, opener.receive_artifact(package), opener.receive_artifact(share))
    assert prepared.status is OperationStatus.PREPARED, prepared
    output = opener.files / "pre-rotation.bin"
    assert opener.app.service.save_received(prepared.prepared.handle, output).status is OperationStatus.SUCCESS
    assert output.read_bytes() == DATA
