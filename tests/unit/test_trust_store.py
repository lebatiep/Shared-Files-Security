import json
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from secure_share.keys import public_pem
from secure_share.envelope import encode_json
from secure_share.errors import ErrorCode, ShareError
from secure_share.models import TrustStatus
from secure_share.trust_store import TrustStore


@pytest.fixture(scope='module')
def bundles():
    keys = [public_pem(rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key())
            for _ in range(4)]
    return tuple(encode_json({'version': 1, 'display_name': 'Bob',
                             'encryption_public_key': keys[index], 'signing_public_key': keys[index + 1]})
                 for index in (0, 2))


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path, SimpleNamespace(get_profile=lambda profile_id: None))


def verify(store, contact):
    return store.verify_contact('alice', contact.contact_id, contact.encryption_fingerprint, contact.signing_fingerprint)


@pytest.mark.parametrize('status', list(TrustStatus))
@pytest.mark.parametrize('replace', [False, True])
def test_same_keys_preserve_name_status_and_disk(store, bundles, status, replace):
    contact = store.import_contact('alice', 'bob', bundles[0])
    if status is TrustStatus.VERIFIED:
        verify(store, contact)
    elif status is TrustStatus.DISABLED:
        store.disable_contact('alice', 'bob')
    path = store._path('alice', 'bob')
    before = path.read_bytes()
    renamed = json.loads(bundles[0])
    renamed['display_name'] = 'New name'
    result = store.import_contact('alice', 'bob', encode_json(renamed), replace=replace)
    assert result.status is status
    assert result.display_name == 'Bob'
    assert path.read_bytes() == before
    restarted = TrustStore(store.root.parent, store.keys)
    assert restarted.list_contacts('alice')[0].status is status


@pytest.mark.case("I06")
def test_changed_pair_requires_replacement_and_reverification(store, bundles):
    original = verify(store, store.import_contact('alice', 'bob', bundles[0]))
    with pytest.raises(ShareError) as error:
        store.import_contact('alice', 'bob', bundles[1])
    assert error.value.code is ErrorCode.DESTINATION_EXISTS
    assert store.resolve_recipient('alice', 'bob') == original
    changed = store.import_contact('alice', 'bob', bundles[1], replace=True)
    assert changed.status is TrustStatus.UNVERIFIED
    with pytest.raises(ShareError):
        store.resolve_recipient('alice', 'bob')
    assert verify(store, changed).status is TrustStatus.VERIFIED


@pytest.mark.case("I05")
@pytest.mark.parametrize('wrong', [None, '0' * 64, '\u00e9' * 64])
@pytest.mark.parametrize('field', ['encryption', 'signing'])
def test_wrong_fingerprint_does_not_verify(store, bundles, wrong, field):
    contact = store.import_contact('alice', 'bob', bundles[0])
    fingerprints = [contact.encryption_fingerprint, contact.signing_fingerprint]
    fingerprints[0 if field == 'encryption' else 1] = wrong
    with pytest.raises(ShareError) as error:
        store.verify_contact('alice', 'bob', *fingerprints)
    assert error.value.code is ErrorCode.UNTRUSTED_RECIPIENT
    assert store.list_contacts('alice')[0].status is TrustStatus.UNVERIFIED


@pytest.mark.case("I04")
def test_correct_fingerprints_verify_and_make_the_contact_usable(store, bundles):
    contact = store.import_contact('alice', 'bob', bundles[0])
    assert contact.status is TrustStatus.UNVERIFIED
    with pytest.raises(ShareError):
        store.resolve_recipient('alice', 'bob')
    verified = verify(store, contact)
    assert verified.status is TrustStatus.VERIFIED
    assert store.resolve_recipient('alice', 'bob').encryption_fingerprint == contact.encryption_fingerprint
    assert store.resolve_sender('alice', contact.signing_fingerprint).contact_id == 'bob'


@pytest.mark.case("I10")
def test_swapped_role_fingerprints_do_not_verify(store, bundles):
    # I10: the encryption and signing fingerprints must each match their own role.
    contact = store.import_contact('alice', 'bob', bundles[0])
    assert contact.encryption_fingerprint != contact.signing_fingerprint
    with pytest.raises(ShareError) as error:
        store.verify_contact('alice', 'bob', contact.signing_fingerprint, contact.encryption_fingerprint)
    assert error.value.code is ErrorCode.UNTRUSTED_RECIPIENT
    assert store.list_contacts('alice')[0].status is TrustStatus.UNVERIFIED


@pytest.mark.case("L02")
@pytest.mark.case("A01")
def test_disabled_contact_cannot_be_verified_or_resolved(store, bundles):
    contact = verify(store, store.import_contact('alice', 'bob', bundles[0]))
    store.disable_contact('alice', 'bob')
    with pytest.raises(ShareError):
        verify(store, contact)
    with pytest.raises(ShareError):
        store.resolve_recipient('alice', 'bob')
    with pytest.raises(ShareError):
        store.resolve_sender('alice', contact.signing_fingerprint)
    assert store.list_contacts('alice')[0].status is TrustStatus.DISABLED


@pytest.mark.parametrize('operation', ['replace', 'verify', 'disable'])
def test_failed_write_preserves_pin_after_restart(store, bundles, monkeypatch, operation):
    contact = store.import_contact('alice', 'bob', bundles[0])
    before = store._path('alice', 'bob').read_bytes()
    def fail_replace(*args):
        raise OSError('disk unavailable')
    monkeypatch.setattr('secure_share.storage.os.replace', fail_replace)
    with pytest.raises(ShareError) as error:
        if operation == 'replace':
            store.import_contact('alice', 'bob', bundles[1], replace=True)
        elif operation == 'verify':
            verify(store, contact)
        else:
            store.disable_contact('alice', 'bob')
    assert error.value.code is ErrorCode.SAVE_FAILED
    assert store._path('alice', 'bob').read_bytes() == before
    assert TrustStore(store.root.parent, store.keys).list_contacts('alice')[0] == contact
    assert not list(store._directory('alice').glob('.sfile-*.tmp'))


def test_name_conflicts_exclude_self_and_other_profiles(store, bundles):
    store.import_contact('alice', 'bob', bundles[0])
    other = store.import_contact('alice', 'other', bundles[1])
    store.import_contact('carol', 'bob', bundles[0])
    assert store.find_name_conflicts('alice', 'bob') == (other,)
    assert store.find_name_conflicts('carol', 'bob') == ()


@pytest.mark.parametrize('contents', [b'{}', b'[]', b'not json'])
def test_corrupt_pin_is_not_replaced(store, bundles, contents):
    store.import_contact('alice', 'bob', bundles[0])
    path = store._path('alice', 'bob')
    path.write_bytes(contents)
    with pytest.raises(ShareError):
        store.import_contact('alice', 'bob', bundles[1], replace=True)
    assert path.read_bytes() == contents


@pytest.mark.parametrize('field,value', [('version', True), ('display_name', ''), ('display_name', '\ud800'), ('unexpected', 'value')])
def test_invalid_bundle_does_not_replace_pin(store, bundles, field, value):
    store.import_contact('alice', 'bob', bundles[0])
    path = store._path('alice', 'bob')
    before = path.read_bytes()
    invalid = json.loads(bundles[1])
    invalid[field] = value
    with pytest.raises(ShareError):
        store.import_contact('alice', 'bob', json.dumps(invalid).encode(), replace=True)
    assert path.read_bytes() == before


def test_read_failure_does_not_replace_pin(store, bundles, monkeypatch):
    store.import_contact('alice', 'bob', bundles[0])
    path = store._path('alice', 'bob')
    before = path.read_bytes()
    def fail_read(*args):
        raise ShareError(ErrorCode.READ_FAILED)
    monkeypatch.setattr(store.storage, 'read_limited', fail_read)
    with pytest.raises(ShareError) as error:
        store.import_contact('alice', 'bob', bundles[1], replace=True)
    assert error.value.code is ErrorCode.READ_FAILED
    assert path.read_bytes() == before


@pytest.mark.parametrize('contact_id', ['../bob', 'BOB', 'con', 'bob/other'])
def test_invalid_contact_identifier_is_rejected(store, bundles, contact_id):
    with pytest.raises(ShareError) as error:
        store.import_contact('alice', contact_id, bundles[0])
    assert error.value.code is ErrorCode.PROFILE_INVALID
    assert list(store.root.rglob('*.json')) == []
