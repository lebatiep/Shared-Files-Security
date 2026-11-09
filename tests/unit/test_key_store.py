import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from secure_share.errors import ErrorCode, ShareError
from secure_share.keys import KeyStore, fingerprint, load_public, public_pem
from secure_share.models import KeyRole


PASSWORD = b'correct-test-passphrase'


class KeyStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with TemporaryDirectory() as root:
            store = KeyStore(root)
            store.create_profile('alice', 'Alice', PASSWORD)
            cls.initial = (Path(root) / 'profiles/alice.json').read_bytes()
            store.rotate_keys('alice', PASSWORD)
            cls.rotated = (Path(root) / 'profiles/alice.json').read_bytes()

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = KeyStore(self.directory.name)
        self.path = Path(self.directory.name) / 'profiles/alice.json'
        self.path.write_bytes(self.initial)

    def assert_error(self, code, operation):
        with self.assertRaises(ShareError) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)

    def test_generated_keys_are_distinct_encrypted_rsa3072(self):
        obj = json.loads(self.initial)
        keys = []
        for role in KeyRole:
            entry = obj['generations'][0][role.value]
            private = self.store.unlock_private_key('alice', role, fingerprint(load_public(entry['public'])), PASSWORD)
            self.assertEqual(private.key_size, 3072)
            self.assertEqual(private.public_key().public_numbers().e, 65537)
            self.assertTrue(entry['private'].startswith('-----BEGIN ENCRYPTED PRIVATE KEY-----'))
            with self.assertRaises(TypeError):
                serialization.load_pem_private_key(entry['private'].encode(), None)
            keys.append(private.public_key().public_numbers())
        self.assertNotEqual(*keys)

    def test_rotation_preserves_old_keys_across_restart_and_restore(self):
        self.path.write_bytes(self.rotated)
        restarted = KeyStore(self.directory.name)
        backup = restarted.backup_profile('alice', PASSWORD)
        with TemporaryDirectory() as root:
            restored = KeyStore(root)
            restored.restore_profile(backup, PASSWORD)
            self.assertEqual(json.loads(backup)['generations'][0], json.loads(self.initial)['generations'][0])
            for generation in json.loads(backup)['generations']:
                for role in KeyRole:
                    fp = fingerprint(load_public(generation[role.value]['public']))
                    restored.unlock_private_key('alice', role, fp, PASSWORD)
                    if role == KeyRole.ENCRYPTION:
                        self.assertEqual(restored.resolve_decryption_key('alice', fp).fingerprint, fp)

    def test_wrong_password_does_not_change_profile(self):
        for operation in (self.store.rotate_keys, self.store.backup_profile):
            self.assert_error(ErrorCode.KEY_UNLOCK_FAILED, lambda: operation('alice', b'incorrect-password'))
            self.assertEqual(self.path.read_bytes(), self.initial)

    def test_corrupt_or_mismatched_retained_key_blocks_backup_rotation_restore(self):
        for index in (0, 1):
            for replacement in ('-----BEGIN ENCRYPTED PRIVATE KEY-----\nYWJj\n-----END ENCRYPTED PRIVATE KEY-----\n',
                                json.loads(self.initial)['generations'][0]['signing']['private']):
                obj = json.loads(self.rotated)
                obj['generations'][index]['encryption']['private'] = replacement
                damaged = json.dumps(obj).encode()
                self.path.write_bytes(damaged)
                for operation in (self.store.rotate_keys, self.store.backup_profile):
                    self.assert_error(ErrorCode.KEY_UNLOCK_FAILED, lambda: operation('alice', PASSWORD))
                    self.assertEqual(self.path.read_bytes(), damaged)
                with TemporaryDirectory() as root:
                    restored = KeyStore(root)
                    self.assert_error(ErrorCode.KEY_UNLOCK_FAILED, lambda: restored.restore_profile(damaged, PASSWORD))
                    self.assertEqual(list(restored.profiles.iterdir()), [])

    def test_failed_atomic_replace_preserves_profile_and_cleans_temporary_file(self):
        with patch('secure_share.storage.os.replace', side_effect=OSError):
            self.assert_error(ErrorCode.SAVE_FAILED, lambda: self.store.rotate_keys('alice', PASSWORD))
        self.assertEqual(self.path.read_bytes(), self.initial)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        KeyStore(self.directory.name).backup_profile('alice', PASSWORD)

    def test_invalid_creation_inputs_do_not_write(self):
        for password in (b' ' * 12, b'short', b'\xff' * 12, 'correct-test-passphrase', b'a' * 1025):
            self.assert_error(ErrorCode.INVALID_REQUEST, lambda: self.store.create_profile('bob', 'Bob', password))
        for profile in ('../bob', 'con', '', None):
            self.assert_error(ErrorCode.PROFILE_INVALID, lambda: self.store.create_profile(profile, 'Bob', PASSWORD))
        for name in ('', '\ud800', 'bad\0name'):
            self.assert_error(ErrorCode.PROFILE_INVALID, lambda: self.store.create_profile('bob', name, PASSWORD))
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_wrong_role_and_duplicate_keys_are_rejected(self):
        profile = self.store.get_profile('alice')
        self.assert_error(ErrorCode.RECIPIENT_KEY_NOT_FOUND,
                          lambda: self.store.unlock_private_key('alice', KeyRole.SIGNING, profile.encryption_fingerprint, PASSWORD))
        obj = json.loads(self.initial)
        obj['generations'][0]['signing'] = copy.deepcopy(obj['generations'][0]['encryption'])
        self.path.write_text(json.dumps(obj))
        self.assert_error(ErrorCode.PROFILE_INVALID, lambda: self.store.get_profile('alice'))

    def test_incomplete_private_pem_is_rejected(self):
        obj = json.loads(self.initial)
        obj['generations'][0]['encryption']['private'] = '-----BEGIN ENCRYPTED PRIVATE KEY-----garbage'
        self.path.write_text(json.dumps(obj))
        self.assert_error(ErrorCode.PROFILE_INVALID, lambda: self.store.get_profile('alice'))

    def test_unsupported_private_encryption_is_safe_failure(self):
        with patch('secure_share.keys.serialization.load_pem_private_key', side_effect=UnsupportedAlgorithm('secret')):
            self.assert_error(ErrorCode.KEY_UNLOCK_FAILED, lambda: self.store.backup_profile('alice', PASSWORD))

    def test_public_key_boundary_rejects_wrong_parameters_and_private_pem(self):
        public = load_public(json.loads(self.initial)['generations'][0]['encryption']['public'])
        numbers = public.public_numbers()
        wrong_exponent = rsa.RSAPublicNumbers(3, numbers.n).public_key()
        small_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        for pem in (public_pem(wrong_exponent), public_pem(small_key),
                    json.loads(self.initial)['generations'][0]['encryption']['private'],
                    public_pem(public) + 'garbage', None):
            self.assert_error(ErrorCode.PROFILE_INVALID, lambda: load_public(pem))
        self.assertEqual(fingerprint(load_public(public_pem(public).replace('\n', '\r\n'))), fingerprint(public))
