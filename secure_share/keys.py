from pathlib import Path
import re
from threading import RLock

from .config import MIN_PASSPHRASE_CHARACTERS, RSA_KEY_BITS, RSA_PUBLIC_EXPONENT
from .crypto_ops import generate_rsa_key, is_probable_prime, sha256
from .envelope import encode_json, read_json
from .errors import ErrorCode, ShareError
from . import key_codec
from .key_codec import RSAPrivateKey, encrypted_private_pem, load_private, public_der, public_pem
from .models import KeyReference, KeyRole, ProfileSummary
from .storage import LocalStorage

MAX_PROFILE_BYTES = 262144
MAX_GENERATIONS = 10


def load_public(pem):
    try:
        return key_codec.load_public(pem)
    except (ValueError, TypeError, UnicodeError):
        raise ShareError(ErrorCode.PROFILE_INVALID) from None


def fingerprint(key):
    return sha256(public_der(key)).hex()


def identifier(value):
    reserved = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)), *(f'lpt{i}' for i in range(1, 10))}
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', value) or value in reserved:
        raise ShareError(ErrorCode.PROFILE_INVALID)
    return value


def display_name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 100 or any(ord(c) < 32 for c in value):
        raise ShareError(ErrorCode.PROFILE_INVALID)
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise ShareError(ErrorCode.PROFILE_INVALID) from None
    return value


def validate_bundle(data):
    obj = read_json(data, 8192)
    if not isinstance(obj, dict) or set(obj) != {'version', 'display_name', 'encryption_public_key', 'signing_public_key'}:
        raise ShareError(ErrorCode.PROFILE_INVALID)
    if type(obj['version']) is not int or obj['version'] != 1:
        raise ShareError(ErrorCode.PROFILE_INVALID)
    display_name(obj['display_name'])
    enc = load_public(obj['encryption_public_key'])
    sig = load_public(obj['signing_public_key'])
    if fingerprint(enc) == fingerprint(sig):
        raise ShareError(ErrorCode.PROFILE_INVALID)
    return obj, enc, sig


class KeyStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.profiles = self.root / 'profiles'
        self.profiles.mkdir(parents=True, exist_ok=True)
        self.storage = LocalStorage()
        self.lock = RLock()

    def _path(self, profile_id):
        path = self.profiles / (identifier(profile_id) + '.json')
        if path.resolve().parent != self.profiles.resolve():
            raise ShareError(ErrorCode.PROFILE_INVALID)
        return path

    def _read(self, profile_id, data=None):
        try:
            identifier(profile_id)
            if data is None:
                data = self.storage.read_limited(self._path(profile_id), MAX_PROFILE_BYTES)
            obj = read_json(data, MAX_PROFILE_BYTES)
            if not isinstance(obj, dict) or set(obj) != {'version', 'profile_id', 'display_name', 'generations'}:
                raise ValueError
            if type(obj['version']) is not int or obj['version'] != 1 or obj['profile_id'] != profile_id:
                raise ValueError
            display_name(obj['display_name'])
            generations = obj['generations']
            if not isinstance(generations, list) or not 1 <= len(generations) <= MAX_GENERATIONS:
                raise ValueError
            seen = set()
            for generation in generations:
                if not isinstance(generation, dict) or set(generation) != {'encryption', 'signing'}:
                    raise ValueError
                for entry in generation.values():
                    if not isinstance(entry, dict) or set(entry) != {'public', 'private'}:
                        raise ValueError
                    fp = fingerprint(load_public(entry['public']))
                    if fp in seen or not isinstance(entry['private'], str) or not re.fullmatch(r'-----BEGIN ENCRYPTED PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END ENCRYPTED PRIVATE KEY-----\r?\n?', entry['private']):
                        raise ValueError
                    seen.add(fp)
            return obj
        except (ValueError, TypeError, KeyError, FileNotFoundError):
            raise ShareError(ErrorCode.PROFILE_INVALID) from None

    def _generation(self, passphrase):
        try:
            valid = False
            if isinstance(passphrase, bytes) and len(passphrase) <= 1024:
                text = passphrase.decode('utf-8')
                valid = len(text) >= MIN_PASSPHRASE_CHARACTERS and bool(text.strip())
        except UnicodeError:
            valid = False
        if not valid:
            raise ShareError(ErrorCode.INVALID_REQUEST)
        result = {}
        for role in KeyRole:
            private = RSAPrivateKey(*generate_rsa_key(RSA_KEY_BITS, RSA_PUBLIC_EXPONENT))
            result[role.value] = {
                'public': public_pem(private.public_key()),
                'private': encrypted_private_pem(private, passphrase),
            }
        return result

    def create_profile(self, profile_id, name, passphrase):
        with self.lock:
            path = self._path(profile_id)
            display_name(name)
            if path.exists():
                raise ShareError(ErrorCode.DESTINATION_EXISTS)
            obj = {'version': 1, 'profile_id': profile_id, 'display_name': name,
                   'generations': [self._generation(passphrase)]}
            self.storage.save_atomic(encode_json(obj), path)
            return self.get_profile(profile_id)

    def list_profiles(self):
        return [self.get_profile(p.stem) for p in sorted(self.profiles.glob('*.json'))]

    def get_profile(self, profile_id):
        obj = self._read(profile_id)
        current = obj['generations'][-1]
        return ProfileSummary(profile_id, obj['display_name'],
                              fingerprint(load_public(current['encryption']['public'])),
                              fingerprint(load_public(current['signing']['public'])))

    def public_bundle(self, profile_id):
        obj = self._read(profile_id)
        current = obj['generations'][-1]
        return encode_json({'version': 1, 'display_name': obj['display_name'],
                            'encryption_public_key': current['encryption']['public'],
                            'signing_public_key': current['signing']['public']})

    def protected_paths(self, profile_id):
        self._read(profile_id)
        return (self.root, *(p for p in self.root.rglob('*') if p.is_file()))

    def _entry(self, profile_id, role, fp):
        if not isinstance(role, KeyRole):
            raise ShareError(ErrorCode.PROFILE_INVALID)
        for generation in self._read(profile_id)['generations']:
            entry = generation[role.value]
            if fingerprint(load_public(entry['public'])) == fp:
                return entry
        raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)

    def resolve_decryption_key(self, profile_id, fingerprint):
        self._entry(profile_id, KeyRole.ENCRYPTION, fingerprint)
        return KeyReference(profile_id, fingerprint, KeyRole.ENCRYPTION, self._path(profile_id))

    def unlock_private_key(self, profile_id, role, fp, passphrase):
        entry = self._entry(profile_id, role, fp)
        return self._unlock_entry(entry, fp, passphrase)

    def _unlock_entry(self, entry, fp, passphrase):
        try:
            key = load_private(entry['private'], passphrase)
            if fingerprint(key.public_key()) != fp:
                raise ValueError
            return key
        except (ValueError, TypeError, UnicodeError):
            raise ShareError(ErrorCode.KEY_UNLOCK_FAILED) from None

    def _validate_private_keys(self, obj, passphrase, *, imported=False):
        for generation in obj['generations']:
            for entry in generation.values():
                key = self._unlock_entry(entry, fingerprint(load_public(entry['public'])), passphrase)
                if imported and not (is_probable_prime(key.p) and is_probable_prime(key.q)):
                    raise ShareError(ErrorCode.KEY_UNLOCK_FAILED)

    def rotate_keys(self, profile_id, passphrase):
        with self.lock:
            obj = self._read(profile_id)
            self._validate_private_keys(obj, passphrase)
            if len(obj['generations']) >= MAX_GENERATIONS:
                raise ShareError(ErrorCode.INPUT_TOO_LARGE)
            obj['generations'].append(self._generation(passphrase))
            self.storage.save_atomic(encode_json(obj), self._path(profile_id), overwrite_confirmed=True)
            return self.get_profile(profile_id)

    def backup_profile(self, profile_id, passphrase):
        with self.lock:
            obj = self._read(profile_id)
            self._validate_private_keys(obj, passphrase)
            return encode_json(obj)

    def restore_profile(self, data, passphrase):
        with self.lock:
            obj = read_json(data, MAX_PROFILE_BYTES)
            if not isinstance(obj, dict) or 'profile_id' not in obj:
                raise ShareError(ErrorCode.PROFILE_INVALID)
            profile_id = identifier(obj['profile_id'])
            obj = self._read(profile_id, data)
            # Validate every retained key before committing anything. Contacts
            # are not restored: public keys must be verified on the new machine.
            self._validate_private_keys(obj, passphrase, imported=True)
            self.storage.save_atomic(encode_json(obj), self._path(profile_id))
            return self.get_profile(profile_id)
