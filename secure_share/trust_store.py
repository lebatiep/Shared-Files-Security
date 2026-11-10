from dataclasses import replace
from pathlib import Path
import secrets
from threading import RLock

from .envelope import encode_json, read_json
from .errors import ErrorCode, ShareError
from .keys import fingerprint, identifier, validate_bundle
from .models import TrustedContact, TrustStatus
from .storage import LocalStorage


class TrustStore:
    def __init__(self, root, keys):
        self.root = Path(root).resolve() / 'contacts'
        self.root.mkdir(parents=True, exist_ok=True)
        self.keys = keys
        self.storage = LocalStorage()
        self.lock = RLock()

    def _directory(self, profile_id):
        self.keys.get_profile(profile_id)
        directory = self.root / identifier(profile_id)
        if directory.resolve().parent != self.root:
            raise ShareError(ErrorCode.PROFILE_INVALID)
        return directory

    def _path(self, profile_id, contact_id):
        directory = self._directory(profile_id)
        path = directory / (identifier(contact_id) + '.json')
        if path.resolve().parent != directory:
            raise ShareError(ErrorCode.PROFILE_INVALID)
        return path

    def _read(self, profile_id, contact_id):
        try:
            data = self.storage.read_limited(self._path(profile_id, contact_id), 16384)
            obj = read_json(data, 16384)
            if not isinstance(obj, dict) or set(obj) != {'version', 'bundle', 'status'} or type(obj['version']) is not int or obj['version'] != 1:
                raise ValueError
            bundle, enc, sig = validate_bundle(encode_json(obj['bundle']))
            status = TrustStatus(obj['status'])
            contact = TrustedContact(profile_id, contact_id, bundle['display_name'], fingerprint(enc), fingerprint(sig), enc, sig, status)
            return obj, contact
        except (ValueError, TypeError, FileNotFoundError):
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT) from None

    def import_contact(self, profile_id, contact_id, bundle_data, *, replace=False):
        with self.lock:
            bundle, enc, sig = validate_bundle(bundle_data)
            path = self._path(profile_id, contact_id)
            if path.exists():
                _, contact = self._read(profile_id, contact_id)
                if (contact.encryption_fingerprint, contact.signing_fingerprint) == (fingerprint(enc), fingerprint(sig)):
                    return contact
                if contact.status is TrustStatus.DISABLED and replace:
                    raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
            path.parent.mkdir(parents=True, exist_ok=True)
            obj = {'version': 1, 'bundle': bundle, 'status': TrustStatus.UNVERIFIED.value}
            self.storage.save_atomic(encode_json(obj), path, overwrite_confirmed=replace)
            return self._read(profile_id, contact_id)[1]

    def verify_contact(self, profile_id, contact_id, encryption_fingerprint, signing_fingerprint):
        with self.lock:
            obj, contact = self._read(profile_id, contact_id)
            if self._is_disabled(contact, self._contacts(profile_id)):
                raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
            for expected, actual in ((encryption_fingerprint, contact.encryption_fingerprint), (signing_fingerprint, contact.signing_fingerprint)):
                if not isinstance(expected, str) or not expected.isascii() or not secrets.compare_digest(expected, actual):
                    raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
            obj['status'] = TrustStatus.VERIFIED.value
            self.storage.save_atomic(encode_json(obj), self._path(profile_id, contact_id), overwrite_confirmed=True)
            return self._read(profile_id, contact_id)[1]

    def disable_contact(self, profile_id, contact_id):
        with self.lock:
            obj, _ = self._read(profile_id, contact_id)
            obj['status'] = TrustStatus.DISABLED.value
            self.storage.save_atomic(encode_json(obj), self._path(profile_id, contact_id), overwrite_confirmed=True)

    def _contacts(self, profile_id):
        return [self._read(profile_id, path.stem)[1] for path in sorted(self._directory(profile_id).glob('*.json'))]

    @staticmethod
    def _is_disabled(contact, contacts):
        return any(
            other.status is TrustStatus.DISABLED
            and (
                contact.encryption_fingerprint == other.encryption_fingerprint
                or contact.signing_fingerprint == other.signing_fingerprint
            )
            for other in contacts
        )

    def list_contacts(self, profile_id):
        with self.lock:
            contacts = self._contacts(profile_id)
            disabled = [contact for contact in contacts if contact.status is TrustStatus.DISABLED]
            return [
                replace(contact, status=TrustStatus.DISABLED)
                if self._is_disabled(contact, disabled)
                else contact
                for contact in contacts
            ]

    def find_name_conflicts(self, profile_id, contact_id):
        contact = self._read(profile_id, contact_id)[1]
        return tuple(other for other in self.list_contacts(profile_id)
                     if other.contact_id != contact_id and other.display_name == contact.display_name)

    def resolve_recipient(self, profile_id, contact_id):
        identifier(contact_id)
        for contact in self.list_contacts(profile_id):
            if contact.contact_id == contact_id and contact.status is TrustStatus.VERIFIED:
                return contact
        raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)

    def resolve_sender(self, profile_id, signing_fingerprint):
        for contact in self.list_contacts(profile_id):
            if contact.signing_fingerprint == signing_fingerprint and contact.status is TrustStatus.VERIFIED:
                return contact
        raise ShareError(ErrorCode.UNTRUSTED_SENDER)
