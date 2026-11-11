"""Build and open threshold packages without exposing unwrapped shares to the UI."""

from dataclasses import dataclass, field
from pathlib import Path
import secrets

from . import threshold
from .config import AES_KEY_BYTES, MAX_FILE_BYTES, MAX_PACKAGE_BYTES, NONCE_BYTES
from .crypto_ops import sha256, unwrap_threshold_secret, wrap_threshold_secret
from .errors import ErrorCode, ShareError
from .models import KeyRole, Payload, TrustStatus


_SHARE_LABEL = b"SFILE2-RECIPIENT-SHARE"
_CONTRIBUTION_LABEL = b"SFILE2-CONTRIBUTION"


@dataclass(frozen=True, slots=True)
class ThresholdOutput:
    data: bytes = field(repr=False)
    transfer_id: str
    protected_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class ThresholdOpened:
    payload: Payload
    transfer_id: str
    sender_name: str
    sender_fingerprint: str
    recipient_fingerprint: str
    protected_paths: tuple[Path, ...]


def _package_id(package):
    return sha256(package.signature).hex()


def _check_share(header, position, share):
    if (
        threshold.share_index(share) != position + 1
        or not secrets.compare_digest(
            threshold.share_commitment(header.transfer_id, share),
            header.recipients[position].commitment,
        )
    ):
        raise ShareError(ErrorCode.INVALID_SHARE)


class ThresholdWorkflow:
    def __init__(self, *, keys, trust, crypto, envelope, storage):
        self.keys = keys
        self.trust = trust
        self.crypto = crypto
        self.envelope = envelope
        self.storage = storage

    def _read(self, path, limit):
        try:
            data = self.storage.read_limited(path, limit)
        except OSError:
            raise ShareError(ErrorCode.READ_FAILED) from None
        if not isinstance(data, bytes) or len(data) > limit:
            raise ShareError(ErrorCode.INPUT_TOO_LARGE)
        return data

    def _recipient(self, profile_id, contact_id):
        contact = self.trust.resolve_recipient(profile_id, contact_id)
        if (
            contact.profile_id != profile_id or contact.contact_id != contact_id
            or contact.status is not TrustStatus.VERIFIED
        ):
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
        return contact

    def send(self, request):
        ids = request.recipient_contact_ids
        if (
            not isinstance(ids, tuple) or len(ids) != 3
            or any(not isinstance(item, str) or not item for item in ids)
            or len(set(ids)) != 3
        ):
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        profile = self.keys.get_profile(request.profile_id)
        if profile.profile_id != request.profile_id:
            raise ShareError(ErrorCode.PROFILE_INVALID)
        contacts = tuple(self._recipient(request.profile_id, item) for item in ids)
        pairs = tuple((contact.encryption_fingerprint, contact.signing_fingerprint) for contact in contacts)
        role_fingerprints = {fingerprint for pair in pairs for fingerprint in pair}
        if len(role_fingerprints) != 6 or role_fingerprints.intersection(
            (profile.encryption_fingerprint, profile.signing_fingerprint)
        ):
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        expected = request.expected_recipient_fingerprints
        if expected is not None and expected != pairs:
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)

        data = self._read(request.source_path, MAX_FILE_BYTES)
        payload = self.envelope.build_payload(request.source_path.name, data)
        signing_key = self.keys.unlock_private_key(
            request.profile_id, KeyRole.SIGNING, profile.signing_fingerprint, request.passphrase
        )
        aes_key = self.crypto.generate_aes_key()
        shares = threshold.split_key(aes_key)
        transfer_id = secrets.token_hex(16)
        recipients = tuple(
            threshold.ThresholdRecipient(contact.encryption_fingerprint, threshold.share_commitment(transfer_id, share))
            for contact, share in zip(contacts, shares, strict=True)
        )
        header = threshold.ThresholdHeader(transfer_id, profile.signing_fingerprint, recipients)
        raw_header = threshold.build_header(header)
        wrapped = tuple(
            wrap_threshold_secret(share, contact.encryption_public_key, _SHARE_LABEL)
            for contact, share in zip(contacts, shares, strict=True)
        )
        nonce = self.crypto.generate_nonce()
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise ShareError(ErrorCode.INVALID_LENGTH)
        ciphertext = self.crypto.encrypt_payload(aes_key, nonce, payload, threshold.build_aad(raw_header, wrapped))
        message = threshold.build_signature_input(raw_header, wrapped, nonce, ciphertext)
        signature = self.crypto.sign_package(message, signing_key)
        encoded = threshold.serialize_package(
            threshold.ThresholdEnvelope(header, raw_header, wrapped, nonce, ciphertext, signature)
        )
        protected = (request.source_path, *self.keys.protected_paths(request.profile_id))
        return ThresholdOutput(encoded, transfer_id, protected)

    def _verified_package(self, profile_id, path):
        package = threshold.parse_package(self._read(path, MAX_PACKAGE_BYTES))
        header = package.header
        sender = self.trust.resolve_sender(profile_id, header.sender_sig_fp)
        if (
            sender.profile_id != profile_id or sender.signing_fingerprint != header.sender_sig_fp
            or sender.status is not TrustStatus.VERIFIED
        ):
            raise ShareError(ErrorCode.UNTRUSTED_SENDER)
        message = threshold.build_signature_input(
            package.header_bytes, package.wrapped_shares, package.nonce, package.ciphertext
        )
        if self.crypto.verify_signature(package.signature, message, sender.signing_public_key) is not None:
            raise ShareError(ErrorCode.SIGNATURE_INVALID)
        return package, sender

    def _holder(self, profile_id, header):
        matches = []
        for position, recipient in enumerate(header.recipients):
            try:
                reference = self.keys.resolve_decryption_key(profile_id, recipient.fingerprint)
            except ShareError as error:
                if error.code is ErrorCode.RECIPIENT_KEY_NOT_FOUND:
                    continue
                raise
            if (
                reference.profile_id != profile_id or reference.role is not KeyRole.ENCRYPTION
                or reference.fingerprint != recipient.fingerprint
            ):
                raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)
            matches.append((position, reference))
        if len(matches) != 1:
            raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)
        return matches[0]

    def _own_share(self, package, position, private_key):
        share = unwrap_threshold_secret(package.wrapped_shares[position], private_key, _SHARE_LABEL)
        _check_share(package.header, position, share)
        return share

    def contribute(self, request):
        package, _ = self._verified_package(request.profile_id, request.package_path)
        position, reference = self._holder(request.profile_id, package.header)
        target = self._recipient(request.profile_id, request.recipient_contact_id)
        target_fp = target.encryption_fingerprint
        if request.expected_recipient_fingerprint not in (None, target_fp):
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
        if target_fp == reference.fingerprint or all(
            target_fp != holder.fingerprint for holder in package.header.recipients
        ):
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        private_key = self.keys.unlock_private_key(
            request.profile_id, KeyRole.ENCRYPTION, reference.fingerprint, request.passphrase
        )
        share = self._own_share(package, position, private_key)
        package_id = _package_id(package)
        wrapped = wrap_threshold_secret(bytes.fromhex(package_id) + share, target.encryption_public_key, _CONTRIBUTION_LABEL)
        data = threshold.serialize_contribution(
            threshold.Contribution(package_id, reference.fingerprint, target_fp, wrapped)
        )
        protected = (request.package_path, reference.private_key_path, *self.keys.protected_paths(request.profile_id))
        return ThresholdOutput(data, package.header.transfer_id, protected)

    def open(self, request):
        package, sender = self._verified_package(request.profile_id, request.package_path)
        position, reference = self._holder(request.profile_id, package.header)
        header = package.header
        contribution = threshold.parse_contribution(self._read(request.contribution_path, threshold.MAX_CONTRIBUTION_BYTES))
        package_id = _package_id(package)
        source_position = next(
            (i for i, holder in enumerate(header.recipients) if holder.fingerprint == contribution.source_fp), None
        )
        if (
            contribution.package_id != package_id or contribution.target_fp != reference.fingerprint
            or source_position is None or source_position == position
        ):
            raise ShareError(ErrorCode.INVALID_SHARE)
        private_key = self.keys.unlock_private_key(
            request.profile_id, KeyRole.ENCRYPTION, reference.fingerprint, request.passphrase
        )
        own_share = self._own_share(package, position, private_key)
        incoming = unwrap_threshold_secret(contribution.wrapped_share, private_key, _CONTRIBUTION_LABEL)
        package_hash = bytes.fromhex(package_id)
        if len(incoming) != len(package_hash) + threshold.SHARE_BYTES or not secrets.compare_digest(
            incoming[:len(package_hash)], package_hash
        ):
            raise ShareError(ErrorCode.INVALID_SHARE)
        other_share = incoming[len(package_hash):]
        _check_share(header, source_position, other_share)
        key = threshold.combine_shares((own_share, other_share))
        if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
            raise ShareError(ErrorCode.INVALID_SHARE)
        aad = threshold.build_aad(package.header_bytes, package.wrapped_shares)
        plaintext = self.crypto.decrypt_payload(key, package.nonce, package.ciphertext, aad)
        payload = self.envelope.parse_payload(plaintext)
        protected = (
            request.package_path, request.contribution_path, reference.private_key_path,
            *self.keys.protected_paths(request.profile_id),
        )
        return ThresholdOpened(
            payload, header.transfer_id, sender.display_name, header.sender_sig_fp, reference.fingerprint, protected
        )
