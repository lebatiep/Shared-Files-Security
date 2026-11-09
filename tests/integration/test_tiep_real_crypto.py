"""Exercise Tiệp's workflow with real cryptography, using test-only adapters.

These in-memory helpers are not deployable replacements for Nhật's key/trust,
Hoàng's codec/crypto, or Việt's storage. They check the service's interoperability
and stage ordering; they do not certify the production parser, PEM protection,
filesystem writer or GUI. Private keys are generated in memory and never saved.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import unittest

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_share.config import (
    AAD_CONTEXT,
    MAX_FILE_BYTES,
    MAX_METADATA_BYTES,
    NONCE_BYTES,
    OAEP_LABEL,
    PSS_SALT_BYTES,
    RSA_KEY_BITS,
    RSA_PUBLIC_EXPONENT,
    SIGNATURE_CONTEXT,
)
from secure_share.errors import ErrorCode, ShareError
from secure_share.history import MemoryHistoryStore
from secure_share.models import (
    KeyReference,
    KeyRole,
    OperationStatus,
    PackageHeader,
    Payload,
    ProcessingStage,
    ProfileSummary,
    RawEnvelope,
    ReceiveRequest,
    SendRequest,
    TrustedContact,
    TrustStatus,
    WriteReceipt,
)
from secure_share.service import FileShareService


_PASSPHRASE = b"test-only-passphrase"


def _fingerprint(public_key: rsa.RSAPublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


class _MemoryStorage:
    """Test-only byte store; performs no filesystem writes."""

    def __init__(self) -> None:
        self.files: dict[Path, bytes] = {}
        self.writes: list[Path] = []

    def read_limited(self, path: Path, max_bytes: int) -> bytes:
        try:
            data = self.files[Path(path).resolve()]
        except KeyError as exc:
            raise ShareError(ErrorCode.READ_FAILED) from exc
        if len(data) > max_bytes:
            raise ShareError(ErrorCode.INPUT_TOO_LARGE)
        return data

    def save_atomic(
        self,
        data: bytes,
        destination: Path,
        *,
        overwrite_confirmed: bool = False,
        protected_paths: tuple[Path, ...] = (),
    ) -> WriteReceipt:
        target = Path(destination).resolve()
        if target in {Path(path).resolve() for path in protected_paths}:
            raise ShareError(ErrorCode.PROTECTED_PATH)
        if target in self.files and not overwrite_confirmed:
            raise ShareError(ErrorCode.DESTINATION_EXISTS)
        self.files[target] = bytes(data)
        self.writes.append(target)
        return WriteReceipt(destination=target, byte_count=len(data))


class _MemoryIdentity:
    """Test-only profiles and explicitly verified contacts, no PEM serialization."""

    def __init__(self, keypairs: dict[str, dict[KeyRole, rsa.RSAPrivateKey]]) -> None:
        self.keypairs = keypairs
        self.profiles = {
            profile: ProfileSummary(
                profile_id=profile,
                display_name=profile.title(),
                encryption_fingerprint=_fingerprint(keys[KeyRole.ENCRYPTION].public_key()),
                signing_fingerprint=_fingerprint(keys[KeyRole.SIGNING].public_key()),
            )
            for profile, keys in keypairs.items()
        }

    def get_profile(self, profile_id: str) -> ProfileSummary:
        try:
            return self.profiles[profile_id]
        except KeyError as exc:
            raise ShareError(ErrorCode.PROFILE_INVALID) from exc

    def protected_paths(self, profile_id: str) -> tuple[Path, ...]:
        return tuple(
            Path("test-only-memory-profiles") / profile_id / f"{role.value}.pem"
            for role in (KeyRole.ENCRYPTION, KeyRole.SIGNING)
        )

    def resolve_decryption_key(self, profile_id: str, fingerprint: str) -> KeyReference:
        profile = self.get_profile(profile_id)
        if fingerprint != profile.encryption_fingerprint:
            raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)
        return KeyReference(
            profile_id=profile_id,
            fingerprint=fingerprint,
            role=KeyRole.ENCRYPTION,
            private_key_path=self.protected_paths(profile_id)[0],
        )

    def unlock_private_key(
        self,
        profile_id: str,
        role: KeyRole,
        fingerprint: str,
        passphrase: bytes,
    ) -> object:
        profile = self.get_profile(profile_id)
        expected = (
            profile.signing_fingerprint
            if role is KeyRole.SIGNING
            else profile.encryption_fingerprint
        )
        if passphrase != _PASSPHRASE or fingerprint != expected:
            raise ShareError(ErrorCode.KEY_UNLOCK_FAILED)
        return self.keypairs[profile_id][role]

    def _contact(self, owner: str, contact_id: str) -> TrustedContact:
        self.get_profile(owner)
        contact = self.get_profile(contact_id)
        keys = self.keypairs[contact_id]
        return TrustedContact(
            profile_id=owner,
            contact_id=contact_id,
            display_name=contact.display_name,
            encryption_fingerprint=contact.encryption_fingerprint,
            signing_fingerprint=contact.signing_fingerprint,
            encryption_public_key=keys[KeyRole.ENCRYPTION].public_key(),
            signing_public_key=keys[KeyRole.SIGNING].public_key(),
            status=TrustStatus.VERIFIED,
        )

    def resolve_recipient(self, profile_id: str, contact_id: str) -> TrustedContact:
        return self._contact(profile_id, contact_id)

    def resolve_sender(self, profile_id: str, signing_fingerprint: str) -> TrustedContact:
        for contact_id, profile in self.profiles.items():
            if profile.signing_fingerprint == signing_fingerprint:
                return self._contact(profile_id, contact_id)
        raise ShareError(ErrorCode.UNTRUSTED_SENDER)


class _RealCryptoForTests:
    """Real primitives with counters to demonstrate where the service stopped."""

    def __init__(self) -> None:
        self.events: list[str] = []

    @staticmethod
    def generate_aes_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def generate_nonce() -> bytes:
        return os.urandom(NONCE_BYTES)

    @staticmethod
    def _oaep() -> padding.OAEP:
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        )

    @staticmethod
    def _pss() -> padding.PSS:
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_BYTES)

    def wrap_key(self, aes_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        self.events.append("wrap")
        return public_key.encrypt(aes_key, self._oaep())

    def unwrap_key(self, wrapped_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        self.events.append("unwrap")
        try:
            return private_key.decrypt(wrapped_key, self._oaep())
        except ValueError as exc:
            raise ShareError(ErrorCode.UNWRAP_FAILED) from exc

    def encrypt_payload(self, key: bytes, nonce: bytes, payload: bytes, aad: bytes) -> bytes:
        self.events.append("encrypt")
        return AESGCM(key).encrypt(nonce, payload, aad)

    def decrypt_payload(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        self.events.append("decrypt")
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ShareError(ErrorCode.GCM_AUTH_FAILED) from exc

    def sign_package(self, message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        self.events.append("sign")
        return private_key.sign(message, self._pss(), hashes.SHA256())

    def verify_signature(
        self, signature: bytes, message: bytes, public_key: rsa.RSAPublicKey
    ) -> None:
        self.events.append("verify")
        try:
            public_key.verify(signature, message, self._pss(), hashes.SHA256())
        except InvalidSignature as exc:
            raise ShareError(ErrorCode.SIGNATURE_INVALID) from exc


class _TestEnvelopeCodec:
    """Small valid-fixture codec, not the production untrusted-input parser.

    The tests intentionally do not claim coverage of duplicate JSON fields,
    hostile recursion, filesystem names or all schema/cap edge cases.
    """

    def __init__(self) -> None:
        self.payload_parse_count = 0

    @staticmethod
    def build_header(header: PackageHeader) -> bytes:
        return json.dumps(asdict(header), separators=(",", ":")).encode("utf-8")

    @staticmethod
    def build_payload(filename: str, data: bytes) -> bytes:
        metadata = json.dumps({"filename": filename}, ensure_ascii=False).encode("utf-8")
        if len(metadata) > MAX_METADATA_BYTES or len(data) > MAX_FILE_BYTES:
            raise ShareError(ErrorCode.PAYLOAD_INVALID)
        return len(metadata).to_bytes(4, "big") + metadata + data

    def parse_payload(self, data: bytes) -> Payload:
        self.payload_parse_count += 1
        length = int.from_bytes(data[:4], "big")
        metadata = json.loads(data[4 : 4 + length].decode("utf-8"))
        return Payload(filename=metadata["filename"], data=data[4 + length :])

    @staticmethod
    def build_aad(header_bytes: bytes, wrapped_key: bytes) -> bytes:
        return AAD_CONTEXT + _frame(header_bytes) + _frame(wrapped_key)

    @staticmethod
    def build_signature_input(
        header_bytes: bytes, wrapped_key: bytes, nonce: bytes, ciphertext: bytes
    ) -> bytes:
        return (
            SIGNATURE_CONTEXT
            + _frame(header_bytes)
            + _frame(wrapped_key)
            + _frame(nonce)
            + _frame(ciphertext)
        )

    @staticmethod
    def serialize_envelope(envelope: RawEnvelope) -> bytes:
        fields = {
            "header_b64": envelope.header_bytes,
            "wrapped_key_b64": envelope.wrapped_key,
            "nonce_b64": envelope.nonce,
            "ciphertext_b64": envelope.ciphertext,
            "signature_b64": envelope.signature,
        }
        return json.dumps(
            {key: base64.b64encode(value).decode("ascii") for key, value in fields.items()},
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def parse_envelope(data: bytes) -> RawEnvelope:
        document = json.loads(data.decode("utf-8"))
        fields = {key: base64.b64decode(value, validate=True) for key, value in document.items()}
        header_bytes = fields["header_b64"]
        return RawEnvelope(
            header=PackageHeader(**json.loads(header_bytes.decode("utf-8"))),
            header_bytes=header_bytes,
            wrapped_key=fields["wrapped_key_b64"],
            nonce=fields["nonce_b64"],
            ciphertext=fields["ciphertext_b64"],
            signature=fields["signature_b64"],
        )


class RealCryptoServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Six fresh private keys are generated once for this test class only.
        cls.keypairs = {
            profile: {
                role: rsa.generate_private_key(
                    public_exponent=RSA_PUBLIC_EXPONENT,
                    key_size=RSA_KEY_BITS,
                )
                for role in (KeyRole.ENCRYPTION, KeyRole.SIGNING)
            }
            for profile in ("alice", "bob", "mallory")
        }

    def setUp(self) -> None:
        self.storage = _MemoryStorage()
        self.identities = _MemoryIdentity(self.keypairs)
        self.crypto = _RealCryptoForTests()
        self.codec = _TestEnvelopeCodec()
        self.history = MemoryHistoryStore()
        self.sender = self._service()
        self.receiver = self._service()
        self.package_path = Path("test-only-memory/gift.sfile")
        self.output_path = Path("test-only-memory/recovered.bin")

    def _service(self) -> FileShareService:
        return FileShareService(
            keys=self.identities,
            trust=self.identities,
            crypto=self.crypto,
            envelope=self.codec,
            storage=self.storage,
            history=self.history,
        )

    def _send(self, data: bytes, filename: str = "source.bin") -> RawEnvelope:
        source = Path("test-only-memory") / filename
        self.storage.files[source.resolve()] = data
        result = self.sender.send_file(
            SendRequest(
                profile_id="alice",
                recipient_contact_id="bob",
                source_path=source,
                destination_path=self.package_path,
                passphrase=_PASSPHRASE,
            )
        )
        self.assertEqual(result.status, OperationStatus.SUCCESS, result.error)
        encoded = self.storage.files[self.package_path.resolve()]
        envelope = self.codec.parse_envelope(encoded)
        self.assertEqual(len(envelope.wrapped_key), RSA_KEY_BITS // 8)
        self.assertEqual(len(envelope.signature), RSA_KEY_BITS // 8)
        self.crypto.events.clear()
        self.codec.payload_parse_count = 0
        return envelope

    def _prepare(self, profile_id: str = "bob"):
        return self.receiver.prepare_receive(
            ReceiveRequest(
                profile_id=profile_id,
                package_path=self.package_path,
                passphrase=_PASSPHRASE,
            )
        )

    def _store_modified(self, envelope: RawEnvelope, *, sign_again: bool) -> None:
        if sign_again:
            message = self.codec.build_signature_input(
                envelope.header_bytes,
                envelope.wrapped_key,
                envelope.nonce,
                envelope.ciphertext,
            )
            signature = self.crypto.sign_package(message, self.keypairs["alice"][KeyRole.SIGNING])
            envelope = replace(envelope, signature=signature)
        self.storage.files[self.package_path.resolve()] = self.codec.serialize_envelope(envelope)
        self.crypto.events.clear()
        self.codec.payload_parse_count = 0

    def _assert_rejected_without_output(self, result, code, stage, events) -> None:
        self.assertEqual(result.status, OperationStatus.FAILED)
        self.assertEqual(result.error.code, code)
        self.assertEqual(result.stage, stage)
        self.assertEqual(self.crypto.events, events)
        self.assertFalse(self.receiver.has_prepared)
        self.assertNotIn(self.output_path.resolve(), self.storage.files)
        self.assertEqual(self.codec.payload_parse_count, 0)
        # The only write remains the sender's encrypted package.
        self.assertEqual(self.storage.writes, [self.package_path.resolve()])

    def test_real_binary_round_trip_preserves_bytes_and_profile_history(self):
        original = bytes(range(256)) * 19 + b"\x00\xff\x10\x00"
        envelope = self._send(original, filename="Bài tập nhóm.bin")
        self.assertNotIn(original, self.storage.files[self.package_path.resolve()])
        result = self._prepare()
        self.assertEqual(result.status, OperationStatus.PREPARED, result.error)
        self.assertEqual(result.prepared.filename, "Bài tập nhóm.bin")
        self.assertEqual(self.crypto.events, ["verify", "unwrap", "decrypt"])
        self.assertNotIn(self.output_path.resolve(), self.storage.files)

        saved = self.receiver.save_received(result.prepared.handle, self.output_path)
        self.assertEqual(saved.status, OperationStatus.SUCCESS, saved.error)
        recovered = self.storage.files[self.output_path.resolve()]
        self.assertEqual(recovered, original)
        self.assertEqual(hashlib.sha256(recovered).digest(), hashlib.sha256(original).digest())
        self.assertTrue(self.history.has_seen("bob", envelope.header.transfer_id))
        self.assertFalse(self.history.has_seen("alice", envelope.header.transfer_id))
        self.assertFalse(self.receiver.has_prepared)

    def test_real_empty_file_round_trip(self):
        self._send(b"", filename="empty.bin")
        result = self._prepare()
        self.assertEqual(result.status, OperationStatus.PREPARED, result.error)
        self.assertEqual(result.prepared.byte_count, 0)
        saved = self.receiver.save_received(result.prepared.handle, self.output_path)
        self.assertEqual(saved.status, OperationStatus.SUCCESS, saved.error)
        self.assertEqual(self.storage.files[self.output_path.resolve()], b"")

    def test_modified_ciphertext_is_rejected_by_real_pss_before_decryption(self):
        envelope = self._send(b"test document")
        modified = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
        self._store_modified(replace(envelope, ciphertext=modified), sign_again=False)
        self._assert_rejected_without_output(
            self._prepare(),
            ErrorCode.SIGNATURE_INVALID,
            ProcessingStage.SIGNATURE,
            ["verify"],
        )

    def test_other_recipient_is_rejected_before_real_oaep_unwrap(self):
        self._send(b"for Bob only")
        self._assert_rejected_without_output(
            self._prepare(profile_id="mallory"),
            ErrorCode.RECIPIENT_KEY_NOT_FOUND,
            ProcessingStage.RECIPIENT,
            ["verify"],
        )

    def test_pss_valid_fixture_with_bad_tag_reaches_real_gcm_failure(self):
        envelope = self._send(b"intentionally malformed test fixture")
        modified = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
        # Only a test holder of Alice's signing key constructs this fixture.
        self._store_modified(replace(envelope, ciphertext=modified), sign_again=True)
        self._assert_rejected_without_output(
            self._prepare(),
            ErrorCode.GCM_AUTH_FAILED,
            ProcessingStage.GCM,
            ["verify", "unwrap", "decrypt"],
        )

    def test_pss_valid_fixture_with_bad_wrapped_key_reaches_real_oaep_failure(self):
        envelope = self._send(b"intentionally malformed OAEP fixture")
        self._store_modified(
            replace(envelope, wrapped_key=b"\x00" * (RSA_KEY_BITS // 8)),
            sign_again=True,
        )
        self._assert_rejected_without_output(
            self._prepare(),
            ErrorCode.UNWRAP_FAILED,
            ProcessingStage.UNWRAP,
            ["verify", "unwrap"],
        )


if __name__ == "__main__":
    unittest.main()
