"""Dependency boundaries for collaborators' adapters.

Protocols describe shape, not security proofs. The real implementations must
honour the validation, trust and commit guarantees documented below.
"""

from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import (
    KeyReference,
    KeyRole,
    PackageHeader,
    Payload,
    ProfileSummary,
    RawEnvelope,
    TrustedContact,
    WriteReceipt,
)


@runtime_checkable
class StoragePort(Protocol):
    def read_limited(self, path: Path, max_bytes: int) -> bytes:
        """Read one immutable snapshot, enforcing the actual number of bytes.

        FileNotFoundError remains distinguishable for initial empty history.
        Other known failures should use ShareError without private detail.
        """
        ...

    def save_atomic(
        self,
        data: bytes,
        destination: Path,
        *,
        overwrite_confirmed: bool = False,
        protected_paths: tuple[Path, ...] = (),
    ) -> WriteReceipt:
        """Commit all bytes then return a receipt.

        Known ShareError failures guarantee no commit and preservation of the
        old destination. An unrecognised exception may mean an uncertain
        commit: service must not silently offer a potentially duplicate retry.
        Check protected path aliases; never infer an output path from payload.
        """
        ...


@runtime_checkable
class KeyProvider(Protocol):
    def get_profile(self, profile_id: str) -> ProfileSummary: ...

    def protected_paths(self, profile_id: str) -> tuple[Path, ...]:
        """Include manifests, trust files and all private-key files as relevant."""
        ...

    def resolve_decryption_key(
        self, profile_id: str, fingerprint: str
    ) -> KeyReference:
        """Resolve the exact encryption role, including retained old keys."""
        ...

    def unlock_private_key(
        self,
        profile_id: str,
        role: KeyRole,
        fingerprint: str,
        passphrase: bytes,
    ) -> object:
        """Return a temporary validated key; never persist the passphrase."""
        ...


@runtime_checkable
class TrustProvider(Protocol):
    def resolve_recipient(
        self, profile_id: str, contact_id: str
    ) -> TrustedContact:
        """Resolve a contact only inside the requested profile's trust store."""
        ...

    def resolve_sender(
        self, profile_id: str, signing_fingerprint: str
    ) -> TrustedContact:
        """Do not import or trust a public key supplied by the received file."""
        ...


@runtime_checkable
class CryptoProvider(Protocol):
    def generate_aes_key(self) -> bytes: ...

    def generate_nonce(self) -> bytes: ...

    def wrap_key(self, aes_key: bytes, public_key: object) -> bytes: ...

    def unwrap_key(self, wrapped_key: bytes, private_key: object) -> bytes: ...

    def encrypt_payload(
        self, key: bytes, nonce: bytes, payload: bytes, aad: bytes
    ) -> bytes: ...

    def decrypt_payload(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
    ) -> bytes:
        """Return plaintext only after GCM authentication succeeded."""
        ...

    def sign_package(self, message: bytes, private_key: object) -> bytes: ...

    def verify_signature(
        self, signature: bytes, message: bytes, public_key: object
    ) -> None:
        """Return None on success; raise ShareError on every verification failure.

        Returning False (or True) is a contract violation, not success.
        """
        ...


@runtime_checkable
class EnvelopeCodec(Protocol):
    def build_header(self, header: PackageHeader) -> bytes: ...

    def build_payload(self, filename: str, data: bytes) -> bytes: ...

    def parse_payload(self, data: bytes) -> Payload: ...

    def build_aad(self, header_bytes: bytes, wrapped_key: bytes) -> bytes: ...

    def build_signature_input(
        self,
        header_bytes: bytes,
        wrapped_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
    ) -> bytes: ...

    def serialize_envelope(self, envelope: RawEnvelope) -> bytes: ...

    def parse_envelope(self, data: bytes) -> RawEnvelope:
        """Strictly check schema, duplicate keys, encodings, profile and caps.

        Keep raw H unchanged. Parsing never authenticates a sender by itself.
        """
        ...


@runtime_checkable
class HistoryPort(Protocol):
    def has_seen(self, profile_id: str, transfer_id: str) -> bool: ...

    def record(self, profile_id: str, transfer_id: str) -> None:
        """Called after successful output commit, with the original profile."""
        ...
