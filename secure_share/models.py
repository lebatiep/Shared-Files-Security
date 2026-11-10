"""Immutable data contracts. Dataclass types do not replace validation.

The codecs validate untrusted package data; the service applies trust and
operation rules. Secret-bearing values are excluded from generated reprs.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import ErrorCode, safe_message


class KeyRole(StrEnum):
    ENCRYPTION = "encryption"
    SIGNING = "signing"


class TrustStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    DISABLED = "disabled"


class OperationStatus(StrEnum):
    SUCCESS = "success"
    PREPARED = "prepared"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ProcessingStage(StrEnum):
    READ = "READ"
    PARSE = "PARSE"
    TRUST = "TRUST"
    SIGNATURE = "SIGNATURE"
    RECIPIENT = "RECIPIENT"
    KEY_UNLOCK = "KEY_UNLOCK"
    UNWRAP = "UNWRAP"
    GCM = "GCM"
    PAYLOAD = "PAYLOAD"
    SAVE = "SAVE"
    HISTORY = "HISTORY"


class WarningCode(StrEnum):
    DUPLICATE_TRANSFER = "DUPLICATE_TRANSFER"
    HISTORY_UNAVAILABLE = "HISTORY_UNAVAILABLE"
    HISTORY_NOT_SAVED = "HISTORY_NOT_SAVED"


@dataclass(frozen=True, slots=True)
class ProfileSummary:
    profile_id: str
    display_name: str
    encryption_fingerprint: str
    signing_fingerprint: str


@dataclass(frozen=True, slots=True)
class TrustedContact:
    profile_id: str
    contact_id: str
    display_name: str
    encryption_fingerprint: str
    signing_fingerprint: str
    encryption_public_key: Any = field(repr=False)
    signing_public_key: Any = field(repr=False)
    status: TrustStatus = TrustStatus.UNVERIFIED


@dataclass(frozen=True, slots=True)
class KeyReference:
    profile_id: str
    fingerprint: str
    role: KeyRole
    private_key_path: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class PackageHeader:
    format: str
    version: int
    suite: str
    transfer_id: str
    sender_sig_fp: str
    recipient_enc_fp: str


@dataclass(frozen=True, slots=True)
class RawEnvelope:
    header: PackageHeader
    header_bytes: bytes = field(repr=False)
    wrapped_key: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    signature: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class Payload:
    filename: str = field(repr=False)
    data: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PreparedReceive:
    """Public metadata only. Plaintext and immutable context stay in service."""

    handle: str
    profile_id: str
    transfer_id: str
    sender_name: str
    sender_fingerprint: str
    recipient_fingerprint: str
    filename: str = field(repr=False)
    byte_count: int
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class WriteReceipt:
    """Returning a receipt means the complete output has committed."""

    destination: Path = field(repr=False)
    byte_count: int


@dataclass(frozen=True, slots=True)
class SendRequest:
    profile_id: str
    recipient_contact_id: str
    source_path: Path = field(repr=False)
    destination_path: Path = field(repr=False)
    passphrase: bytes = field(repr=False)
    overwrite_confirmed: bool = False
    expected_recipient_fingerprints: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ReceiveRequest:
    profile_id: str
    package_path: Path = field(repr=False)
    passphrase: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    code: ErrorCode
    stage: ProcessingStage | None
    message: str = ""

    def __post_init__(self) -> None:
        # Even an accidental ErrorInfo(..., message=str(library_error)) cannot
        # carry arbitrary library/user data into a returned UI result.
        object.__setattr__(self, "message", safe_message(self.code))


@dataclass(frozen=True, slots=True)
class OperationResult:
    status: OperationStatus
    stage: ProcessingStage | None = None
    transfer_id: str | None = None
    receipt: WriteReceipt | None = None
    prepared: PreparedReceive | None = None
    sender_name: str | None = None
    warnings: tuple[WarningCode, ...] = ()
    error: ErrorInfo | None = None
