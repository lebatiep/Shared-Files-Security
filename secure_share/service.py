"""File-sharing workflow with injected key, crypto and storage providers."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import secrets
from threading import Lock

from .config import (
    AES_KEY_BYTES,
    CIPHER_SUITE,
    FORMAT_NAME,
    FORMAT_VERSION,
    MAX_CIPHERTEXT_BYTES,
    MAX_FILE_BYTES,
    MAX_HEADER_BYTES,
    MAX_PACKAGE_BYTES,
    MIN_CIPHERTEXT_BYTES,
    NONCE_BYTES,
    SIGNATURE_BYTES,
    WRAPPED_KEY_BYTES,
)
from .errors import ErrorCode, ShareError
from .models import (
    ErrorInfo,
    KeyRole,
    OperationResult,
    OperationStatus,
    PackageHeader,
    PreparedReceive,
    ProcessingStage,
    RawEnvelope,
    ReceiveRequest,
    SendRequest,
    TrustStatus,
    WarningCode,
    WriteReceipt,
)
from .ports import (
    CryptoProvider,
    EnvelopeCodec,
    HistoryPort,
    KeyProvider,
    StoragePort,
    TrustProvider,
)


@dataclass(frozen=True, slots=True)
class _PendingReceive:
    metadata: PreparedReceive
    data: bytes = field(repr=False)
    protected_paths: tuple[Path, ...] = field(repr=False)
    warnings: tuple[WarningCode, ...] = ()


class FileShareService:
    """Keep one active operation and hold verified content until save or cancel."""

    def __init__(
        self,
        *,
        keys: KeyProvider,
        trust: TrustProvider,
        crypto: CryptoProvider,
        envelope: EnvelopeCodec,
        storage: StoragePort,
        history: HistoryPort,
    ) -> None:
        self._keys = keys
        self._trust = trust
        self._crypto = crypto
        self._envelope = envelope
        self._storage = storage
        self._history = history
        self._lock = Lock()
        self._pending: _PendingReceive | None = None

    @property
    def has_prepared(self) -> bool:
        """UI hint only; public mutations still acquire the operation lock."""
        return self._pending is not None

    @property
    def is_busy(self) -> bool:
        return self._lock.locked()

    @staticmethod
    def _failed(code: ErrorCode, stage: ProcessingStage | None) -> OperationResult:
        # Only the fixed, public message for this code may leave the service.
        safe_error = ShareError(code)
        return OperationResult(
            status=OperationStatus.FAILED,
            stage=stage,
            error=ErrorInfo(code=code, stage=stage, message=str(safe_error)),
        )

    @staticmethod
    def _require_bytes(value: object, *, exact: int | None = None) -> bytes:
        if not isinstance(value, bytes) or (exact is not None and len(value) != exact):
            raise ShareError(ErrorCode.INVALID_LENGTH)
        return value

    @staticmethod
    def _valid_hex(value: object, length: int) -> bool:
        return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None

    @staticmethod
    def _path(value: object) -> Path:
        """Capture a stable absolute path before keeping an operation context."""
        try:
            raw = os.fspath(value)
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                raise ValueError
            return Path(raw).resolve()
        except Exception:
            raise ShareError(ErrorCode.INVALID_REQUEST) from None

    @staticmethod
    def _matches_handle(state: _PendingReceive | None, handle: object) -> bool:
        return (
            state is not None
            and isinstance(handle, str)
            and handle.isascii()
            and len(handle) == len(state.metadata.handle)
            and secrets.compare_digest(handle, state.metadata.handle)
        )

    @classmethod
    def _check_header(cls, header: PackageHeader) -> None:
        if header.format != FORMAT_NAME:
            raise ShareError(ErrorCode.INVALID_SCHEMA)
        if type(header.version) is not int or header.version != FORMAT_VERSION:
            raise ShareError(ErrorCode.UNSUPPORTED_VERSION)
        if header.suite != CIPHER_SUITE:
            raise ShareError(ErrorCode.UNSUPPORTED_SUITE)
        if not (
            cls._valid_hex(header.transfer_id, 32)
            and cls._valid_hex(header.sender_sig_fp, 64)
            and cls._valid_hex(header.recipient_enc_fp, 64)
        ):
            raise ShareError(ErrorCode.INVALID_SCHEMA)

    @classmethod
    def _check_envelope(cls, package: RawEnvelope) -> None:
        cls._check_header(package.header)
        cls._require_bytes(package.header_bytes)
        if not 0 < len(package.header_bytes) <= MAX_HEADER_BYTES:
            raise ShareError(ErrorCode.INVALID_LENGTH)
        cls._require_bytes(package.wrapped_key, exact=WRAPPED_KEY_BYTES)
        cls._require_bytes(package.nonce, exact=NONCE_BYTES)
        cls._require_bytes(package.signature, exact=SIGNATURE_BYTES)
        cls._require_bytes(package.ciphertext)
        if not MIN_CIPHERTEXT_BYTES <= len(package.ciphertext) <= MAX_CIPHERTEXT_BYTES:
            raise ShareError(ErrorCode.INVALID_LENGTH)

    @staticmethod
    def _valid_receipt(receipt: object, destination: Path, length: int) -> bool:
        return (
            isinstance(receipt, WriteReceipt)
            and type(receipt.byte_count) is int
            and receipt.byte_count == length
            and Path(receipt.destination).resolve() == destination.resolve()
        )

    def send_file(self, request: SendRequest) -> OperationResult:
        if not self._lock.acquire(blocking=False):
            return self._failed(ErrorCode.BUSY, None)
        stage = ProcessingStage.READ
        try:
            if self._pending is not None:
                return self._failed(ErrorCode.BUSY, None)
            if not isinstance(request, SendRequest):
                raise ShareError(ErrorCode.INVALID_REQUEST)
            if type(request.overwrite_confirmed) is not bool or not isinstance(request.passphrase, bytes):
                raise ShareError(ErrorCode.INVALID_REQUEST)
            source = self._path(request.source_path)
            destination = self._path(request.destination_path)
            data = self._require_bytes(self._storage.read_limited(source, MAX_FILE_BYTES))
            if len(data) > MAX_FILE_BYTES:
                raise ShareError(ErrorCode.INPUT_TOO_LARGE)

            stage = ProcessingStage.TRUST
            profile = self._keys.get_profile(request.profile_id)
            if profile.profile_id != request.profile_id:
                raise ShareError(ErrorCode.PROFILE_INVALID)
            recipient = self._trust.resolve_recipient(request.profile_id, request.recipient_contact_id)
            if (
                recipient.profile_id != request.profile_id
                or recipient.contact_id != request.recipient_contact_id
                or recipient.status is not TrustStatus.VERIFIED
            ):
                raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
            header = PackageHeader(
                format=FORMAT_NAME,
                version=FORMAT_VERSION,
                suite=CIPHER_SUITE,
                transfer_id=secrets.token_hex(16),
                sender_sig_fp=profile.signing_fingerprint,
                recipient_enc_fp=recipient.encryption_fingerprint,
            )
            self._check_header(header)
            protected_paths = (source, *(self._path(p) for p in self._keys.protected_paths(request.profile_id)))

            stage = ProcessingStage.KEY_UNLOCK
            signing_key = self._keys.unlock_private_key(
                request.profile_id, KeyRole.SIGNING, profile.signing_fingerprint, request.passphrase
            )
            stage = ProcessingStage.PAYLOAD
            payload = self._require_bytes(self._envelope.build_payload(source.name, data))
            raw_header = self._require_bytes(self._envelope.build_header(header))
            if not 0 < len(raw_header) <= MAX_HEADER_BYTES:
                raise ShareError(ErrorCode.INVALID_LENGTH)

            # The providers generate fresh random material; no fallback key is used.
            stage = ProcessingStage.GCM
            aes_key = self._require_bytes(self._crypto.generate_aes_key(), exact=AES_KEY_BYTES)
            nonce = self._require_bytes(self._crypto.generate_nonce(), exact=NONCE_BYTES)
            wrapped_key = self._require_bytes(
                self._crypto.wrap_key(aes_key, recipient.encryption_public_key), exact=WRAPPED_KEY_BYTES
            )
            aad = self._require_bytes(self._envelope.build_aad(raw_header, wrapped_key))
            ciphertext = self._require_bytes(self._crypto.encrypt_payload(aes_key, nonce, payload, aad))
            if not MIN_CIPHERTEXT_BYTES <= len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
                raise ShareError(ErrorCode.INVALID_LENGTH)

            stage = ProcessingStage.SIGNATURE
            message = self._require_bytes(
                self._envelope.build_signature_input(raw_header, wrapped_key, nonce, ciphertext)
            )
            signature = self._require_bytes(
                self._crypto.sign_package(message, signing_key), exact=SIGNATURE_BYTES
            )
            package = RawEnvelope(
                header=header,
                header_bytes=raw_header,
                wrapped_key=wrapped_key,
                nonce=nonce,
                ciphertext=ciphertext,
                signature=signature,
            )
            encoded = self._require_bytes(self._envelope.serialize_envelope(package))
            if not encoded or len(encoded) > MAX_PACKAGE_BYTES:
                raise ShareError(ErrorCode.INPUT_TOO_LARGE)

            stage = ProcessingStage.SAVE
            try:
                receipt = self._storage.save_atomic(
                    encoded,
                    destination,
                    overwrite_confirmed=request.overwrite_confirmed,
                    protected_paths=protected_paths,
                )
                if not self._valid_receipt(receipt, destination, len(encoded)):
                    return self._failed(ErrorCode.SAVE_STATE_UNKNOWN, stage)
            except ShareError:
                raise
            except Exception:
                return self._failed(ErrorCode.SAVE_STATE_UNKNOWN, stage)
            return OperationResult(
                status=OperationStatus.SUCCESS,
                stage=stage,
                transfer_id=header.transfer_id,
                receipt=receipt,
                sender_name=profile.display_name,
            )
        except ShareError as exc:
            return self._failed(exc.code, stage)
        except OSError:
            return self._failed(ErrorCode.READ_FAILED if stage is ProcessingStage.READ else ErrorCode.INTERNAL_ERROR, stage)
        except Exception:
            return self._failed(ErrorCode.INTERNAL_ERROR, stage)
        finally:
            self._lock.release()

    def prepare_receive(self, request: ReceiveRequest) -> OperationResult:
        if not self._lock.acquire(blocking=False):
            return self._failed(ErrorCode.BUSY, None)
        stage = ProcessingStage.READ
        try:
            if self._pending is not None:
                return self._failed(ErrorCode.BUSY, None)
            if not isinstance(request, ReceiveRequest):
                raise ShareError(ErrorCode.INVALID_REQUEST)
            if not isinstance(request.passphrase, bytes):
                raise ShareError(ErrorCode.INVALID_REQUEST)
            package_path = self._path(request.package_path)
            snapshot = self._require_bytes(self._storage.read_limited(package_path, MAX_PACKAGE_BYTES))
            if not snapshot or len(snapshot) > MAX_PACKAGE_BYTES:
                raise ShareError(ErrorCode.INPUT_TOO_LARGE)

            stage = ProcessingStage.PARSE
            package = self._envelope.parse_envelope(snapshot)
            self._check_envelope(package)

            stage = ProcessingStage.TRUST
            sender = self._trust.resolve_sender(request.profile_id, package.header.sender_sig_fp)
            if (
                sender.profile_id != request.profile_id
                or sender.signing_fingerprint != package.header.sender_sig_fp
                or sender.status is not TrustStatus.VERIFIED
            ):
                raise ShareError(ErrorCode.UNTRUSTED_SENDER)

            stage = ProcessingStage.SIGNATURE
            message = self._require_bytes(self._envelope.build_signature_input(
                package.header_bytes, package.wrapped_key, package.nonce, package.ciphertext
            )
            )
            verified = self._crypto.verify_signature(package.signature, message, sender.signing_public_key)
            # The contract uses the cryptography verify convention: None or raise.
            # A mistakenly returned False must never become a successful check.
            if verified is not None:
                raise ShareError(ErrorCode.SIGNATURE_INVALID)

            stage = ProcessingStage.RECIPIENT
            key_ref = self._keys.resolve_decryption_key(request.profile_id, package.header.recipient_enc_fp)
            if (
                key_ref.profile_id != request.profile_id
                or key_ref.fingerprint != package.header.recipient_enc_fp
                or key_ref.role is not KeyRole.ENCRYPTION
            ):
                raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)
            protected_paths = (
                package_path,
                self._path(key_ref.private_key_path),
                *(self._path(p) for p in self._keys.protected_paths(request.profile_id)),
            )

            stage = ProcessingStage.KEY_UNLOCK
            private_key = self._keys.unlock_private_key(
                request.profile_id, KeyRole.ENCRYPTION, key_ref.fingerprint, request.passphrase
            )
            stage = ProcessingStage.UNWRAP
            aes_key = self._crypto.unwrap_key(package.wrapped_key, private_key)
            if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_BYTES:
                raise ShareError(ErrorCode.AES_KEY_LENGTH_INVALID)

            stage = ProcessingStage.GCM
            aad = self._require_bytes(self._envelope.build_aad(package.header_bytes, package.wrapped_key))
            plaintext = self._require_bytes(
                self._crypto.decrypt_payload(aes_key, package.nonce, package.ciphertext, aad)
            )
            stage = ProcessingStage.PAYLOAD
            payload = self._envelope.parse_payload(plaintext)
            self._require_bytes(payload.data)
            if not isinstance(payload.filename, str) or len(payload.data) > MAX_FILE_BYTES:
                raise ShareError(ErrorCode.PAYLOAD_INVALID)

            warnings: list[WarningCode] = []
            try:
                duplicate = self._history.has_seen(request.profile_id, package.header.transfer_id)
                if type(duplicate) is not bool:
                    raise ShareError(ErrorCode.HISTORY_INVALID)
                if duplicate:
                    warnings.append(WarningCode.DUPLICATE_TRANSFER)
            except Exception:
                duplicate = False
                warnings.append(WarningCode.HISTORY_UNAVAILABLE)

            prepared = PreparedReceive(
                handle=secrets.token_urlsafe(32),
                profile_id=request.profile_id,
                transfer_id=package.header.transfer_id,
                sender_name=sender.display_name,
                sender_fingerprint=package.header.sender_sig_fp,
                recipient_fingerprint=package.header.recipient_enc_fp,
                filename=payload.filename,
                byte_count=len(payload.data),
                duplicate=duplicate,
            )
            self._pending = _PendingReceive(
                metadata=prepared,
                data=payload.data,
                protected_paths=protected_paths,
                warnings=tuple(warnings),
            )
            return OperationResult(
                status=OperationStatus.PREPARED,
                stage=stage,
                transfer_id=prepared.transfer_id,
                prepared=prepared,
                sender_name=prepared.sender_name,
                warnings=tuple(warnings),
            )
        except ShareError as exc:
            return self._failed(exc.code, stage)
        except OSError:
            return self._failed(ErrorCode.READ_FAILED if stage is ProcessingStage.READ else ErrorCode.INTERNAL_ERROR, stage)
        except Exception:
            return self._failed(ErrorCode.INTERNAL_ERROR, stage)
        finally:
            self._lock.release()

    def save_received(
        self, handle: str, destination: Path, *, overwrite_confirmed: bool = False
    ) -> OperationResult:
        if not self._lock.acquire(blocking=False):
            return self._failed(ErrorCode.BUSY, None)
        try:
            state = self._pending
            if not self._matches_handle(state, handle):
                return self._failed(ErrorCode.INVALID_HANDLE, ProcessingStage.SAVE)
            assert state is not None
            try:
                if type(overwrite_confirmed) is not bool:
                    raise ShareError(ErrorCode.INVALID_REQUEST)
                destination = self._path(destination)
            except ShareError:
                return self._failed(ErrorCode.INVALID_REQUEST, ProcessingStage.SAVE)
            try:
                receipt = self._storage.save_atomic(
                    state.data,
                    destination,
                    overwrite_confirmed=overwrite_confirmed,
                    protected_paths=state.protected_paths,
                )
                if not self._valid_receipt(receipt, destination, len(state.data)):
                    self._pending = None
                    return self._failed(ErrorCode.SAVE_STATE_UNKNOWN, ProcessingStage.SAVE)
            except ShareError as exc:
                # Known pre-commit errors allow choosing a different destination.
                if exc.code not in (
                    ErrorCode.SAVE_FAILED,
                    ErrorCode.DESTINATION_EXISTS,
                    ErrorCode.PROTECTED_PATH,
                    ErrorCode.INVALID_REQUEST,
                ):
                    self._pending = None
                    return self._failed(ErrorCode.SAVE_STATE_UNKNOWN, ProcessingStage.SAVE)
                return self._failed(exc.code, ProcessingStage.SAVE)
            except Exception:
                self._pending = None
                return self._failed(ErrorCode.SAVE_STATE_UNKNOWN, ProcessingStage.SAVE)

            # The file is committed. Consume first, even if recording history fails.
            self._pending = None
            warnings = list(state.warnings)
            try:
                self._history.record(state.metadata.profile_id, state.metadata.transfer_id)
            except Exception:
                warnings.append(WarningCode.HISTORY_NOT_SAVED)
            return OperationResult(
                status=OperationStatus.SUCCESS,
                stage=ProcessingStage.SAVE,
                transfer_id=state.metadata.transfer_id,
                receipt=receipt,
                sender_name=state.metadata.sender_name,
                warnings=tuple(warnings),
            )
        finally:
            self._lock.release()

    def discard_prepared(self, handle: str) -> OperationResult:
        if not self._lock.acquire(blocking=False):
            return self._failed(ErrorCode.BUSY, None)
        try:
            state = self._pending
            if not self._matches_handle(state, handle):
                return self._failed(ErrorCode.INVALID_HANDLE, None)
            assert state is not None
            self._pending = None
            return OperationResult(
                status=OperationStatus.CANCELLED,
                transfer_id=state.metadata.transfer_id,
            )
        finally:
            self._lock.release()

    def close(self) -> None:
        """Wait for an active operation, then discard in-memory prepared data.

        This drops references; it does not claim to securely erase Python memory.
        """
        with self._lock:
            self._pending = None
