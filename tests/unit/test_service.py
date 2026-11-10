"""Behavioral tests of Tiệp's orchestration, using TEST-ONLY port doubles.

These doubles are not cryptography or production adapters. Real AES/RSA tests
are separate; collaborator implementations still need their own acceptance.
"""

import pytest
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest

from secure_share.config import MAX_FILE_BYTES, MAX_PACKAGE_BYTES
from secure_share.errors import ErrorCode, ShareError
from secure_share.models import (
    KeyReference, KeyRole, OperationStatus, PackageHeader, Payload,
    ProcessingStage, ProfileSummary, RawEnvelope, ReceiveRequest, SendRequest,
    TrustedContact, TrustStatus, WarningCode, WriteReceipt,
)
from secure_share.service import FileShareService


ALICE_ENC, ALICE_SIG, BOB_ENC, BOB_SIG = (c * 64 for c in "abcd")
PASSPHRASE = b"correct-test-passphrase"


class StorageDouble:
    def __init__(self, events):
        self.events = events
        self.files = {}
        self.writes = []
        self.reads = []
        self.save_error = None
        self.commit_then_raise = False
        self.bad_receipt = False
        self.forced_read = None

    def read_limited(self, path, max_bytes):
        self.events.append("read")
        self.reads.append((path, max_bytes))
        if self.forced_read is not None:
            return self.forced_read
        return self.files[path]

    def save_atomic(self, data, destination, *, overwrite_confirmed=False, protected_paths=()):
        self.events.append("save")
        if self.save_error:
            raise self.save_error
        if destination in protected_paths:
            raise ShareError(ErrorCode.PROTECTED_PATH)
        if destination in self.files and not overwrite_confirmed:
            raise ShareError(ErrorCode.DESTINATION_EXISTS)
        self.files[destination] = data
        self.writes.append((destination, data, protected_paths))
        if self.commit_then_raise:
            raise RuntimeError("private file content must not leave the adapter")
        return WriteReceipt(destination, len(data) + int(self.bad_receipt))


class KeysDouble:
    def __init__(self, events):
        self.events = events
        self.unlocked = []
        self.recipient_override = None
        self.profiles = {
            "alice": ProfileSummary("alice", "Alice", ALICE_ENC, ALICE_SIG),
            "bob": ProfileSummary("bob", "Bob", BOB_ENC, BOB_SIG),
        }

    def get_profile(self, profile_id):
        self.events.append("profile")
        return self.profiles[profile_id]

    def protected_paths(self, profile_id):
        return (Path("runtime") / profile_id / "private.pem",)

    def resolve_decryption_key(self, profile_id, fingerprint):
        self.events.append("recipient")
        if self.recipient_override is not None:
            return self.recipient_override
        if profile_id != "bob" or fingerprint != BOB_ENC:
            raise ShareError(ErrorCode.RECIPIENT_KEY_NOT_FOUND)
        return KeyReference("bob", BOB_ENC, KeyRole.ENCRYPTION, Path("runtime/bob/private.pem"))

    def unlock_private_key(self, profile_id, role, fingerprint, passphrase):
        self.events.append("unlock")
        if passphrase != PASSPHRASE:
            raise ShareError(ErrorCode.KEY_UNLOCK_FAILED)
        self.unlocked.append((profile_id, role, fingerprint))
        return (profile_id, role, fingerprint)


class TrustDouble:
    def __init__(self, events):
        self.events = events
        self.recipient = TrustedContact(
            "alice", "bob", "Bob", BOB_ENC, BOB_SIG, object(), object(), TrustStatus.VERIFIED
        )
        self.sender = TrustedContact(
            "bob", "alice", "Alice pinned", ALICE_ENC, ALICE_SIG,
            object(), object(), TrustStatus.VERIFIED,
        )

    def resolve_recipient(self, profile_id, contact_id):
        self.events.append("trust-recipient")
        return self.recipient

    def resolve_sender(self, profile_id, signing_fingerprint):
        self.events.append("trust-sender")
        return self.sender


class CryptoDouble:
    def __init__(self, events):
        self.events = events
        self.fail = None
        self.key = b"K" * 32
        self.unwrapped_key = b"K" * 32
        self.verify_return = None
        self.counter = 0

    def generate_aes_key(self):
        self.events.append("fresh-key")
        return self.key

    def generate_nonce(self):
        self.events.append("fresh-nonce")
        self.counter += 1
        return self.counter.to_bytes(12, "big")

    def wrap_key(self, aes_key, public_key):
        self.events.append("wrap")
        return b"W" * 384

    def unwrap_key(self, wrapped_key, private_key):
        self.events.append("unwrap")
        if self.fail == "unwrap":
            raise ShareError(ErrorCode.UNWRAP_FAILED)
        return self.unwrapped_key

    def encrypt_payload(self, key, nonce, payload, aad):
        self.events.append("encrypt")
        return payload + b"T" * 16

    def decrypt_payload(self, key, nonce, ciphertext, aad):
        self.events.append("decrypt")
        if self.fail == "gcm":
            raise ShareError(ErrorCode.GCM_AUTH_FAILED)
        return ciphertext[:-16]

    @staticmethod
    def _signature(message):
        return hashlib.sha256(message).digest() * 12

    def sign_package(self, message, private_key):
        self.events.append("sign")
        return self._signature(message)

    def verify_signature(self, signature, message, public_key):
        self.events.append("verify")
        if self.fail == "signature" or signature != self._signature(message):
            raise ShareError(ErrorCode.SIGNATURE_INVALID)
        return self.verify_return


class CodecDouble:
    def __init__(self, events):
        self.events = events
        self.packages = {}
        self.next_id = 0
        self.payload_override = None
        self.aad_override = None
        self.serialized_override = None

    def build_header(self, header):
        return json.dumps(asdict(header)).encode("utf-8")

    def build_payload(self, filename, data):
        return filename.encode("utf-8") + b"\x00" + data

    def parse_payload(self, data):
        self.events.append("payload")
        if self.payload_override is not None:
            return self.payload_override
        name, content = data.split(b"\x00", 1)
        return Payload(name.decode("utf-8"), content)

    def build_aad(self, header_bytes, wrapped_key):
        if self.aad_override is not None:
            return self.aad_override
        return b"test-aad" + header_bytes + wrapped_key

    def build_signature_input(self, header_bytes, wrapped_key, nonce, ciphertext):
        return b"test-message" + header_bytes + wrapped_key + nonce + ciphertext

    def serialize_envelope(self, envelope):
        self.next_id += 1
        encoded = b"test-only-package-" + str(self.next_id).encode("ascii")
        self.packages[encoded] = envelope
        return encoded if self.serialized_override is None else self.serialized_override

    def parse_envelope(self, data):
        self.events.append("parse")
        return self.packages[data]


class HistoryDouble:
    def __init__(self, events):
        self.events = events
        self.seen = set()
        self.records = []
        self.read_error = False
        self.write_error = False

    def has_seen(self, profile_id, transfer_id):
        self.events.append("history-read")
        if self.read_error:
            raise ShareError(ErrorCode.HISTORY_INVALID)
        return (profile_id, transfer_id) in self.seen

    def record(self, profile_id, transfer_id):
        self.events.append("history-write")
        if self.write_error:
            raise ShareError(ErrorCode.HISTORY_INVALID)
        self.seen.add((profile_id, transfer_id))
        self.records.append((profile_id, transfer_id))


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.storage = StorageDouble(self.events)
        self.keys = KeysDouble(self.events)
        self.trust = TrustDouble(self.events)
        self.crypto = CryptoDouble(self.events)
        self.codec = CodecDouble(self.events)
        self.history = HistoryDouble(self.events)
        self.service = FileShareService(
            keys=self.keys, trust=self.trust, crypto=self.crypto,
            envelope=self.codec, storage=self.storage, history=self.history,
        )
        self.source = Path("input.bin").resolve()
        self.package = Path("sample.sfile").resolve()
        self.output = Path("restored.bin").resolve()
        self.content = b"\x00private-content\xff\n"
        self.storage.files[self.source] = self.content

    def send(self, **overrides):
        req = SendRequest("alice", "bob", self.source, self.package, PASSPHRASE)
        result = self.service.send_file(replace(req, **overrides))
        return result

    def prepared(self, **overrides):
        if self.package not in self.storage.files:
            self.assertEqual(self.send().status, OperationStatus.SUCCESS)
        req = ReceiveRequest("bob", self.package, PASSPHRASE)
        return self.service.prepare_receive(replace(req, **overrides))

    def mutate_package(self, **changes):
        encoded = self.storage.files[self.package]
        self.codec.packages[encoded] = replace(self.codec.packages[encoded], **changes)

    def assert_failed(self, result, code, stage=None):
        self.assertEqual(result.status, OperationStatus.FAILED)
        self.assertEqual(result.error.code, code)
        if stage is not None:
            self.assertEqual(result.stage, stage)
        self.assertIsNone(result.receipt)
        self.assertIsNone(result.prepared)

    def test_round_trip_is_prepared_then_explicitly_saved(self):
        prepared = self.prepared()
        self.assertEqual(prepared.status, OperationStatus.PREPARED)
        self.assertNotIn(self.output, self.storage.files)
        self.assertEqual(prepared.prepared.sender_name, "Alice pinned")
        self.assertFalse(hasattr(prepared.prepared, "data"))
        self.assertNotIn("private-content", repr(prepared))
        result = self.service.save_received(prepared.prepared.handle, self.output)
        self.assertEqual(result.status, OperationStatus.SUCCESS)
        self.assertEqual(self.storage.files[self.output], self.content)
        self.assertEqual(self.history.records, [("bob", prepared.transfer_id)])
        self.assertFalse(self.service.has_prepared)

    @pytest.mark.case("S01")
    def test_empty_file_round_trip(self):
        self.storage.files[self.source] = b""
        result = self.prepared()
        self.assertEqual(result.prepared.byte_count, 0)
        self.service.save_received(result.prepared.handle, self.output)
        self.assertEqual(self.storage.files[self.output], b"")

    def test_receive_order_and_single_snapshot(self):
        self.send()
        self.events.clear()
        reads = len(self.storage.reads)
        result = self.prepared()
        self.assertEqual(result.status, OperationStatus.PREPARED)
        self.assertEqual(len(self.storage.reads), reads + 1)
        self.assertEqual(self.events, [
            "read", "parse", "trust-sender", "verify", "recipient",
            "unlock", "unwrap", "decrypt", "payload", "history-read",
        ])
        # Replacing the file after prepare cannot change saved content/context.
        self.storage.files[self.package] = b"different later snapshot"
        self.service.save_received(result.prepared.handle, self.output)
        self.assertEqual(self.storage.files[self.output], self.content)

    @pytest.mark.case("A01")
    def test_untrusted_sender_stops_before_verify(self):
        self.send()
        self.events.clear()
        self.trust.sender = replace(self.trust.sender, status=TrustStatus.UNVERIFIED)
        self.assert_failed(self.prepared(), ErrorCode.UNTRUSTED_SENDER, ProcessingStage.TRUST)
        self.assertNotIn("verify", self.events)
        self.assertNotIn("decrypt", self.events)

    def test_sender_contact_must_belong_to_requested_profile(self):
        self.send()
        self.trust.sender = replace(self.trust.sender, profile_id="alice")
        self.assert_failed(self.prepared(), ErrorCode.UNTRUSTED_SENDER)

    @pytest.mark.case("A02")
    def test_signature_failure_stops_before_private_key_unlock(self):
        self.send()
        self.events.clear()
        self.crypto.fail = "signature"
        self.assert_failed(self.prepared(), ErrorCode.SIGNATURE_INVALID, ProcessingStage.SIGNATURE)
        self.assertNotIn("unlock", self.events)
        self.assertNotIn("unwrap", self.events)
        self.assertFalse(self.service.has_prepared)

    def test_false_verify_return_is_not_success(self):
        self.send()
        self.crypto.verify_return = False
        self.assert_failed(self.prepared(), ErrorCode.SIGNATURE_INVALID)

    @pytest.mark.case("A06")
    def test_wrong_recipient_stops_before_unwrap(self):
        self.send()
        self.events.clear()
        self.assert_failed(self.prepared(profile_id="alice"), ErrorCode.UNTRUSTED_SENDER)
        self.trust.sender = replace(self.trust.sender, profile_id="alice")
        self.assert_failed(self.prepared(profile_id="alice"), ErrorCode.RECIPIENT_KEY_NOT_FOUND)
        self.assertNotIn("unwrap", self.events)

    def test_wrong_key_reference_role_is_rejected(self):
        self.send()
        self.keys.recipient_override = KeyReference("bob", BOB_ENC, KeyRole.SIGNING, Path("wrong.pem"))
        self.assert_failed(self.prepared(), ErrorCode.RECIPIENT_KEY_NOT_FOUND)

    def test_wrong_key_reference_profile_is_rejected(self):
        self.send()
        self.keys.recipient_override = KeyReference("alice", BOB_ENC, KeyRole.ENCRYPTION, Path("wrong.pem"))
        self.assert_failed(self.prepared(), ErrorCode.RECIPIENT_KEY_NOT_FOUND)

    @pytest.mark.case("I07")
    def test_bad_passphrase_is_a_safe_failure(self):
        self.send()
        result = self.prepared(passphrase=b"never-echo-this-passphrase")
        self.assert_failed(result, ErrorCode.KEY_UNLOCK_FAILED, ProcessingStage.KEY_UNLOCK)
        self.assertNotIn("never-echo", repr(result))

    @pytest.mark.case("A07")
    def test_unwrap_failure_has_no_prepared_plaintext(self):
        self.send()
        self.crypto.fail = "unwrap"
        self.assert_failed(self.prepared(), ErrorCode.UNWRAP_FAILED, ProcessingStage.UNWRAP)
        self.assertFalse(self.service.has_prepared)

    @pytest.mark.case("A08")
    def test_unwrapped_aes_key_length_is_checked(self):
        self.send()
        self.crypto.unwrapped_key = b"K" * 31
        self.assert_failed(self.prepared(), ErrorCode.AES_KEY_LENGTH_INVALID, ProcessingStage.UNWRAP)

    @pytest.mark.case("A09")
    def test_gcm_failure_stops_before_payload_and_save(self):
        self.send()
        self.events.clear()
        self.crypto.fail = "gcm"
        self.assert_failed(self.prepared(), ErrorCode.GCM_AUTH_FAILED, ProcessingStage.GCM)
        self.assertNotIn("payload", self.events)
        self.assertNotIn("save", self.events)

    @pytest.mark.case("A12")
    def test_oversized_decrypted_file_is_rejected(self):
        self.send()
        self.codec.payload_override = Payload("x", b"x" * (MAX_FILE_BYTES + 1))
        self.assert_failed(self.prepared(), ErrorCode.PAYLOAD_INVALID, ProcessingStage.PAYLOAD)
        self.assertNotIn(self.output, self.storage.files)

    def test_invalid_crypto_lengths_stop_before_save(self):
        self.crypto.key = b"K" * 31
        self.assert_failed(self.send(), ErrorCode.INVALID_LENGTH)
        self.assertEqual(self.storage.writes, [])

    def test_aad_must_be_bytes(self):
        self.codec.aad_override = "not bytes"
        self.assert_failed(self.send(), ErrorCode.INVALID_LENGTH)

    def test_serialized_package_cap_is_checked(self):
        self.codec.serialized_override = b"x" * (MAX_PACKAGE_BYTES + 1)
        self.assert_failed(self.send(), ErrorCode.INPUT_TOO_LARGE)
        self.assertEqual(self.storage.writes, [])

    @pytest.mark.case("S04")
    def test_input_cap_is_defended_even_if_storage_breaks_contract(self):
        self.storage.forced_read = b"x" * (MAX_FILE_BYTES + 1)
        self.assert_failed(self.send(), ErrorCode.INPUT_TOO_LARGE, ProcessingStage.READ)
        self.assertNotIn("trust-recipient", self.events)

    def test_received_package_cap_precedes_parser(self):
        self.send()
        self.events.clear()
        self.storage.forced_read = b"x" * (MAX_PACKAGE_BYTES + 1)
        self.assert_failed(self.prepared(), ErrorCode.INPUT_TOO_LARGE)
        self.assertNotIn("parse", self.events)

    def test_bad_envelope_length_precedes_trust(self):
        self.send()
        self.mutate_package(nonce=b"bad")
        self.events.clear()
        self.assert_failed(self.prepared(), ErrorCode.INVALID_LENGTH, ProcessingStage.PARSE)
        self.assertNotIn("trust-sender", self.events)

    def test_bool_version_is_not_integer_version(self):
        self.send()
        encoded = self.storage.files[self.package]
        env = self.codec.packages[encoded]
        self.mutate_package(header=replace(env.header, version=True))
        self.assert_failed(self.prepared(), ErrorCode.UNSUPPORTED_VERSION)

    @pytest.mark.case("S06")
    def test_send_requires_trusted_recipient_in_same_profile(self):
        for recipient in (
            replace(self.trust.recipient, status=TrustStatus.UNVERIFIED),
            replace(self.trust.recipient, profile_id="bob"),
            replace(self.trust.recipient, contact_id="mallory"),
        ):
            with self.subTest(recipient=recipient):
                self.trust.recipient = recipient
                self.assert_failed(self.send(), ErrorCode.UNTRUSTED_RECIPIENT)
        self.assertEqual(self.storage.writes, [])

    @pytest.mark.case("S09")
    def test_send_stops_if_confirmed_recipient_keys_changed(self):
        recipient = self.trust.recipient
        confirmed = (recipient.encryption_fingerprint, recipient.signing_fingerprint)
        self.trust.recipient = replace(recipient, encryption_fingerprint="0" * 64)
        result = self.send(expected_recipient_fingerprints=confirmed)
        self.assert_failed(result, ErrorCode.UNTRUSTED_RECIPIENT, ProcessingStage.TRUST)
        self.assertEqual(self.storage.writes, [])

    def test_overwrite_requires_actual_boolean(self):
        self.assert_failed(self.send(overwrite_confirmed="yes"), ErrorCode.INVALID_REQUEST)
        ready = self.prepared()
        result = self.service.save_received(ready.prepared.handle, self.output, overwrite_confirmed="yes")
        self.assert_failed(result, ErrorCode.INVALID_REQUEST)
        self.assertTrue(self.service.has_prepared)

    def test_unicode_and_invalid_handles_are_safe(self):
        ready = self.prepared()
        for value in ("Tiệp", "☃", "wrong", "", None, "x" * 10000):
            with self.subTest(value_type=type(value).__name__):
                self.assert_failed(self.service.save_received(value, self.output), ErrorCode.INVALID_HANDLE)
                self.assert_failed(self.service.discard_prepared(value), ErrorCode.INVALID_HANDLE)
                self.assertTrue(self.service.has_prepared)
        self.assertEqual(self.service.discard_prepared(ready.prepared.handle).status, OperationStatus.CANCELLED)

    def test_bad_pathlike_is_safe_and_keeps_handle(self):
        class BadPath:
            def __fspath__(self):
                raise RuntimeError("secret path detail")
        ready = self.prepared()
        result = self.service.save_received(ready.prepared.handle, BadPath())
        self.assert_failed(result, ErrorCode.INVALID_REQUEST)
        self.assertNotIn("secret path", repr(result))
        self.assertTrue(self.service.has_prepared)

    @pytest.mark.case("R07")
    def test_discard_writes_nothing_and_invalidates_handle(self):
        ready = self.prepared()
        writes = len(self.storage.writes)
        result = self.service.discard_prepared(ready.prepared.handle)
        self.assertEqual(result.status, OperationStatus.CANCELLED)
        self.assertEqual(len(self.storage.writes), writes)
        self.assertEqual(self.history.records, [])
        self.assert_failed(self.service.save_received(ready.prepared.handle, self.output), ErrorCode.INVALID_HANDLE)

    @pytest.mark.case("O06")
    def test_prepared_operation_blocks_new_work(self):
        ready = self.prepared()
        self.assert_failed(self.send(), ErrorCode.BUSY)
        self.assert_failed(self.prepared(), ErrorCode.BUSY)
        self.service.discard_prepared(ready.prepared.handle)
        self.assertEqual(self.prepared().status, OperationStatus.PREPARED)

    def test_known_precommit_failure_allows_new_destination(self):
        ready = self.prepared()
        self.storage.save_error = ShareError(ErrorCode.SAVE_FAILED)
        self.assert_failed(self.service.save_received(ready.prepared.handle, self.output), ErrorCode.SAVE_FAILED)
        self.assertTrue(self.service.has_prepared)
        self.assertEqual(self.history.records, [])
        self.storage.save_error = None
        self.assertEqual(self.service.save_received(ready.prepared.handle, self.output).status, OperationStatus.SUCCESS)

    def test_protected_paths_include_absolute_snapshot_and_key(self):
        ready = self.prepared()
        self.assert_failed(self.service.save_received(ready.prepared.handle, self.package), ErrorCode.PROTECTED_PATH)
        result = self.service.save_received(ready.prepared.handle, self.output)
        self.assertEqual(result.status, OperationStatus.SUCCESS)
        paths = self.storage.writes[-1][2]
        self.assertIn(self.package, paths)
        self.assertIn(Path("runtime/bob/private.pem").resolve(), paths)
        self.assertTrue(all(p.is_absolute() for p in paths))

    def test_output_commit_then_unknown_error_consumes_handle(self):
        ready = self.prepared()
        self.storage.commit_then_raise = True
        result = self.service.save_received(ready.prepared.handle, self.output)
        self.assert_failed(result, ErrorCode.SAVE_STATE_UNKNOWN)
        self.assertEqual(self.storage.files[self.output], self.content)
        self.assertFalse(self.service.has_prepared)
        self.assertEqual(self.history.records, [])
        self.assertNotIn("private file content", repr(result))

    def test_malformed_receipt_is_uncertain_not_retryable(self):
        ready = self.prepared()
        self.storage.bad_receipt = True
        self.assert_failed(self.service.save_received(ready.prepared.handle, self.output), ErrorCode.SAVE_STATE_UNKNOWN)
        self.assertFalse(self.service.has_prepared)

    def test_history_failure_after_commit_stays_success(self):
        ready = self.prepared()
        self.history.write_error = True
        result = self.service.save_received(ready.prepared.handle, self.output)
        self.assertEqual(result.status, OperationStatus.SUCCESS)
        self.assertIn(WarningCode.HISTORY_NOT_SAVED, result.warnings)
        self.assertEqual(self.storage.files[self.output], self.content)
        self.assertFalse(self.service.has_prepared)
        self.assert_failed(self.service.save_received(ready.prepared.handle, self.output), ErrorCode.INVALID_HANDLE)

    def test_history_unavailable_warns_without_bypassing_crypto(self):
        self.history.read_error = True
        result = self.prepared()
        self.assertEqual(result.status, OperationStatus.PREPARED)
        self.assertIn(WarningCode.HISTORY_UNAVAILABLE, result.warnings)
        self.assertIn("verify", self.events)
        self.assertIn("decrypt", self.events)

    @pytest.mark.case("L04")
    def test_duplicate_warns_but_allows_deliberate_reopen(self):
        first = self.prepared()
        self.service.save_received(first.prepared.handle, self.output)
        again = self.prepared()
        self.assertTrue(again.prepared.duplicate)
        self.assertIn(WarningCode.DUPLICATE_TRANSFER, again.warnings)
        self.assertEqual(self.service.save_received(again.prepared.handle, Path("copy.bin")).status, OperationStatus.SUCCESS)

    def test_original_profile_context_survives_ui_selection_change(self):
        ready = self.prepared()
        # A new UI-selected profile cannot be passed into save_received at all.
        self.keys.profiles["bob"] = replace(self.keys.profiles["bob"], profile_id="mallory")
        self.service.save_received(ready.prepared.handle, self.output)
        self.assertEqual(self.history.records, [("bob", ready.transfer_id)])

    def test_close_discards_pending_without_writing(self):
        ready = self.prepared()
        writes = len(self.storage.writes)
        self.service.close()
        self.assertFalse(self.service.has_prepared)
        self.assertEqual(len(self.storage.writes), writes)
        self.assert_failed(self.service.discard_prepared(ready.prepared.handle), ErrorCode.INVALID_HANDLE)

    def test_unexpected_exception_does_not_expose_detail(self):
        def explode(profile_id):
            raise RuntimeError("passphrase plaintext private.pem")
        self.keys.get_profile = explode
        result = self.send()
        self.assert_failed(result, ErrorCode.INTERNAL_ERROR)
        self.assertNotIn("private.pem", repr(result))
        self.assertNotIn("plaintext", repr(result))

    @pytest.mark.case("O06")
    def test_real_concurrent_call_returns_busy(self):
        self.send()
        entered, release = Event(), Event()
        original_read = self.storage.read_limited
        result = []

        def blocking_read(path, max_bytes):
            entered.set()
            if not release.wait(3):
                raise AssertionError("bounded test wait expired")
            return original_read(path, max_bytes)

        self.storage.read_limited = blocking_read
        worker = Thread(target=lambda: result.append(self.prepared()), daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assert_failed(self.send(), ErrorCode.BUSY)
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0].status, OperationStatus.PREPARED)


if __name__ == "__main__":
    unittest.main()
