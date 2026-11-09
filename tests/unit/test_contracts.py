"""Safety and interoperability checks for Tiệp's shared contracts."""

from dataclasses import FrozenInstanceError, fields
import json
from pathlib import Path
import unittest

from secure_share import config
from secure_share.errors import ErrorCode, ShareError, safe_message
from secure_share.models import (
    ErrorInfo,
    KeyReference,
    KeyRole,
    OperationResult,
    OperationStatus,
    PackageHeader,
    Payload,
    PreparedReceive,
    ProcessingStage,
    RawEnvelope,
    ReceiveRequest,
    SendRequest,
    TrustStatus,
    TrustedContact,
    WarningCode,
    WriteReceipt,
)


class ContractsTests(unittest.TestCase):
    def test_new_contact_is_unverified_until_explicit_confirmation(self):
        contact = TrustedContact("alice", "bob", "Bob", "a" * 64, "b" * 64, object(), object())
        self.assertIs(contact.status, TrustStatus.UNVERIFIED)
        verified = TrustedContact(
            "alice", "bob", "Bob", "a" * 64, "b" * 64,
            object(), object(), status=TrustStatus.VERIFIED,
        )
        self.assertIs(verified.status, TrustStatus.VERIFIED)

    def test_passphrases_and_source_paths_are_not_in_request_repr(self):
        marker = b"never-display-this-password"
        send = SendRequest("alice", "bob", Path("private-source.pdf"), Path("out"), marker)
        receive = ReceiveRequest("bob", Path("private-package.sfile"), marker)
        for value in (send, receive):
            self.assertNotIn(marker.decode(), repr(value))
            self.assertNotIn("private-", repr(value))

    def test_raw_crypto_payload_and_key_references_are_not_in_repr(self):
        secret = b"do-not-log-contents"
        h = PackageHeader("SFILE", 1, config.CIPHER_SUITE, "a" * 32, "b" * 64, "c" * 64)
        envelope = RawEnvelope(h, secret, secret, secret, secret, secret)
        contact = TrustedContact("alice", "bob", "Bob", "a" * 64, "b" * 64, secret, secret)
        values = [
            envelope,
            contact,
            Payload("private-name.pdf", secret),
            KeyReference("alice", "a" * 64, KeyRole.ENCRYPTION, Path("private-key.pem")),
            WriteReceipt(Path("private-output.pdf"), 3),
        ]
        for value in values:
            representation = repr(value)
            self.assertNotIn(secret.decode(), representation)
            self.assertNotIn("private-", representation)

    def test_ui_prepared_metadata_has_no_plaintext_field(self):
        prepared = PreparedReceive("opaque-handle", "bob", "a" * 32, "Alice", "b" * 64, "c" * 64, "private-name.pdf", 5)
        result = OperationResult(OperationStatus.PREPARED, prepared=prepared)
        field_names = {f.name for f in fields(prepared)} | {f.name for f in fields(result)}
        self.assertTrue({"data", "plaintext", "passphrase", "private_key"}.isdisjoint(field_names))
        self.assertNotIn("private-name.pdf", repr(result))

    def test_contract_values_cannot_be_reassigned(self):
        value = ReceiveRequest("bob", Path("in.sfile"), b"secret")
        with self.assertRaises(FrozenInstanceError):
            value.profile_id = "mallory"  # type: ignore[misc]

    def test_every_error_code_has_a_safe_owned_message(self):
        messages = [safe_message(code) for code in ErrorCode]
        self.assertTrue(all(isinstance(message, str) and message for message in messages))
        self.assertGreater(len(set(messages)), len(messages) // 2)

    def test_adapter_exception_cannot_inject_a_secret_into_public_error(self):
        secret = "password=do-not-print-me"
        error = ShareError(ErrorCode.KEY_UNLOCK_FAILED, message=secret)
        detail = ErrorInfo(ErrorCode.KEY_UNLOCK_FAILED, ProcessingStage.KEY_UNLOCK, secret)
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error))
        self.assertNotIn(secret, repr(detail))
        self.assertEqual(detail.message, safe_message(ErrorCode.KEY_UNLOCK_FAILED))

    def test_unrecognised_error_input_is_not_echoed(self):
        secret = "never-echo-this"
        error = ShareError(secret)  # type: ignore[arg-type]
        self.assertEqual(error.code, ErrorCode.INTERNAL_ERROR)
        self.assertNotIn(secret, str(error))

    def test_ciphertext_upper_bound_includes_payload_prefix_metadata_and_tag(self):
        maximum_payload = 4 + config.MAX_METADATA_BYTES + config.MAX_FILE_BYTES
        self.assertEqual(config.MAX_CIPHERTEXT_BYTES, maximum_payload + config.GCM_TAG_BYTES)
        # Base64 expands by four thirds; envelope cap must fit a full-size file.
        encoded_ciphertext = 4 * ((config.MAX_CIPHERTEXT_BYTES + 2) // 3)
        self.assertLess(encoded_ciphertext + 16_384, config.MAX_PACKAGE_BYTES)

    def test_statuses_and_warnings_are_json_values(self):
        value = json.dumps({"status": OperationStatus.SUCCESS, "warning": WarningCode.HISTORY_NOT_SAVED})
        self.assertEqual(json.loads(value), {"status": "success", "warning": "HISTORY_NOT_SAVED"})


if __name__ == "__main__":
    unittest.main()
