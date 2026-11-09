"""Behavior tests for Tiệp's history, using no real storage backend."""

from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from secure_share.config import MAX_HISTORY_BYTES, MAX_HISTORY_ENTRIES
from secure_share.errors import ErrorCode, ShareError
from secure_share.history import JsonHistoryStore, MemoryHistoryStore
from secure_share.models import WriteReceipt


TRANSFER_A = "a" * 32
TRANSFER_B = "b" * 32


class FakeStorage:
    def __init__(self) -> None:
        self.files: dict[Path, bytes] = {}
        self.read_calls: list[tuple[Path, int]] = []
        self.save_calls: list[tuple[bytes, Path, bool, tuple[Path, ...]]] = []
        self.read_error: Exception | None = None
        self.save_error: Exception | None = None
        self.enforce_read_cap = True

    def read_limited(self, path: Path, max_bytes: int) -> bytes:
        self.read_calls.append((path, max_bytes))
        if self.read_error:
            raise self.read_error
        if path not in self.files:
            raise FileNotFoundError(path)
        data = self.files[path]
        if self.enforce_read_cap and len(data) > max_bytes:
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
        self.save_calls.append((data, destination, overwrite_confirmed, protected_paths))
        if self.save_error:
            raise self.save_error
        self.files[destination] = data
        return WriteReceipt(destination=destination, byte_count=len(data))


class JsonHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = (Path(tempfile.gettempdir()) / "secure-share-history-unit").resolve()
        self.storage = FakeStorage()
        self.history = JsonHistoryStore(self.root, self.storage)
        self.alice_path = self.root / "alice.json"

    def encoded(self, entries: list[str], **changes: object) -> bytes:
        document = {"version": 1, "profile_id": "alice", "transfer_ids": entries}
        document.update(changes)
        return json.dumps(document, separators=(",", ":")).encode()

    def assert_code(self, expected: ErrorCode, function, *args) -> None:
        with self.assertRaises(ShareError) as caught:
            function(*args)
        self.assertIs(caught.exception.code, expected)

    def test_missing_history_is_empty_without_creating_a_file(self) -> None:
        self.assertFalse(self.history.has_seen("alice", TRANSFER_A))
        self.assertFalse(self.storage.files)
        self.assertEqual(self.storage.read_calls, [(self.alice_path, MAX_HISTORY_BYTES)])

    def test_records_sorted_schema_and_survives_reopening(self) -> None:
        self.history.record("alice", TRANSFER_B)
        self.history.record("alice", TRANSFER_A)
        document = json.loads(self.storage.files[self.alice_path])
        self.assertEqual(
            document,
            {"version": 1, "profile_id": "alice", "transfer_ids": [TRANSFER_A, TRANSFER_B]},
        )
        reopened = JsonHistoryStore(self.root, self.storage)
        self.assertTrue(reopened.has_seen("alice", TRANSFER_A))
        self.assertTrue(reopened.has_seen("alice", TRANSFER_B))
        self.assertTrue(all(call[2] for call in self.storage.save_calls))
        self.assertTrue(all(call[3] == () for call in self.storage.save_calls))

    def test_record_is_idempotent_without_another_write(self) -> None:
        self.history.record("alice", TRANSFER_A)
        original = self.storage.files[self.alice_path]
        self.history.record("alice", TRANSFER_A)
        self.assertEqual(len(self.storage.save_calls), 1)
        self.assertEqual(self.storage.files[self.alice_path], original)

    def test_history_is_isolated_by_profile(self) -> None:
        self.history.record("alice", TRANSFER_A)
        self.assertTrue(self.history.has_seen("alice", TRANSFER_A))
        self.assertFalse(self.history.has_seen("bob", TRANSFER_A))
        self.history.record("bob", TRANSFER_B)
        self.assertFalse(self.history.has_seen("alice", TRANSFER_B))

    def test_invalid_json_does_not_get_reset_or_overwritten(self) -> None:
        invalid_inputs = [b"not json", b"{", b"\xff", b"{}{}", b"[]", b"null"]
        for encoded in invalid_inputs:
            with self.subTest(encoded=encoded):
                self.storage.files[self.alice_path] = encoded
                self.assert_code(ErrorCode.HISTORY_INVALID, self.history.record, "alice", TRANSFER_A)
                self.assertEqual(self.storage.files[self.alice_path], encoded)
        self.assertFalse(self.storage.save_calls)

    def test_duplicate_fields_are_rejected(self) -> None:
        encoded = b'{"version":1,"version":1,"profile_id":"alice","transfer_ids":[]}'
        self.storage.files[self.alice_path] = encoded
        self.assert_code(ErrorCode.HISTORY_INVALID, self.history.has_seen, "alice", TRANSFER_A)

    def test_strict_schema_and_profile_binding(self) -> None:
        invalid_documents = [
            {"version": True, "profile_id": "alice", "transfer_ids": []},
            {"version": 1.0, "profile_id": "alice", "transfer_ids": []},
            {"version": 2, "profile_id": "alice", "transfer_ids": []},
            {"version": 1, "profile_id": "bob", "transfer_ids": []},
            {"version": 1, "profile_id": "alice", "transfer_ids": {}},
            {"version": 1, "profile_id": "alice", "transfer_ids": [], "extra": 0},
            {"version": 1, "profile_id": "alice"},
            {"version": 1, "profile_id": "alice", "transfer_ids": [TRANSFER_A, TRANSFER_A]},
            {"version": 1, "profile_id": "alice", "transfer_ids": [True]},
            {"version": 1, "profile_id": "alice", "transfer_ids": ["A" * 32]},
        ]
        for document in invalid_documents:
            with self.subTest(document=document):
                self.storage.files[self.alice_path] = json.dumps(document).encode()
                self.assert_code(ErrorCode.HISTORY_INVALID, self.history.has_seen, "alice", TRANSFER_A)

    def test_json_whitespace_is_allowed_and_nan_is_rejected(self) -> None:
        self.storage.files[self.alice_path] = b" \n" + self.encoded([TRANSFER_A]) + b" \t"
        self.assertTrue(self.history.has_seen("alice", TRANSFER_A))
        self.storage.files[self.alice_path] = b'{"version":NaN,"profile_id":"alice","transfer_ids":[]}'
        self.assert_code(ErrorCode.HISTORY_INVALID, self.history.has_seen, "alice", TRANSFER_A)

    def test_rejects_oversized_storage_data_even_if_backend_ignores_cap(self) -> None:
        self.storage.files[self.alice_path] = b" " * (MAX_HISTORY_BYTES + 1)
        for enforce in (True, False):
            with self.subTest(enforce_read_cap=enforce):
                self.storage.enforce_read_cap = enforce
                self.assert_code(ErrorCode.HISTORY_TOO_LARGE, self.history.has_seen, "alice", TRANSFER_A)

    def test_entry_cap_and_idempotence_at_cap(self) -> None:
        entries = [f"{number:032x}" for number in range(MAX_HISTORY_ENTRIES)]
        self.storage.files[self.alice_path] = self.encoded(entries)
        self.history.record("alice", entries[0])
        self.assertFalse(self.storage.save_calls)
        self.assert_code(ErrorCode.HISTORY_TOO_LARGE, self.history.record, "alice", TRANSFER_A)
        self.storage.files[self.alice_path] = self.encoded(entries + [TRANSFER_A])
        self.assert_code(ErrorCode.HISTORY_TOO_LARGE, self.history.has_seen, "alice", TRANSFER_A)

    def test_invalid_profile_ids_are_rejected_before_storage_access(self) -> None:
        invalid_ids = ["", ".", "..", "../alice", "a/b", "a\\b", "C:alice", "Alice", "nhật", "_a", "a" * 65,
                       "con", "prn", "aux", "nul", "com1", "lpt9"]
        for profile_id in invalid_ids:
            with self.subTest(profile_id=profile_id):
                self.assert_code(ErrorCode.HISTORY_INVALID, self.history.record, profile_id, TRANSFER_A)
        self.assertFalse(self.storage.read_calls)
        self.assertFalse(self.storage.save_calls)

    def test_valid_profile_id_boundaries(self) -> None:
        for profile_id in ("a", "0", "alice-01", "profile_1", "a" * 64):
            with self.subTest(profile_id=profile_id):
                self.history.record(profile_id, TRANSFER_A)
                self.assertTrue(self.history.has_seen(profile_id, TRANSFER_A))

    def test_invalid_transfer_ids_are_rejected_before_storage_access(self) -> None:
        for transfer_id in ("", "a" * 31, "a" * 33, "A" * 32, "g" * 32, "0" * 31 + "\n", None):
            with self.subTest(transfer_id=transfer_id):
                self.assert_code(ErrorCode.HISTORY_INVALID, self.history.has_seen, "alice", transfer_id)
        self.assertFalse(self.storage.read_calls)

    def test_unreadable_history_is_not_treated_as_missing(self) -> None:
        self.storage.read_error = PermissionError("sensitive path detail")
        self.assert_code(ErrorCode.READ_FAILED, self.history.record, "alice", TRANSFER_A)
        self.assertFalse(self.storage.save_calls)
        self.storage.read_error = ShareError(ErrorCode.READ_FAILED)
        self.assert_code(ErrorCode.READ_FAILED, self.history.has_seen, "alice", TRANSFER_A)

    def test_failed_save_preserves_previous_history(self) -> None:
        original = self.encoded([TRANSFER_A])
        self.storage.files[self.alice_path] = original
        for error in (ShareError(ErrorCode.SAVE_FAILED), OSError("disk full secret detail")):
            with self.subTest(error_type=type(error).__name__):
                self.storage.save_error = error
                self.assert_code(ErrorCode.SAVE_FAILED, self.history.record, "alice", TRANSFER_B)
                self.assertEqual(self.storage.files[self.alice_path], original)

    def test_invalid_receipt_after_commit_is_reported_without_retry(self) -> None:
        expected_length = len(self.encoded([TRANSFER_A]))

        class BadPath:
            def __fspath__(self):
                raise RuntimeError("backend-private-detail")

        invalid_receipts = [
            None,
            object(),
            WriteReceipt(destination=self.root / "bob.json", byte_count=expected_length),
            WriteReceipt(destination=self.alice_path, byte_count=0),
            WriteReceipt(destination=self.alice_path, byte_count=float(expected_length)),
            WriteReceipt(destination=BadPath(), byte_count=expected_length),
        ]
        for receipt in invalid_receipts:
            with self.subTest(receipt_type=type(receipt).__name__):
                storage = FakeStorage()
                history = JsonHistoryStore(self.root, storage)
                normal_save = storage.save_atomic

                def save_with_bad_receipt(*args, **kwargs):
                    normal_save(*args, **kwargs)
                    return receipt

                with patch.object(storage, "save_atomic", side_effect=save_with_bad_receipt):
                    self.assert_code(ErrorCode.HISTORY_INVALID, history.record, "alice", TRANSFER_A)
                self.assertEqual(len(storage.save_calls), 1)
                self.assertEqual(json.loads(storage.files[self.alice_path])["transfer_ids"], [TRANSFER_A])

    def test_single_instance_serializes_read_modify_write(self) -> None:
        transfer_ids = [f"{number:032x}" for number in range(20)]
        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(lambda transfer_id: self.history.record("alice", transfer_id), transfer_ids))
        document = json.loads(self.storage.files[self.alice_path])
        self.assertEqual(set(document["transfer_ids"]), set(transfer_ids))


class MemoryHistoryTests(unittest.TestCase):
    def test_isolation_and_idempotence(self) -> None:
        history = MemoryHistoryStore()
        self.assertFalse(history.has_seen("alice", TRANSFER_A))
        history.record("alice", TRANSFER_A)
        history.record("alice", TRANSFER_A)
        self.assertTrue(history.has_seen("alice", TRANSFER_A))
        self.assertFalse(history.has_seen("bob", TRANSFER_A))

    def test_limits_match_persistent_store(self) -> None:
        history = MemoryHistoryStore()
        for number in range(MAX_HISTORY_ENTRIES):
            history.record("alice", f"{number:032x}")
        history.record("alice", "0" * 32)
        with self.assertRaises(ShareError) as caught:
            history.record("alice", TRANSFER_A)
        self.assertIs(caught.exception.code, ErrorCode.HISTORY_TOO_LARGE)

    def test_identifiers_have_the_same_validation(self) -> None:
        history = MemoryHistoryStore()
        for profile_id, transfer_id in (("../alice", TRANSFER_A), ("Alice", TRANSFER_A), ("alice", "bad")):
            with self.subTest(profile_id=profile_id, transfer_id=transfer_id):
                with self.assertRaises(ShareError) as caught:
                    history.record(profile_id, transfer_id)
                self.assertIs(caught.exception.code, ErrorCode.HISTORY_INVALID)


if __name__ == "__main__":
    unittest.main()
