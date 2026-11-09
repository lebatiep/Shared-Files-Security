"""Profile-scoped transfer history behind the shared storage contract.

History is a duplicate warning, not a replay-prevention security boundary. The
service records a transfer only after the recovered file has been committed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any

from .config import MAX_HISTORY_BYTES, MAX_HISTORY_ENTRIES
from .errors import ErrorCode, ShareError
from .models import WriteReceipt

if TYPE_CHECKING:
    from .ports import StoragePort

_PROFILE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.ASCII)
_TRANSFER_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_SCHEMA_FIELDS = frozenset({"version", "profile_id", "transfer_ids"})


def _validate_profile_id(profile_id: str) -> None:
    # Lowercase identifiers also prevent case aliases on Windows filesystems.
    # A human-readable display name is a separate ProfileSummary field.
    if (
        not isinstance(profile_id, str)
        or _PROFILE_ID.fullmatch(profile_id) is None
        or profile_id in _RESERVED_NAMES
    ):
        raise ShareError(ErrorCode.HISTORY_INVALID)


def _validate_transfer_id(transfer_id: str) -> None:
    if not isinstance(transfer_id, str) or _TRANSFER_ID.fullmatch(transfer_id) is None:
        raise ShareError(ErrorCode.HISTORY_INVALID)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-standard JSON constant")


class JsonHistoryStore:
    """Persist bounded JSON history through ``StoragePort`` only.

    ``root`` is the application's history directory. Its lifecycle and physical
    file operations belong to the storage/bootstrap layer. An RLock prevents
    lost updates between threads using this instance; this is not a cross-
    process database or a transaction covering the recovered output file.
    """

    def __init__(self, root: Path, storage: StoragePort) -> None:
        self._root = Path(root).resolve()
        self._storage = storage
        self._lock = RLock()

    def has_seen(self, profile_id: str, transfer_id: str) -> bool:
        """Return whether this profile recorded the transfer previously."""
        _validate_profile_id(profile_id)
        _validate_transfer_id(transfer_id)
        with self._lock:
            return transfer_id in self._read(profile_id)

    def record(self, profile_id: str, transfer_id: str) -> None:
        """Record a successfully saved transfer, idempotently.

        Missing history starts empty. Malformed or unreadable existing history
        is never silently replaced. The caller handles a recording failure as
        a warning when the recovered file has already been saved.
        """
        _validate_profile_id(profile_id)
        _validate_transfer_id(transfer_id)
        with self._lock:
            transfer_ids = self._read(profile_id)
            if transfer_id in transfer_ids:
                return
            if len(transfer_ids) >= MAX_HISTORY_ENTRIES:
                raise ShareError(ErrorCode.HISTORY_TOO_LARGE)
            transfer_ids.add(transfer_id)
            encoded = json.dumps(
                {
                    "version": 1,
                    "profile_id": profile_id,
                    "transfer_ids": sorted(transfer_ids),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > MAX_HISTORY_BYTES:
                raise ShareError(ErrorCode.HISTORY_TOO_LARGE)
            destination = self._path(profile_id)
            try:
                receipt = self._storage.save_atomic(
                    encoded,
                    destination,
                    overwrite_confirmed=True,
                    protected_paths=(),
                )
            except ShareError:
                raise
            except OSError as exc:
                raise ShareError(ErrorCode.SAVE_FAILED) from exc
            try:
                valid_receipt = (
                    isinstance(receipt, WriteReceipt)
                    and type(receipt.byte_count) is int
                    and receipt.byte_count == len(encoded)
                    and Path(receipt.destination).resolve() == destination
                )
            except Exception:
                valid_receipt = False
            if not valid_receipt:
                # The backend may already have committed. Do not retry or
                # overwrite here; the caller reports the history warning.
                raise ShareError(ErrorCode.HISTORY_INVALID)

    def _path(self, profile_id: str) -> Path:
        # profile_id is validated before every public operation. Resolve also
        # rejects an existing per-profile symlink pointing outside this root.
        try:
            path = (self._root / f"{profile_id}.json").resolve()
            path.relative_to(self._root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ShareError(ErrorCode.HISTORY_INVALID) from exc
        return path

    def _read(self, profile_id: str) -> set[str]:
        try:
            encoded = self._storage.read_limited(
                self._path(profile_id), MAX_HISTORY_BYTES
            )
        except FileNotFoundError:
            return set()
        except ShareError as exc:
            if exc.code is ErrorCode.INPUT_TOO_LARGE:
                raise ShareError(ErrorCode.HISTORY_TOO_LARGE) from exc
            raise
        except OSError as exc:
            raise ShareError(ErrorCode.READ_FAILED) from exc

        if not isinstance(encoded, bytes):
            raise ShareError(ErrorCode.HISTORY_INVALID)
        if len(encoded) > MAX_HISTORY_BYTES:
            # Enforce the cap even if an integration violates read_limited.
            raise ShareError(ErrorCode.HISTORY_TOO_LARGE)
        try:
            document = json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise ShareError(ErrorCode.HISTORY_INVALID) from exc
        if (
            not isinstance(document, dict)
            or set(document) != _SCHEMA_FIELDS
            or type(document["version"]) is not int
            or document["version"] != 1
            or document["profile_id"] != profile_id
            or not isinstance(document["transfer_ids"], list)
        ):
            raise ShareError(ErrorCode.HISTORY_INVALID)

        entries = document["transfer_ids"]
        if len(entries) > MAX_HISTORY_ENTRIES:
            raise ShareError(ErrorCode.HISTORY_TOO_LARGE)
        result: set[str] = set()
        for transfer_id in entries:
            _validate_transfer_id(transfer_id)
            if transfer_id in result:
                raise ShareError(ErrorCode.HISTORY_INVALID)
            result.add(transfer_id)
        return result


class MemoryHistoryStore:
    """Thread-safe, profile-isolated history for explicit ephemeral use/tests."""

    def __init__(self) -> None:
        self._entries: dict[str, set[str]] = {}
        self._lock = RLock()

    def has_seen(self, profile_id: str, transfer_id: str) -> bool:
        _validate_profile_id(profile_id)
        _validate_transfer_id(transfer_id)
        with self._lock:
            return transfer_id in self._entries.get(profile_id, set())

    def record(self, profile_id: str, transfer_id: str) -> None:
        _validate_profile_id(profile_id)
        _validate_transfer_id(transfer_id)
        with self._lock:
            entries = self._entries.setdefault(profile_id, set())
            if transfer_id in entries:
                return
            if len(entries) >= MAX_HISTORY_ENTRIES:
                raise ShareError(ErrorCode.HISTORY_TOO_LARGE)
            entries.add(transfer_id)
