from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

if os.name == 'nt':
    import msvcrt
else:
    import fcntl

from .errors import ErrorCode, ShareError
from .models import WriteReceipt


_MARKER_NAME = re.compile(r'[a-f0-9]{32}\.json')
_MAX_MARKER_BYTES = 262_144


def _file_identity(metadata):
    return [metadata.st_dev, metadata.st_ino, getattr(metadata, 'st_birthtime_ns', None)]


def _is_regular_file(metadata):
    attributes = getattr(metadata, 'st_file_attributes', 0)
    return stat.S_ISREG(metadata.st_mode) and not attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT


def _remove_temporary(temporary, identity):
    try:
        metadata = temporary.lstat()
    except FileNotFoundError:
        return temporary.parent.is_dir()
    if not _is_regular_file(metadata) or _file_identity(metadata) != identity:
        return False
    temporary.unlink()
    return True


class LocalStorage:
    def __init__(self, protected_roots=(), *, recovery_root=None):
        self.protected_roots = tuple(Path(p).resolve() for p in protected_roots)
        self._recovery_root = Path(recovery_root).absolute() if recovery_root is not None else None

    @contextmanager
    def _save_lock(self):
        if self._recovery_root is None:
            yield
            return
        self._recovery_root.mkdir(mode=0o700, exist_ok=True)
        if self._recovery_root.resolve(strict=True) != self._recovery_root:
            raise OSError('Invalid recovery directory')
        lock_path = self._recovery_root / 'save.lock'
        try:
            if not _is_regular_file(lock_path.lstat()):
                raise OSError('Invalid save lock')
        except FileNotFoundError:
            pass
        with lock_path.open('a+b') as lock:
            # The OS releases the lock on close or if this process terminates.
            if os.name == 'nt':
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def recover_pending_saves(self):
        """Remove only registered temporary files when no instance is saving."""
        if self._recovery_root is None:
            return
        try:
            with self._save_lock():
                for marker in self._recovery_root.iterdir():
                    if _MARKER_NAME.fullmatch(marker.name):
                        self._recover_marker(marker)
        except OSError:
            # An active save or inaccessible journal must not block startup.
            pass

    @staticmethod
    def _recover_marker(marker):
        try:
            if not _is_regular_file(marker.lstat()):
                return
            with marker.open('rb') as stream:
                encoded = stream.read(_MAX_MARKER_BYTES + 1)
            if len(encoded) > _MAX_MARKER_BYTES:
                return
            record = json.loads(encoded)
            parent = Path(record['parent'])
            identity = record['identity']
            if (
                not parent.is_absolute()
                or parent.resolve(strict=True) != parent
                or not isinstance(identity, list)
                or len(identity) != 3
                or any(type(value) is not int for value in identity[:2])
                or identity[1] <= 0
                or (identity[2] is not None and type(identity[2]) is not int)
                or parent.stat().st_dev != identity[0]
            ):
                return
            temporary = parent / f'.sfile-{marker.stem}.tmp'
            if _remove_temporary(temporary, identity):
                marker.unlink()
        except (KeyError, TypeError, ValueError, RuntimeError, OSError):
            # Leave entries in place if the drive or file identity cannot be verified.
            pass

    @staticmethod
    def _record_pending_save(journal, temporary, identity):
        encoded = json.dumps({
            'parent': str(temporary.parent),
            'identity': identity,
        }).encode('ascii')
        journal.write(encoded)
        journal.flush()
        os.fsync(journal.fileno())

    @staticmethod
    def _publish_new(temporary, destination):
        # Windows rename refuses existing targets and works on volumes without
        # hard links. POSIX rename can overwrite, so publish with a link there.
        if os.name == 'nt':
            os.rename(temporary, destination)
        else:
            os.link(temporary, destination)

    def read_limited(self, path, max_bytes):
        try:
            with Path(path).open('rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ShareError(ErrorCode.READ_FAILED)
                data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ShareError(ErrorCode.INPUT_TOO_LARGE)
            return data
        except FileNotFoundError:
            raise
        except OSError:
            raise ShareError(ErrorCode.READ_FAILED) from None

    def _check_destination(self, destination, protected_paths):
        if any(destination == root or root in destination.parents for root in self.protected_roots):
            raise ShareError(ErrorCode.PROTECTED_PATH)
        for protected in protected_paths:
            protected = Path(protected).resolve()
            if destination == protected or protected.is_dir() and protected in destination.parents:
                raise ShareError(ErrorCode.PROTECTED_PATH)
            if destination.exists() and protected.exists() and os.path.samefile(destination, protected):
                raise ShareError(ErrorCode.PROTECTED_PATH)

    def save_atomic(self, data, destination, *, overwrite_confirmed=False, protected_paths=()):
        try:
            with self._save_lock():
                return self._save(data, Path(destination).resolve(), overwrite_confirmed is True, protected_paths)
        except OSError:
            raise ShareError(ErrorCode.SAVE_FAILED) from None

    def _save(self, data, destination, overwrite_confirmed, protected_paths):
        self._check_destination(destination, protected_paths)
        if destination.exists() and not overwrite_confirmed:
            raise ShareError(ErrorCode.DESTINATION_EXISTS)
        token = uuid4().hex
        temporary = destination.parent / f'.sfile-{token}.tmp'
        marker = None if self._recovery_root is None else self._recovery_root / f'{token}.json'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
        fd = os.open(temporary, flags, 0o600)
        identity = None
        marker_created = False
        try:
            with os.fdopen(fd, 'wb') as stream:
                identity = _file_identity(os.fstat(stream.fileno()))
                if marker is not None:
                    # Record ownership before any user data can reach the temp file.
                    with marker.open('xb') as journal:
                        marker_created = True
                        self._record_pending_save(journal, temporary, identity)
                if stream.write(data) != len(data):
                    raise OSError('Short write')
                stream.flush()
                os.fsync(stream.fileno())
            if destination.parent.resolve(strict=True) != destination.parent:
                raise ShareError(ErrorCode.PROTECTED_PATH)
            metadata = temporary.lstat()
            if not _is_regular_file(metadata) or _file_identity(metadata) != identity:
                raise OSError('Temporary file changed before publication')
            self._check_destination(destination, protected_paths)
            receipt = WriteReceipt(destination, len(data))
            try:
                if overwrite_confirmed:
                    os.replace(temporary, destination)
                else:
                    self._publish_new(temporary, destination)
            except FileExistsError:
                raise ShareError(ErrorCode.DESTINATION_EXISTS) from None
            return receipt
        finally:
            self._clear_pending_save(temporary, identity, marker if marker_created else None)

    @staticmethod
    def _clear_pending_save(temporary, identity, marker):
        try:
            if _remove_temporary(temporary, identity) and marker is not None:
                marker.unlink(missing_ok=True)
        except OSError:
            # Keep the marker when temp cleanup fails so startup can retry.
            pass
