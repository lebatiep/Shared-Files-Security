import os
from pathlib import Path
import stat
import tempfile

from .errors import ErrorCode, ShareError
from .models import WriteReceipt


class LocalStorage:
    def __init__(self, protected_roots=()):
        self.protected_roots = tuple(Path(p).resolve() for p in protected_roots)

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
        temporary = None
        try:
            destination = Path(destination).resolve()
            self._check_destination(destination, protected_paths)
            if destination.exists() and not overwrite_confirmed:
                raise ShareError(ErrorCode.DESTINATION_EXISTS)
            fd, temporary = tempfile.mkstemp(prefix='.sfile-', suffix='.tmp', dir=destination.parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_destination(destination, protected_paths)
            if overwrite_confirmed:
                os.replace(temporary, destination)
                temporary = None
            else:
                # A hard link creates the destination atomically without replacing
                # a file another process created after the first existence check.
                os.link(temporary, destination)
            receipt = WriteReceipt(destination, len(data))
        except FileExistsError:
            raise ShareError(ErrorCode.DESTINATION_EXISTS) from None
        except OSError:
            raise ShareError(ErrorCode.SAVE_FAILED) from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
        return receipt
