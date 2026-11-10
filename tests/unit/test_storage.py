import errno
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from secure_share.application import create_application
from secure_share.errors import ErrorCode, ShareError
from secure_share.storage import LocalStorage


@pytest.mark.case('O04')
@pytest.mark.parametrize('cause', ['missing', 'permission'])
def test_unavailable_destination_allows_retry_elsewhere(tmp_path, monkeypatch, cause):
    root = tmp_path / 'app-data'
    storage = create_application(root).storage
    denied = tmp_path / 'unavailable'
    if cause == 'permission':
        denied.mkdir()
        real_open = os.open

        def deny_unavailable(path, *args, **kwargs):
            if Path(path).parent == denied:
                raise PermissionError(errno.EACCES, 'Not writable')
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(os, 'open', deny_unavailable)
    with pytest.raises(ShareError) as error:
        storage.save_atomic(b'data', denied / 'output')
    assert error.value.code is ErrorCode.SAVE_FAILED
    assert not (denied / 'output').exists()
    assert not list((root / 'pending-saves').glob('*.json'))

    output = tmp_path / 'output'
    receipt = storage.save_atomic(b'data', output)
    assert receipt.destination == output
    assert output.read_bytes() == b'data'


@pytest.mark.case('O05')
@pytest.mark.parametrize('overwrite', [False, True])
def test_partial_write_preserves_destination_and_cleans_temp(tmp_path, monkeypatch, overwrite):
    root = tmp_path / 'app-data'
    storage = create_application(root).storage
    output = tmp_path / 'output'
    if overwrite:
        output.write_bytes(b'old')
    real_fdopen = os.fdopen

    class ShortWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def write(self, data):
            self.stream.write(data[:2])
            self.stream.flush()
            raise OSError(errno.ENOSPC, 'Disk full')

    monkeypatch.setattr(os, 'fdopen', lambda *args: ShortWriter(real_fdopen(*args)))
    with pytest.raises(ShareError) as error:
        storage.save_atomic(b'new content', output, overwrite_confirmed=overwrite)
    assert error.value.code is ErrorCode.SAVE_FAILED
    if overwrite:
        assert output.read_bytes() == b'old'
    else:
        assert not output.exists()
    assert not list(tmp_path.glob('.sfile-*.tmp'))
    assert not list((root / 'pending-saves').glob('*.json'))


_PAUSE_BEFORE_PUBLISH = '''
from pathlib import Path
import sys
import time

from secure_share.application import create_application
from secure_share.storage import LocalStorage

root, destination, ready = map(Path, sys.argv[1:4])
overwrite = sys.argv[4] == 'overwrite'
def pause(temporary, destination):
    ready.touch()
    time.sleep(60)

if overwrite:
    import os
    os.replace = pause
else:
    LocalStorage._publish_new = staticmethod(pause)
create_application(root).storage.save_atomic(b'unpublished content', destination, overwrite_confirmed=overwrite)
'''


def _wait_for_pause(process, ready):
    deadline = time.monotonic() + 10
    while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists(), 'Writer did not reach the pre-publication point'


@pytest.mark.case('O08')
@pytest.mark.parametrize('scenario', ['new', 'overwrite', 'replaced_temporary'])
def test_restart_only_removes_its_own_interrupted_save(tmp_path, scenario):
    root = tmp_path / 'app-data'
    pending = root / 'pending-saves'
    output = tmp_path / 'output'
    ready = tmp_path / 'ready'
    unrelated = tmp_path / ('.sfile-' + 'a' * 32 + '.tmp')
    unrelated.write_bytes(b'an unrelated temporary file')
    if scenario == 'overwrite':
        output.write_bytes(b'previous output')
    process = subprocess.Popen([
        sys.executable, '-c', _PAUSE_BEFORE_PUBLISH, str(root), str(output), str(ready), scenario,
    ])
    try:
        _wait_for_pause(process, ready)
        marker, = pending.glob('*.json')
        temporary = tmp_path / f'.sfile-{marker.stem}.tmp'
        assert temporary.read_bytes() == b'unpublished content'
        assert output.exists() == (scenario == 'overwrite')

        # Another running app must leave the first process's live save alone.
        second = create_application(root)
        assert temporary.exists()
        assert marker.exists()
        with pytest.raises(ShareError) as error:
            second.storage.save_atomic(b'other content', tmp_path / 'other output')
        assert error.value.code is ErrorCode.SAVE_FAILED
    finally:
        process.kill()
        process.wait(timeout=10)

    if scenario == 'replaced_temporary':
        replacement = tmp_path / 'replacement'
        replacement.write_bytes(b'file owned by someone else')
        os.replace(replacement, temporary)
    reopened = create_application(root)
    if scenario == 'overwrite':
        assert output.read_bytes() == b'previous output'
    else:
        assert not output.exists()
    assert unrelated.read_bytes() == b'an unrelated temporary file'
    if scenario == 'replaced_temporary':
        assert temporary.read_bytes() == b'file owned by someone else'
        assert marker.exists()
    else:
        assert not temporary.exists()
        assert not marker.exists()

    reopened.storage.save_atomic(b'completed retry', output, overwrite_confirmed=scenario == 'overwrite')
    assert output.read_bytes() == b'completed retry'


@pytest.mark.case('O08')
def test_restart_clears_leftover_marker_without_touching_committed_output(tmp_path, monkeypatch):
    root = tmp_path / 'app-data'
    output = tmp_path / 'output'
    pending = root / 'pending-saves'
    storage = create_application(root).storage
    real_unlink = Path.unlink

    def block_marker_cleanup(path, *args, **kwargs):
        if path.parent == pending:
            raise PermissionError(errno.EACCES, 'Marker cannot be removed')
        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'unlink', block_marker_cleanup)
        assert storage.save_atomic(b'published', output).byte_count == 9
    assert output.read_bytes() == b'published'
    assert len(list(pending.glob('*.json'))) == 1
    create_application(root)
    assert not list(pending.glob('*.json'))
    assert output.read_bytes() == b'published'


@pytest.mark.skipif(os.name != 'nt', reason='Windows has a native no-replace rename')
def test_windows_save_without_hardlink_support(tmp_path, monkeypatch):
    def unsupported(*args):
        raise OSError(errno.ENOTSUP, 'Hard links are unavailable')

    monkeypatch.setattr(os, 'link', unsupported)
    storage = LocalStorage()
    output = tmp_path / 'output'
    storage.save_atomic(b'first', output)
    with pytest.raises(ShareError) as error:
        storage.save_atomic(b'second', output)
    assert error.value.code is ErrorCode.DESTINATION_EXISTS
    assert output.read_bytes() == b'first'
