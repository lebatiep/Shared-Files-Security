import queue
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from secure_share.errors import ErrorCode, safe_message
from secure_share.models import (
    OperationResult,
    OperationStatus,
    PreparedReceive,
    WarningCode,
    WriteReceipt,
)
from secure_share.storage import LocalStorage
from secure_share.ui import app as ui


@pytest.fixture
def window():
    window = ui.App.__new__(ui.App)
    window.root = Mock()
    window.status = Mock()
    window.busy = False
    window.closed = False
    window.app = SimpleNamespace(service=Mock())
    return window


@pytest.fixture
def prepared():
    return PreparedReceive('handle', 'alice', 'transfer', 'Bob', 'a' * 64, 'e' * 64, 'sample.txt', 3)


@pytest.mark.case('O01')
@pytest.mark.parametrize('accept', [False, True])
def test_cancel_receive_confirmation_or_save_dialog_discards_handle(window, monkeypatch, prepared, accept):
    monkeypatch.setattr(ui.messagebox, 'askyesno', lambda *args, **kwargs: accept)
    save_dialog = Mock(return_value='')
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', save_dialog)
    window.app.service.discard_prepared.return_value = OperationResult(OperationStatus.CANCELLED)
    window.run = Mock()

    window.prepared(OperationResult(OperationStatus.PREPARED, prepared=prepared))

    window.app.service.discard_prepared.assert_called_once_with(prepared.handle)
    assert save_dialog.call_count == accept
    window.run.assert_not_called()
    window.status.set.assert_called_once_with('Đã hủy thao tác.')


@pytest.mark.case('R06')
def test_refusing_overwrite_opens_save_as_again_with_same_handle(window, tmp_path, monkeypatch, prepared):
    existing = tmp_path / prepared.filename
    existing.write_bytes(b'old')
    alternative = tmp_path / 'renamed.txt'
    save_dialog = Mock(side_effect=[str(existing), str(alternative)])
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', save_dialog)
    confirm = Mock(return_value=False)
    monkeypatch.setattr(ui.messagebox, 'askyesno', confirm)
    service = window.app.service
    service.has_prepared = False
    service.save_received.side_effect = lambda handle, destination, **options: OperationResult(
        OperationStatus.SUCCESS, receipt=LocalStorage().save_atomic(b'new', destination, **options))
    window.run = lambda work, callback: callback(work())

    window.save_prepared(prepared)

    assert save_dialog.call_count == 2
    assert str(existing) in confirm.call_args.args[1]
    service.save_received.assert_called_once_with(prepared.handle, alternative, overwrite_confirmed=False)
    service.discard_prepared.assert_not_called()
    assert existing.read_bytes() == b'old'
    assert alternative.read_bytes() == b'new'


def test_history_warning_shows_committed_path(window, tmp_path, monkeypatch):
    warning = Mock()
    monkeypatch.setattr(ui.messagebox, 'showwarning', warning)
    path = tmp_path / 'saved.txt'
    result = OperationResult(
        OperationStatus.SUCCESS, receipt=WriteReceipt(path, 3), warnings=(WarningCode.HISTORY_NOT_SAVED,))

    window.result(result)

    assert str(path) in window.status.set.call_args.args[0]
    assert str(path) in warning.call_args.args[1]


def test_worker_failure_is_sanitized_and_releases_controls(window, monkeypatch):
    window.buttons = [Mock()]
    window.progress = Mock()
    window.profiles = Mock()
    window.threshold_selectors = (Mock(),)
    window.results = queue.Queue()
    window.executor = Mock()
    show_error = Mock()
    monkeypatch.setattr(ui.messagebox, 'showerror', show_error)
    callback = Mock()
    work = Mock(side_effect=RuntimeError('sensitive adapter details'))

    window.run(work, callback)
    assert window.busy
    window.profiles.configure.assert_called_once_with(state='disabled')
    blocked = Mock()
    window.perform(blocked)
    blocked.assert_not_called()

    window.executor.submit.call_args.args[0]()
    window.poll()

    assert not window.busy
    assert window.profiles.configure.call_args.kwargs == {'state': 'readonly'}
    callback.assert_not_called()
    window.app.service.close.assert_called_once_with()
    notice = show_error.call_args.args[1]
    assert safe_message(ErrorCode.INTERNAL_ERROR) in notice
    assert 'sensitive adapter details' not in notice


def test_missing_tk_reports_safe_startup_error(monkeypatch, capsys):
    monkeypatch.setattr(ui.tk, 'Tk', Mock(side_effect=ui.tk.TclError('private path')))

    assert ui.main() == 2
    error = capsys.readouterr().err
    assert 'Tcl/Tk' in error
    assert 'private path' not in error
