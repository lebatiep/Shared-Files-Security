import queue
import re
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from secure_share.errors import ErrorCode, safe_message
from secure_share.models import (
    OperationResult,
    OperationStatus,
    PreparedReceive,
    ProfileSummary,
    TrustedContact,
    TrustStatus,
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
    window.selected_profile = Mock(return_value='alice')
    window.contact = Mock()
    window.contact.get.return_value = 'mallory'
    window.password = Mock(return_value=b'local secret')
    window.app = SimpleNamespace(
        trust=Mock(),
        service=Mock(),
    )
    window.app.trust.resolve_recipient.return_value = TrustedContact(
        'alice', 'mallory', 'Người nhận khác', 'e' * 64, 'a' * 64,
        object(), object(), TrustStatus.VERIFIED,
    )
    return window


@pytest.mark.case('S09')
def test_send_has_no_recipient_selected_on_load_or_profile_change(window):
    window.profile = Mock()
    window.profile.get.return_value = 'alice'
    window.recipient_profile = None
    window.contacts = Mock()
    window.contacts.get_children.return_value = []
    window.identity = Mock()
    window.recipients = {}
    window.app.keys = Mock()
    window.app.keys.get_profile.return_value = ProfileSummary('alice', 'Alice', 'e' * 64, 'a' * 64)
    window.app.trust.list_contacts.return_value = [window.app.trust.resolve_recipient.return_value]

    window.refresh_contacts()
    assert window.recipients['values'] == ['mallory']
    window.contact.set.assert_called_once_with('')

    window.contact.set.reset_mock()
    window.refresh_contacts()
    assert window.contact.set.call_args.args == ('mallory',)

    window.profile.get.return_value = 'bob'
    window.app.keys.get_profile.return_value = ProfileSummary('bob', 'Bob', 'e' * 64, 'a' * 64)
    window.contact.set.reset_mock()
    window.refresh_contacts()
    window.contact.set.assert_called_once_with('')


@pytest.mark.case('S09')
def test_send_confirms_selected_id_and_keys_with_opaque_package_name(window, tmp_path, monkeypatch):
    source = tmp_path / 'private-survey.xlsx'
    destination = tmp_path / 'chosen.sfile'
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', lambda **kwargs: str(source))
    save_dialog = Mock(return_value=str(destination))
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', save_dialog)
    confirm = Mock(return_value=True)
    monkeypatch.setattr(ui.messagebox, 'askyesno', confirm)
    window.run = Mock(side_effect=lambda work, callback: work())

    window.send()

    window.app.trust.resolve_recipient.assert_called_once_with('alice', 'mallory')
    suggestion = save_dialog.call_args.kwargs['initialfile']
    assert re.fullmatch(r'[0-9a-f]{32}\.sfile', suggestion)
    assert source.name not in suggestion
    notice = confirm.call_args.args[1]
    assert all(text in notice for text in ('mallory', 'Người nhận khác', 'e' * 64, 'a' * 64, str(source), str(destination)))
    assert confirm.call_args.kwargs['default'] == ui.messagebox.NO
    request = window.app.service.send_file.call_args.args[0]
    assert request.recipient_contact_id == 'mallory'
    assert request.expected_recipient_fingerprints == ('e' * 64, 'a' * 64)
    assert request.destination_path == destination


@pytest.mark.case('O01')
@pytest.mark.parametrize('stop_at', ['recipient', 'source', 'destination', 'confirmation', 'password'])
def test_send_cancellation_starts_no_work(window, tmp_path, monkeypatch, stop_at):
    source = tmp_path / 'data.txt'
    destination = tmp_path / 'out.sfile'
    if stop_at == 'recipient':
        window.contact.get.return_value = ''
    open_dialog = Mock(return_value='' if stop_at == 'source' else str(source))
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', open_dialog)
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', lambda **kwargs: '' if stop_at == 'destination' else str(destination))
    monkeypatch.setattr(ui.messagebox, 'askyesno', lambda *args, **kwargs: stop_at != 'confirmation')
    if stop_at == 'password':
        window.password.return_value = None
    window.run = Mock()

    window.send()

    window.run.assert_not_called()
    window.app.service.send_file.assert_not_called()
    assert not destination.exists()
    assert not window.busy
    if stop_at == 'recipient':
        open_dialog.assert_not_called()
        assert 'Chọn người nhận' in window.status.set.call_args.args[0]
    else:
        window.status.set.assert_called_once_with('Đã hủy thao tác.')
    assert window.password.call_count == (stop_at == 'password')


@pytest.mark.case('O01')
@pytest.mark.parametrize('package', ['', 'received.sfile'])
def test_receive_cancel_before_prepare(window, monkeypatch, package):
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', lambda **kwargs: package)
    window.password.return_value = None
    window.run = Mock()

    window.receive()

    window.run.assert_not_called()
    window.status.set.assert_called_once_with('Đã hủy thao tác.')
    assert window.password.call_count == bool(package)


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
    window.recipients = Mock()
    window.results = queue.Queue()
    window.executor = Mock()
    show_error = Mock()
    monkeypatch.setattr(ui.messagebox, 'showerror', show_error)
    callback = Mock()
    work = Mock(side_effect=RuntimeError('sensitive adapter details'))

    window.run(work, callback)
    assert window.busy
    window.recipients.configure.assert_called_once_with(state='disabled')
    blocked = Mock()
    window.perform(blocked)
    blocked.assert_not_called()

    window.executor.submit.call_args.args[0]()
    window.poll()

    assert not window.busy
    assert window.recipients.configure.call_args.kwargs == {'state': 'readonly'}
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
