import re
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from secure_share.errors import ErrorCode
from secure_share.models import ContributionRequest, ThresholdReceiveRequest, ThresholdSendRequest, TrustedContact, TrustStatus
from secure_share.ui import app as ui


def holder(contact_id, encryption, signing, *, status=TrustStatus.VERIFIED):
    return TrustedContact('alice', contact_id, contact_id.title(), encryption * 64, signing * 64,
                          object(), object(), status)


@pytest.fixture
def window():
    holders = {item.contact_id: item for item in (
        holder('bob', 'a', 'b'), holder('carol', 'c', 'd'), holder('dave', 'e', 'f'),
    )}
    app = ui.App.__new__(ui.App)
    app.root = Mock()
    app.status = Mock()
    app.busy = False
    app.closed = False
    app.selected_profile = Mock(return_value='alice')
    app.password = Mock(return_value=b'local password')
    app.app = SimpleNamespace(trust=Mock(), service=Mock(), keys=Mock())
    app.app.trust.resolve_recipient.side_effect = lambda profile, contact_id: holders[contact_id]
    app.app.trust.list_contacts.return_value = list(holders.values())
    app.threshold_holders = tuple(MagicMock() for _ in holders)
    for selector, contact_id in zip(app.threshold_holders, holders):
        selector.get.return_value = contact_id
    app.contribution_recipient = MagicMock()
    app.contribution_recipient.get.return_value = 'bob'
    app.threshold_selectors = (*app.threshold_holders, app.contribution_recipient)
    app.run = Mock(side_effect=lambda work, callback: work())
    return app


def test_threshold_selectors_show_only_verified_contacts_and_clear_on_profile_change(window):
    window.profile = Mock()
    window.profile.get.return_value = 'alice'
    window.recipient_profile = 'alice'
    window.contact = Mock()
    window.contacts = Mock()
    window.contacts.get_children.return_value = ()
    window.recipients = {}
    window.identity = Mock()
    window.app.trust.list_contacts.return_value += [holder('eve', '1', '2', status=TrustStatus.UNVERIFIED)]
    window.threshold_holders[0].get.return_value = 'eve'

    window.refresh_contacts()

    for selector in window.threshold_selectors:
        selector.__setitem__.assert_called_once_with('values', ['bob', 'carol', 'dave'])
    window.threshold_holders[0].set.assert_called_once_with('')
    window.threshold_holders[1].set.assert_called_once_with('carol')
    window.contribution_recipient.set.assert_called_once_with('bob')

    window.profile.get.return_value = 'another-profile'
    window.refresh_contacts()
    for selector in window.threshold_selectors:
        assert selector.set.call_args.args == ('',)


def test_threshold_selectors_are_disabled_while_worker_runs(window):
    window.buttons = [Mock()]
    window.profiles = Mock()
    window.recipients = Mock()
    window.progress = Mock()

    window.set_busy(True)
    for selector in window.threshold_selectors:
        selector.configure.assert_called_once_with(state='disabled')
    window.set_busy(False)
    for selector in window.threshold_selectors:
        assert selector.configure.call_args.kwargs == {'state': 'readonly'}


def test_create_confirms_all_holders_and_passes_exact_pins_to_service(window, tmp_path, monkeypatch):
    source, output = tmp_path / 'private.txt', tmp_path / 'selected.sfile2'
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', Mock(return_value=str(source)))
    save = Mock(return_value=str(output))
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', save)
    confirm = Mock(return_value=True)
    monkeypatch.setattr(ui.messagebox, 'askyesno', confirm)

    window.send_threshold()

    request = window.app.service.send_threshold.call_args.args[0]
    pins = (('a' * 64, 'b' * 64), ('c' * 64, 'd' * 64), ('e' * 64, 'f' * 64))
    assert request == ThresholdSendRequest('alice', ('bob', 'carol', 'dave'), source, output, b'local password',
                                           expected_recipient_fingerprints=pins)
    assert re.fullmatch(r'[0-9a-f]{32}\.sfile2', save.call_args.kwargs['initialfile'])
    assert save.call_args.kwargs['defaultextension'] == '.sfile2'
    notice = confirm.call_args.args[1]
    assert all(name in notice for name in ('Bob (bob)', 'Carol (carol)', 'Dave (dave)'))
    assert all(fingerprint in notice for pair in pins for fingerprint in pair)
    assert str(source) in notice and str(output) in notice
    assert confirm.call_args.kwargs['default'] == ui.messagebox.NO
    window.password.assert_called_once_with()


@pytest.mark.parametrize('problem', ['missing', 'same-id', 'same-key'])
def test_create_rejects_duplicate_or_missing_holders_before_file_selection(window, monkeypatch, problem):
    if problem == 'missing':
        window.threshold_holders[1].get.return_value = ''
    elif problem == 'same-id':
        window.threshold_holders[1].get.return_value = 'bob'
    else:
        window.app.trust.resolve_recipient.side_effect = [
            holder('bob', 'a', 'b'), holder('carol', 'a', 'd'), holder('dave', 'e', 'f'),
        ]
    open_dialog = Mock()
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', open_dialog)
    window.show_error = Mock()

    window.perform(window.send_threshold)

    window.show_error.assert_called_once_with(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
    open_dialog.assert_not_called()
    window.password.assert_not_called()
    window.run.assert_not_called()


def test_export_pins_verified_target_and_chooses_approval_output(window, tmp_path, monkeypatch):
    package, output = tmp_path / 'package.sfile2', tmp_path / 'approval.sapproval'
    open_dialog = Mock(return_value=str(package))
    save = Mock(return_value=str(output))
    confirm = Mock(return_value=True)
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', open_dialog)
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', save)
    monkeypatch.setattr(ui.messagebox, 'askyesno', confirm)

    window.export_contribution()

    window.app.trust.resolve_recipient.assert_called_once_with('alice', 'bob')
    assert open_dialog.call_args.kwargs['filetypes'][0][1] == '*.sfile2'
    assert re.fullmatch(r'[0-9a-f]{32}\.sapproval', save.call_args.kwargs['initialfile'])
    assert save.call_args.kwargs['defaultextension'] == '.sapproval'
    notice = confirm.call_args.args[1]
    assert all(value in notice for value in ('Bob (bob)', 'a' * 64, str(package), str(output)))
    assert confirm.call_args.kwargs['default'] == ui.messagebox.NO
    request = window.app.service.export_contribution.call_args.args[0]
    assert request == ContributionRequest('alice', 'bob', package, output, b'local password',
                                          expected_recipient_fingerprint='a' * 64)


def test_receive_uses_one_local_password_and_existing_prepare_and_save_flow(window, tmp_path, monkeypatch):
    package, approval = tmp_path / 'package.sfile2', tmp_path / 'other.sapproval'
    open_dialog = Mock(side_effect=[str(package), str(approval)])
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', open_dialog)

    window.receive_threshold()

    assert [call.kwargs['filetypes'][0][1] for call in open_dialog.call_args_list] == ['*.sfile2', '*.sapproval']
    window.password.assert_called_once_with()
    window.app.service.prepare_threshold_receive.assert_called_once_with(
        ThresholdReceiveRequest('alice', package, approval, b'local password'))
    assert window.run.call_args.args[1] == window.prepared
    window.app.service.prepare_receive.assert_not_called()


@pytest.mark.parametrize(('operation', 'cancel_at'), [
    ('send_threshold', 'source'), ('send_threshold', 'destination'), ('send_threshold', 'confirmation'),
    ('send_threshold', 'password'), ('export_contribution', 'source'), ('export_contribution', 'destination'),
    ('export_contribution', 'confirmation'), ('export_contribution', 'password'), ('receive_threshold', 'source'),
    ('receive_threshold', 'approval'), ('receive_threshold', 'password'),
])
def test_cancelling_a_threshold_dialog_never_starts_work(window, tmp_path, monkeypatch, operation, cancel_at):
    source, approval, output = tmp_path / 'source', tmp_path / 'approval', tmp_path / 'out'
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', Mock(side_effect=[
        '' if cancel_at == 'source' else str(source), '' if cancel_at == 'approval' else str(approval),
    ]))
    monkeypatch.setattr(ui.filedialog, 'asksaveasfilename', Mock(return_value='' if cancel_at == 'destination' else str(output)))
    monkeypatch.setattr(ui.messagebox, 'askyesno', Mock(return_value=cancel_at != 'confirmation'))
    if cancel_at == 'password':
        window.password.return_value = None

    getattr(window, operation)()

    window.run.assert_not_called()
    window.status.set.assert_called_once_with('Đã hủy thao tác.')
    assert not window.app.service.mock_calls
    assert not output.exists()
    assert window.password.call_count == (cancel_at == 'password')
