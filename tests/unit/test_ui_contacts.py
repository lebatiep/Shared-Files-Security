from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from secure_share.models import TrustStatus
from secure_share.ui import app as ui


@pytest.mark.parametrize('conflicts,status', [
    ((), TrustStatus.VERIFIED),
    ((object(),), TrustStatus.UNVERIFIED),
])
def test_import_contact_warns_on_name_conflict(monkeypatch, conflicts, status):
    trust = SimpleNamespace(
        import_contact=Mock(return_value=SimpleNamespace(status=status)),
        find_name_conflicts=Mock(return_value=conflicts))
    window = ui.App.__new__(ui.App)
    window.root = object()
    window.app = SimpleNamespace(
        trust=trust, storage=SimpleNamespace(read_limited=Mock(return_value=b'bundle')))
    window.selected_profile = Mock(return_value='alice')
    window.refresh_contacts = Mock()
    window.status = Mock()
    monkeypatch.setattr(ui.filedialog, 'askopenfilename', lambda **kwargs: 'bundle.json')
    monkeypatch.setattr(ui.simpledialog, 'askstring', lambda *args, **kwargs: 'bob')
    warning = Mock()
    monkeypatch.setattr(ui.messagebox, 'showwarning', warning)

    window.import_contact()

    trust.import_contact.assert_called_once_with('alice', 'bob', b'bundle')
    trust.find_name_conflicts.assert_called_once_with('alice', 'bob')
    window.refresh_contacts.assert_called_once()
    assert warning.call_count == bool(conflicts)
    text = window.status.set.call_args.args[0]
    assert ('preserved' in text) == (status is TrustStatus.VERIFIED)
