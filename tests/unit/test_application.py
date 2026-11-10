"""Bootstrap tests for the application's storage boundaries."""

import pytest

from secure_share.application import create_application, default_root
from secure_share.errors import ErrorCode, ShareError


def test_default_root_uses_local_app_data(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert default_root() == tmp_path / "Shared-Files-Security"


def test_application_separates_private_storage_from_export_storage(tmp_path):
    root = tmp_path / "app-data"
    app = create_application(root)

    private_path = root / "profiles" / "bootstrap-check.json"
    app.keys.storage.save_atomic(b"private metadata", private_path)

    assert app.keys.storage is app.trust.storage
    assert app.keys.storage is not app.storage
    assert private_path.read_bytes() == b"private metadata"

    with pytest.raises(ShareError) as error:
        app.storage.save_atomic(b"must not enter app data", root / "profiles" / "blocked.json")
    assert error.value.code is ErrorCode.PROTECTED_PATH

    export_path = tmp_path / "shared.sfile"
    receipt = app.storage.save_atomic(b"exported package", export_path)
    assert receipt.destination == export_path
    assert export_path.read_bytes() == b"exported package"
