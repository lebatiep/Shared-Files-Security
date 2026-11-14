import time

import pytest

from secure_share.ui import app as ui
from tools.demo_threshold import HOLDERS, SENDER, prepare_demo


@pytest.mark.case("R01")
def test_threshold_tab_create_contribute_and_receive(tmp_path, monkeypatch):
    try:
        root = ui.tk.Tk()
    except ui.tk.TclError:
        pytest.skip("Tk display is not available")
    root.withdraw()
    application, passwords = prepare_demo(tmp_path / "private")
    window = ui.App(root, application)
    source = tmp_path / "Hồ sơ.bin"
    source.write_bytes(b"threshold Tk roundtrip\x00\xff")
    package = tmp_path / "survey.sfile2"
    contribution = tmp_path / "hoang-to-nhat-minh.sapproval"
    output = tmp_path / "recovered.bin"
    open_paths = iter((source, package, package, contribution))
    save_paths = iter((package, contribution, output))
    errors = []
    monkeypatch.setattr(ui.filedialog, "askopenfilename", lambda **kwargs: str(next(open_paths)))
    monkeypatch.setattr(ui.filedialog, "asksaveasfilename", lambda **kwargs: str(next(save_paths)))
    monkeypatch.setattr(ui.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *args, **kwargs: None)
    monkeypatch.setattr(window, "password", lambda **kwargs: passwords[window.profile.get()])

    def wait():
        deadline = time.monotonic() + 15
        while window.busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert not window.busy
        assert not errors

    try:
        notebook, = (
            widget for frame in root.winfo_children() for widget in frame.winfo_children()
            if isinstance(widget, ui.ttk.Notebook)
        )
        assert {notebook.tab(tab, "text") for tab in notebook.tabs()} == {
            "My keys", "Contacts", "Two-of-three sharing",
        }
        assert notebook.tab(notebook.select(), "text") == "Two-of-three sharing"
        for profile_id, expected_name in zip((SENDER, *HOLDERS), ("Tiêp", "Nhật Minh", "Hoàng", "Việt"), strict=True):
            assert application.keys.get_profile(profile_id).display_name == expected_name

        window.profile.set(SENDER)
        window.refresh_contacts()
        for selector, holder in zip(window.threshold_holders, HOLDERS, strict=True):
            selector.set(holder)
        window.send_threshold()
        wait()
        assert package.is_file()

        opener, contributor = HOLDERS[:2]
        window.profile.set(contributor)
        window.refresh_contacts()
        window.contribution_recipient.set(opener)
        window.export_contribution()
        wait()
        assert contribution.is_file()

        window.profile.set(opener)
        window.refresh_contacts()
        window.receive_threshold()
        wait()
        assert output.read_bytes() == source.read_bytes()
    finally:
        window.close()
