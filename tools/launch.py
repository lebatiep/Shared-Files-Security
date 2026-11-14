"""Desktop launcher with optional machine-local data and bundled Tcl/Tk support."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile


def configure_data(repo, use_default=False):
    config = repo / 'run.local.json'
    if use_default or not config.exists():
        return
    settings = json.loads(config.read_text(encoding='utf-8-sig'))
    path = Path(settings['local_app_data']).expanduser()
    if not path.is_absolute():
        path = repo / path
    if not path.is_dir():
        raise ValueError('The configured local data directory does not exist.')
    os.environ['LOCALAPPDATA'] = str(path.resolve())


def configure_tk():
    import tkinter
    # Most Python installers already expose Tcl/Tk scripts normally.
    try:
        tkinter.Tcl()
        return
    except tkinter.TclError:
        pass
    # Some Windows installers bundle them in ZIPs beside the interpreter.
    source = Path(sys.base_prefix) / 'tcl'
    version = str(tkinter.TclVersion)
    archives = []
    for kind in ('tcl', 'tk'):
        matches = sorted(source.glob(f'lib{kind}{version}.*.zip'))
        if not matches:
            raise RuntimeError('Tcl/Tk runtime not found. Repair the Python installation with Tcl/Tk enabled.')
        archives.append(matches[-1])
    digest = hashlib.sha256(b''.join(p.read_bytes() for p in archives)).hexdigest()[:20]
    cache = Path(tempfile.gettempdir()) / 'shared-files-security-tk' / digest
    cache.mkdir(parents=True, exist_ok=True)
    for archive in archives:
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                target = (cache / entry.filename).resolve()
                if not target.is_relative_to(cache.resolve()):
                    raise ValueError('Invalid Tcl/Tk archive path.')
            bundle.extractall(cache)
    for variable, folder, script in [('TCL_LIBRARY', 'tcl_library', 'init.tcl'),
                                      ('TK_LIBRARY', 'tk_library', 'tk.tcl')]:
        directory = cache / folder
        if not (directory / script).is_file():
            raise RuntimeError('Incomplete Tcl/Tk runtime. Repair the Python installation.')
        os.environ[variable] = str(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--default-data', action='store_true')
    args = parser.parse_args(argv)
    try:
        configure_data(Path(__file__).resolve().parents[1], args.default_data)
        configure_tk()
        if not args.check:
            from secure_share.__main__ import main as run_app
            return run_app([])
        from secure_share.__main__ import main as check_environment
        if check_environment(['--check']):
            return 2
        import tkinter as tk
        from secure_share.application import create_application
        from secure_share.ui.app import App
        root = tk.Tk()
        root.withdraw()
        try:
            # A startup check must not create or modify the user's profiles.
            with tempfile.TemporaryDirectory(prefix='sfs-startup-') as temp:
                app = create_application(temp)
                try:
                    ui = App(root, app)
                    ui.executor.shutdown(wait=True)
                    print('Desktop startup: OK')
                finally:
                    app.service.close()
        finally:
            root.destroy()
        return 0
    except Exception as exc:
        print(f'Cannot start the app ({type(exc).__name__}). Check Python/Tkinter and run.local.json, if present.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
