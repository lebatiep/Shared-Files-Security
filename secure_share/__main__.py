"""Command-line entry point and honest checks for the project foundation."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
from pathlib import Path
import sys
from typing import TextIO

from . import __version__


_INTEGRATION_MODULES = (
    "keys",
    "trust_store",
    "crypto_ops",
    "envelope",
    "storage",
    "ui.app",
)


def _module_file(module_name: str) -> Path:
    """Return the planned source location without importing collaborators' code."""
    return Path(__file__).resolve().parent.joinpath(*module_name.split(".")).with_suffix(".py")


def environment_report() -> dict[str, object]:
    """Inspect dependencies and module presence, without generating any secrets."""
    python_supported = sys.version_info >= (3, 12)
    crypto_available = False
    crypto_version: str | None = None
    crypto_error: str | None = None
    try:
        crypto_version = importlib.metadata.version("cryptography")
        # Importing the compiled primitive also catches a broken local install.
        importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
        crypto_available = True
    except Exception as exc:
        # A broken compiled dependency must also produce a readable check result.
        # Do not print its arguments, which can include private local paths.
        crypto_error = type(exc).__name__

    missing = [
        f"secure_share.{name}"
        for name in _INTEGRATION_MODULES
        if not _module_file(name).is_file()
    ]
    return {
        "project": "Shared-Files-Security",
        "version": __version__,
        "python_version": sys.version.split()[0],
        "python_supported": python_supported,
        "cryptography_available": crypto_available,
        "cryptography_version": crypto_version,
        "cryptography_error": crypto_error,
        "environment_ready": python_supported and crypto_available,
        "integration_modules_present": not missing,
        "missing_integration_modules": missing,
        "integration_note": (
            "Module presence is a wiring check, not proof of working encryption or a passing release."
        ),
    }


def _message(message: str, stream: TextIO | None = None) -> None:
    """Print a safe message even when a redirected Windows stream is not UTF-8."""
    destination = sys.stderr if stream is None else stream
    try:
        print(message, file=destination)
    except UnicodeEncodeError:
        encoding = destination.encoding or "utf-8"
        printable = message.encode(encoding, errors="backslashreplace").decode(encoding)
        print(printable, file=destination)


def _run_ui() -> int:
    if not _module_file("ui.app").is_file():
        _message(
            "Giao diện chưa được triển khai. Việt cần cung cấp secure_share/ui/app.py "
            "với hàm main(). Dùng --check để xem các phần còn thiếu."
        )
        return 2

    try:
        ui_module = importlib.import_module("secure_share.ui.app")
    except Exception as exc:
        # Do not mislabel a missing dependency inside an existing UI as a missing UI.
        # Exception arguments may contain private information, so show only its type.
        _message(f"Khởi tạo giao diện thất bại ({type(exc).__name__}). Kiểm tra phần tích hợp.")
        return 2

    ui_main = getattr(ui_module, "main", None)
    if not callable(ui_main):
        _message("Giao diện chưa cung cấp hàm main() có thể gọi được.")
        return 2
    try:
        result = ui_main()
    except Exception as exc:
        _message(f"Giao diện dừng vì lỗi ({type(exc).__name__}). Kiểm tra phần tích hợp.")
        return 2
    if result is None:
        return 0
    if type(result) is int:
        return result
    _message("Hàm main() của giao diện phải trả về None hoặc mã thoát kiểu int.")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m secure_share",
        description="Shared Files Security: project entry point and environment check.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report Python/dependency readiness and missing integration modules as JSON",
    )
    args = parser.parse_args(argv)
    if args.check:
        report = environment_report()
        # ASCII JSON also works through redirected legacy Windows terminals.
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 0 if report["environment_ready"] else 2
    return _run_ui()


if __name__ == "__main__":
    raise SystemExit(main())
