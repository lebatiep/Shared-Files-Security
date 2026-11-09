"""Entry-point checks that do not require collaborators' implementations."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from secure_share import __version__
from secure_share import __main__ as cli


class StartupTests(unittest.TestCase):
    def test_version_is_available_without_starting_ui(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn(__version__, output.getvalue())

    def test_help_documents_check(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("--check", output.getvalue())

    def test_check_reports_pending_integrations_but_environment_can_pass(self):
        report = {
            "environment_ready": True,
            "integration_modules_present": False,
            "missing_integration_modules": ["secure_share.crypto_ops"],
        }
        output = io.StringIO()
        with patch.object(cli, "environment_report", return_value=report):
            with redirect_stdout(output):
                result = cli.main(["--check"])
        self.assertEqual(result, 0)
        self.assertFalse(json.loads(output.getvalue())["integration_modules_present"])

    def test_check_fails_when_environment_is_not_ready(self):
        output = io.StringIO()
        with patch.object(cli, "environment_report", return_value={"environment_ready": False}):
            with redirect_stdout(output):
                self.assertEqual(cli.main(["--check"]), 2)

    def test_broken_crypto_install_is_reported_without_exception_arguments(self):
        with patch.object(cli.importlib.metadata, "version", return_value="test-version"):
            with patch.object(cli.importlib, "import_module", side_effect=RuntimeError("private-local-path")):
                report = cli.environment_report()
        self.assertFalse(report["environment_ready"])
        self.assertFalse(report["cryptography_available"])
        self.assertEqual(report["cryptography_error"], "RuntimeError")
        self.assertNotIn("private-local-path", json.dumps(report))

    def test_missing_ui_has_clear_message_and_does_not_import_it(self):
        output = io.StringIO()
        with patch.object(cli, "_module_file") as source:
            source.return_value.is_file.return_value = False
            with patch.object(cli.importlib, "import_module") as importer:
                with redirect_stderr(output):
                    self.assertEqual(cli.main([]), 2)
                importer.assert_not_called()
        self.assertIn("ui/app.py", output.getvalue())

    def test_internal_missing_dependency_is_not_misreported_as_missing_ui(self):
        output = io.StringIO()
        with patch.object(cli, "_module_file") as source:
            source.return_value.is_file.return_value = True
            with patch.object(cli.importlib, "import_module", side_effect=ModuleNotFoundError("private-module")):
                with redirect_stderr(output):
                    self.assertEqual(cli.main([]), 2)
        self.assertIn("ModuleNotFoundError", output.getvalue())
        self.assertNotIn("private-module", output.getvalue())
        self.assertNotIn("chưa được triển khai", output.getvalue())

    def test_ready_ui_main_is_called(self):
        calls = []
        module = SimpleNamespace(main=lambda: calls.append(True))
        with patch.object(cli, "_module_file") as source:
            source.return_value.is_file.return_value = True
            with patch.object(cli.importlib, "import_module", return_value=module):
                self.assertEqual(cli.main([]), 0)
        self.assertEqual(calls, [True])

    def test_ui_without_main_is_an_integration_error(self):
        output = io.StringIO()
        with patch.object(cli, "_module_file") as source:
            source.return_value.is_file.return_value = True
            with patch.object(cli.importlib, "import_module", return_value=SimpleNamespace()):
                with redirect_stderr(output):
                    self.assertEqual(cli.main([]), 2)
        self.assertIn("main()", output.getvalue())

    def test_ui_error_does_not_print_exception_arguments(self):
        def broken_ui():
            raise ValueError("test-secret-passphrase")

        output = io.StringIO()
        with patch.object(cli, "_module_file") as source:
            source.return_value.is_file.return_value = True
            with patch.object(cli.importlib, "import_module", return_value=SimpleNamespace(main=broken_ui)):
                with redirect_stderr(output):
                    self.assertEqual(cli.main([]), 2)
        self.assertIn("ValueError", output.getvalue())
        self.assertNotIn("test-secret-passphrase", output.getvalue())

    def test_check_does_not_write_runtime_in_current_directory(self):
        repo_root = Path(__file__).resolve().parents[2]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root)
        with tempfile.TemporaryDirectory() as target:
            completed = subprocess.run(
                [sys.executable, "-m", "secure_share", "--check"],
                cwd=target,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertIn(completed.returncode, (0, 2))
            self.assertIn("environment_ready", json.loads(completed.stdout))
            self.assertEqual(list(Path(target).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
