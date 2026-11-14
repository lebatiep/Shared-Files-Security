import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.launch import configure_data


class LocalDataTests(unittest.TestCase):
    def test_clean_clone_uses_normal_data_location(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'LOCALAPPDATA': 'normal'}):
            configure_data(Path(temp))
            self.assertEqual(os.environ['LOCALAPPDATA'], 'normal')

    def test_explicit_local_config_and_default_override(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'LOCALAPPDATA': 'normal'}):
            root = Path(temp)
            (root / 'demo').mkdir()
            (root / 'run.local.json').write_text(json.dumps({'local_app_data': 'demo'}))
            configure_data(root, use_default=True)
            self.assertEqual(os.environ['LOCALAPPDATA'], 'normal')
            configure_data(root)
            self.assertEqual(Path(os.environ['LOCALAPPDATA']), root / 'demo')

    def test_bad_local_path_does_not_silently_switch_profiles(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'LOCALAPPDATA': 'normal'}):
            root = Path(temp)
            (root / 'run.local.json').write_text(json.dumps({'local_app_data': 'missing'}))
            with self.assertRaises(ValueError):
                configure_data(root)
            self.assertEqual(os.environ['LOCALAPPDATA'], 'normal')
