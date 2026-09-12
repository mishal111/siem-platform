import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from collectors.common.config import Config, ConfigurationError
from collectors.common.spool import Spool
from collectors.macos.parser import ParseError
from collectors.main import capture_window
from collectors.tests.fixtures import native


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.spool = Spool(self.directory.name)
        self.addCleanup(self.spool.close)
        self.config = Config(api_key="a" * 64)

    def test_catchup_uses_bounded_windows_and_overlap(self):
        source = Mock()
        source.read.return_value = [native()]
        self.assertTrue(capture_window(self.config, self.spool, source, now=1000))
        source.read.assert_called_once_with(932, 967)
        self.assertEqual(self.spool.get("checkpoint"), "967.0")
        self.assertFalse(capture_window(self.config, self.spool, source, now=1000))
        self.assertEqual(len(self.spool.pending()), 1)

    def test_parse_failure_does_not_advance_checkpoint(self):
        source = Mock()
        source.read.return_value = [native(), native(timestamp="bad")]
        with self.assertRaises(ParseError):
            capture_window(self.config, self.spool, source, now=1000)
        self.assertEqual(self.spool.get("checkpoint"), "937")
        self.assertEqual(self.spool.pending(), [])

    def test_empty_window_still_advances_checkpoint(self):
        source = Mock()
        source.read.return_value = [{"finished": 1, "count": 0}]
        capture_window(self.config, self.spool, source, now=1000)
        self.assertIsNotNone(self.spool.get("checkpoint"))

    def test_clock_rollback_does_not_rewind_checkpoint(self):
        self.spool.set("checkpoint", 2000)
        source = Mock()
        self.assertFalse(capture_window(self.config, self.spool, source, now=1000))
        source.read.assert_not_called()
        self.assertEqual(self.spool.get("checkpoint"), "2000")

    def test_remote_plaintext_and_embedded_credentials_rejected(self):
        for url in (
            "http://192.0.2.1/api/v1/events",
            "https://user:password@example.com/api/v1/events",
            "ftp://localhost/api/v1/events",
        ):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                Config(api_key="a" * 64, api_url=url).validate()

    def test_secret_not_exposed_by_config_repr(self):
        self.assertNotIn("a" * 64, repr(self.config))

    def test_default_state_directory_belongs_to_project(self):
        self.assertEqual(self.config.state_dir.parent.parent, Path(__file__).resolve().parents[2])
