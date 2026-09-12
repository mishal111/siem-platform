import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from collectors.common.config import Config
from collectors.common.errors import ParseError, SourceError, SourceGap
from collectors.common.spool import QueueFull, Spool
from collectors.main import capture_windows, main
from collectors.tests.windows_fixtures import windows_xml
from collectors.windows.source import Batch

POSITION = {"bookmark": "<BookmarkList/>", "fingerprint": "synthetic-fingerprint"}


class WindowsCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Config(api_key="a" * 64, state_dir=self.directory.name)

    def test_restart_preserves_queue_endpoint_and_atomic_bookmark(self):
        source = Mock()
        source.read.return_value = Batch([windows_xml()], POSITION, True)
        with Spool(self.directory.name) as spool:
            endpoint = spool.endpoint_id
            self.assertTrue(capture_windows(self.config, spool, source, now=1000))
            original = spool.pending()
        with Spool(self.directory.name) as spool:
            self.assertEqual(spool.endpoint_id, endpoint)
            self.assertEqual(spool.pending(), original)
            capture_windows(self.config, spool, source, once=True, now=2000)
            source.read.assert_called_with(POSITION, 940.0, once=True, limit=100)
            self.assertEqual(spool.pending(), original)

    def test_queue_full_rolls_back_entire_batch_and_bookmark(self):
        source = Mock()
        source.read.return_value = Batch([windows_xml(), windows_xml(record=101)], POSITION, True)
        with Spool(self.directory.name, max_events=1) as spool:
            with self.assertRaises(QueueFull):
                capture_windows(self.config, spool, source, now=1000)
            self.assertEqual(spool.pending(), [])
            self.assertIsNone(spool.get("windows_position"))
            self.assertEqual(spool.get("windows_start"), "940")

    def test_malformed_selected_record_retains_bookmark_and_all_rows(self):
        source = Mock()
        source.read.return_value = Batch([windows_xml(), windows_xml(stamp="bad")], POSITION, True)
        with Spool(self.directory.name) as spool:
            with self.assertRaises(ParseError):
                capture_windows(self.config, spool, source, now=1000)
            self.assertEqual(spool.pending(), [])
            self.assertIsNone(spool.get("windows_position"))

    def test_unsupported_events_advance_bookmark_without_payload(self):
        source = Mock()
        source.read.return_value = Batch([windows_xml(code=9999)], POSITION, False)
        with Spool(self.directory.name) as spool:
            capture_windows(self.config, spool, source)
            self.assertEqual(spool.pending(), [])
            self.assertEqual(json.loads(spool.get("windows_position")), POSITION)

    def test_failed_initial_read_retains_lookback_anchor(self):
        source = Mock()
        source.read.side_effect = SourceError("unavailable")
        with Spool(self.directory.name) as spool:
            for now in (1000, 2000):
                with self.assertRaises(SourceError):
                    capture_windows(self.config, spool, source, now=now)
            self.assertEqual(spool.get("windows_start"), "940")

    def test_corrupt_saved_position_is_not_silently_ignored(self):
        with Spool(self.directory.name) as spool:
            for value in ("not-json", "[]", '{"bookmark": 12}'):
                spool.set("windows_position", value)
                with self.assertRaises(SourceGap):
                    capture_windows(self.config, spool, Mock())

    def test_explicit_recovery_retains_endpoint_queue_and_receipts(self):
        source = Mock()
        source.read.return_value = Batch([windows_xml(), windows_xml(record=101)], POSITION, False)
        with Spool(self.directory.name) as spool:
            capture_windows(self.config, spool, source)
            endpoint = spool.endpoint_id
            spool.acknowledge(spool.pending()[0][0])
            pending = spool.pending()
        with (
            patch("collectors.main.platform.system", return_value="Windows"),
            patch("collectors.main.load_config", return_value=self.config),
            patch("builtins.print"),
        ):
            self.assertEqual(main(["--reset-windows-bookmark"]), 0)
        with Spool(self.directory.name) as spool:
            self.assertEqual(spool.endpoint_id, endpoint)
            self.assertEqual(spool.pending(), pending)
            self.assertEqual(spool.status()["recent_receipts"], 1)
            self.assertEqual(spool.status()["windows_replay_count"], 1)
            self.assertEqual(spool.get("windows_start"), "0")
            self.assertIsNone(spool.get("windows_position"))

    def test_cli_dispatches_windows_once_and_persists_gap_status(self):
        with (
            patch("collectors.main.platform.system", return_value="Windows"),
            patch("collectors.main.load_config", return_value=self.config),
            patch("collectors.main.WindowsSource") as source,
            patch("collectors.main.Sender") as sender,
            patch("builtins.print"),
        ):
            sender.return_value.drain.return_value = False
            source.return_value.read.side_effect = SourceGap("expired")
            self.assertEqual(main(["--once"]), 2)
            self.assertTrue(source.return_value.read.call_args.kwargs["once"])
        with Spool(self.directory.name) as spool:
            self.assertEqual(spool.status()["source_error"], "SourceGap")

    def test_mac_state_is_not_reused_on_windows(self):
        with Spool(self.directory.name) as spool:
            spool.set("checkpoint", 100)
        with (
            patch("collectors.main.platform.system", return_value="Windows"),
            patch("collectors.main.load_config", return_value=self.config),
        ):
            self.assertEqual(main(["--once"]), 1)
