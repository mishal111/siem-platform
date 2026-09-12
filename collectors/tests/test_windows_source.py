import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from collectors.common.errors import SourceError, SourceGap
from collectors.tests.windows_fixtures import windows_xml
from collectors.windows.parser import fingerprint
from collectors.windows.source import WindowsSource


class NativeError(Exception):
    def __init__(self, code):
        self.winerror = code


def handle(xml):
    return SimpleNamespace(xml=xml, Close=Mock())


def fake_api(batches):
    api = SimpleNamespace(
        EvtQueryChannelPath=1,
        EvtQueryForwardDirection=256,
        EvtQueryReverseDirection=512,
        EvtSeekRelativeToBookmark=4,
        EvtSeekStrict=65536,
        EvtRenderEventXml=1,
        EvtRenderBookmark=2,
    )
    api.query = handle("query")
    api.bookmark = handle("<BookmarkList/>")
    api.EvtQuery = Mock(return_value=api.query)
    api.EvtCreateBookmark = Mock(return_value=api.bookmark)
    api.EvtNext = Mock(side_effect=batches)
    api.EvtSeek = Mock()
    api.EvtRender = Mock(side_effect=lambda item, flags: item.xml)
    api.EvtUpdateBookmark = Mock()
    return api


class WindowsSourceTests(unittest.TestCase):
    def test_native_read_closes_handles_and_returns_bookmark(self):
        row = handle(windows_xml())
        api = fake_api([(row,)])
        batch = WindowsSource(api).read({}, 1000)
        self.assertEqual(batch.rows, [row.xml])
        self.assertEqual(batch.position["fingerprint"], fingerprint(row.xml))
        self.assertTrue(batch.has_more)
        self.assertIn("TimeCreated", api.EvtQuery.call_args.args[2])
        for item in (row, api.query, api.bookmark):
            item.Close.assert_called_once()

    def test_resume_validates_and_discards_anchor_before_reading_new_events(self):
        anchor, new = handle(windows_xml()), handle(windows_xml(record=101))
        api = fake_api([(anchor,), (new,)])
        position = {"bookmark": "saved", "fingerprint": fingerprint(anchor.xml)}
        batch = WindowsSource(api).read(position, 0)
        self.assertEqual(batch.rows, [new.xml])
        self.assertEqual(api.EvtQuery.call_args.args[2], "*")
        api.EvtSeek.assert_called_once_with(api.query, 0, 65540, api.bookmark, 0)

    def test_reused_record_id_or_missing_anchor_reports_gap(self):
        for rows in ((), (handle(windows_xml(stamp="2026-09-11T12:00:00Z")),)):
            api = fake_api([rows])
            with self.assertRaises(SourceGap):
                WindowsSource(api).read(
                    {"bookmark": "saved", "fingerprint": fingerprint(windows_xml())}, 0
                )
            api.bookmark.Close.assert_called_once()

    def test_native_stale_bookmark_is_a_gap(self):
        api = fake_api([])
        api.EvtSeek.side_effect = NativeError(15011)
        with self.assertRaises(SourceGap):
            WindowsSource(api, NativeError).read({"bookmark": "saved", "fingerprint": "hash"}, 0)
        api.query.Close.assert_called_once()

    def test_access_failure_is_not_treated_as_empty_or_reset(self):
        api = fake_api([])
        api.EvtQuery.side_effect = NativeError(5)
        with self.assertRaises(SourceError) as caught:
            WindowsSource(api, NativeError).read({}, 0)
        self.assertNotIsInstance(caught.exception, SourceGap)
        api.EvtCreateBookmark.assert_not_called()

    def test_native_empty_and_no_more_items_are_eof(self):
        for result in ((), NativeError(259)):
            batch = WindowsSource(fake_api([result]), NativeError).read({}, 0)
            self.assertEqual(batch.rows, [])
            self.assertFalse(batch.has_more)

    def test_byte_limit_returns_smaller_batch_and_closes_unused_handles(self):
        first, second = handle(windows_xml()), handle(windows_xml(record=101))
        api = fake_api([(first, second)])
        batch = WindowsSource(api).read({}, 0, max_bytes=len(first.xml.encode()))
        self.assertEqual(batch.rows, [first.xml])
        self.assertTrue(batch.has_more)
        api.EvtUpdateBookmark.assert_called_once_with(api.bookmark, first)
        second.Close.assert_called_once()

    def test_once_uses_fixed_native_boundary_across_partial_reads(self):
        last, first = handle(windows_xml(record=200)), handle(windows_xml())
        api = fake_api([(last,), (first,), (first,), ()])
        source = WindowsSource(api)
        batch = source.read({}, 0, once=True)
        self.assertTrue(batch.has_more)
        end = source.read(batch.position, 0, once=True)
        self.assertFalse(end.has_more)
        queries = api.EvtQuery.call_args_list
        self.assertEqual(len(queries), 3)  # One reverse snapshot, two forward reads.
        self.assertEqual(queries[0].args[1], 513)
        for call in queries[1:]:
            self.assertIn("EventRecordID <= 200", call.args[2])

    @unittest.skipUnless(sys.platform == "win32", "Native Event Log API requires Windows")
    def test_native_application_log_api_smoke(self):
        # Read-only, low-privilege check of the actual extension, handles, and API signatures.
        api = WindowsSource().api
        query = api.EvtQuery(
            "Application", api.EvtQueryChannelPath | api.EvtQueryReverseDirection, "*"
        )
        try:
            rows = api.EvtNext(query, 1, 1000, 0)
            if not rows:
                self.skipTest("Application log is empty")
            event = rows[0]
            bookmark = api.EvtCreateBookmark(None)
            try:
                api.EvtUpdateBookmark(bookmark, event)
                self.assertIn("Bookmark", api.EvtRender(bookmark, api.EvtRenderBookmark))
                self.assertIn("Event", api.EvtRender(event, api.EvtRenderEventXml))
                api.EvtSeek(
                    query, 0, api.EvtSeekRelativeToBookmark | api.EvtSeekStrict, bookmark, 0
                )
                resumed = api.EvtNext(query, 1, 1000, 0)
                self.assertEqual(len(resumed), 1)
                for item in resumed:
                    item.Close()
            finally:
                bookmark.Close()
                event.Close()
        finally:
            query.Close()
