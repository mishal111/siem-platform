import tempfile
import unittest

from collectors.common.spool import AlreadyRunning, QueueFull, Spool
from collectors.tests.fixtures import event


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_pending_payload_identity_and_checkpoint_survive_restart(self):
        with Spool(self.directory.name) as spool:
            endpoint = spool.endpoint_id
            spool.enqueue_window([event()], 100)
        with Spool(self.directory.name) as spool:
            self.assertEqual(spool.endpoint_id, endpoint)
            self.assertEqual(spool.pending()[0][1], event())
            self.assertEqual(float(spool.get("checkpoint")), 100)

    def test_full_window_rolls_back_events_and_checkpoint(self):
        with Spool(self.directory.name, max_events=1) as spool:
            spool.set("checkpoint", 50)
            with self.assertRaises(QueueFull):
                spool.enqueue_window([event(1), event(2)], 100)
            self.assertEqual(spool.pending(), [])
            self.assertEqual(spool.get("checkpoint"), "50")

    def test_byte_capacity_is_enforced(self):
        with Spool(self.directory.name, max_bytes=10) as spool:
            with self.assertRaises(QueueFull):
                spool.enqueue_window([event()], 100)
            self.assertIsNone(spool.get("checkpoint"))

    def test_overlap_and_sent_receipts_do_not_requeue(self):
        with Spool(self.directory.name) as spool:
            spool.enqueue_window([event(), event()], 100)
            self.assertEqual(len(spool.pending()), 1)
            spool.acknowledge(event()["event_uid"])
            changed = {**event(), "hostname": "NEW-NAME"}
            spool.enqueue_window([changed], 110)
            self.assertEqual(spool.pending(), [])
            self.assertEqual(spool.status()["buffered_bytes"], 0)
            self.assertEqual(spool.status()["delivered_total"], 1)

    def test_rejected_events_remain_for_inspection(self):
        with Spool(self.directory.name) as spool:
            spool.enqueue_window([event()], 100)
            spool.quarantine(event()["event_uid"], "http_422")
            self.assertEqual(spool.pending(), [])
            self.assertEqual(spool.status()["rejected"], 1)
            self.assertGreater(spool.status()["buffered_bytes"], 0)

    def test_second_process_cannot_share_spool(self):
        with Spool(self.directory.name), self.assertRaises(AlreadyRunning):
            Spool(self.directory.name)

    def test_retry_timer_survives_restart(self):
        with Spool(self.directory.name) as spool:
            spool.retry_later(30)
            next_retry = spool.get("next_retry_at")
        with Spool(self.directory.name) as spool:
            self.assertEqual(spool.get("next_retry_at"), next_retry)
            self.assertEqual(spool.status()["retry_count"], 1)
