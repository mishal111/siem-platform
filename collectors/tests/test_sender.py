import json
import tempfile
import unittest
from urllib.error import URLError

from collectors.common.config import Config
from collectors.common.sender import DeliveryBlocked, Sender, retry_after
from collectors.common.spool import Spool
from collectors.tests.fixtures import event


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.payloads = []

    def post(self, payload):
        self.payloads.append(payload)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def receipt(payload, status=201):
    body = {"event": {**payload, "id": "0123456789abcdef01234567"}, "duplicate": status == 200}
    return status, json.dumps(body).encode(), {}


class SenderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.spool = Spool(self.directory.name)
        self.addCleanup(self.spool.close)
        self.spool.enqueue_window([event()], 100)
        self.config = Config(api_key="a" * 64)

    def test_acknowledge_only_valid_new_or_duplicate_receipt(self):
        for status in (201, 200):
            payload = event(status)
            self.spool.enqueue_window([payload], 100)
        responses = [receipt(event()), receipt(event(201)), receipt(event(200), 200)]
        self.assertEqual(Sender(self.config, self.spool, FakeTransport(responses)).drain(), 3)
        self.assertEqual(self.spool.pending(), [])

    def test_network_outage_keeps_exact_payload_and_persists_backoff(self):
        transport = FakeTransport([URLError("unreachable")])
        sender = Sender(self.config, self.spool, transport)
        self.assertEqual(sender.drain(), 0)
        self.assertEqual(self.spool.pending()[0][1], event())
        self.assertEqual(self.spool.status()["retry_count"], 1)
        self.assertEqual(sender.drain(), 0)
        self.assertEqual(len(transport.payloads), 1)

    def test_recovery_reuses_same_uid(self):
        transport = FakeTransport([(503, b"", {}), receipt(event(), 200)])
        sender = Sender(self.config, self.spool, transport)
        sender.drain()
        self.spool.set("next_retry_at", 0)
        self.assertEqual(sender.drain(), 1)
        self.assertEqual(transport.payloads[0], transport.payloads[1])
        self.assertEqual(self.spool.status()["retry_count"], 0)

    def test_permanent_rejection_does_not_block_following_event(self):
        self.spool.enqueue_window([event(1)], 100)
        sender = Sender(self.config, self.spool, FakeTransport([(422, b"", {}), receipt(event(1))]))
        self.assertEqual(sender.drain(), 1)
        self.assertEqual(self.spool.status()["rejected"], 1)

    def test_auth_and_redirect_errors_retain_queue_and_stop(self):
        for status in (401, 403, 404, 302, 204):
            with self.subTest(status=status), self.assertRaises(DeliveryBlocked):
                Sender(self.config, self.spool, FakeTransport([(status, b"", {})])).drain()
        self.assertEqual(len(self.spool.pending()), 1)

    def test_unverified_success_does_not_delete_event(self):
        wrong = {**event(), "event_uid": event(5)["event_uid"]}
        sender = Sender(self.config, self.spool, FakeTransport([receipt(wrong)]))
        self.assertEqual(sender.drain(), 0)
        self.assertEqual(len(self.spool.pending()), 1)

    def test_retry_after_is_bounded(self):
        self.assertEqual(retry_after({"Retry-After": "30"}), 30)
        self.assertEqual(retry_after({"Retry-After": "99999"}), 300)
        self.assertEqual(retry_after({"Retry-After": "invalid"}), 0)
