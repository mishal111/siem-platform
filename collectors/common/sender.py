import json
import logging
import random
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

logger = logging.getLogger("siem.collector")


class DeliveryBlocked(Exception):
    """Credentials, URL, or protocol configuration needs operator attention."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self, config):
        self.config = config
        # Do not send telemetry/keys via environment-configured proxies or redirect destinations.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def post(self, payload):
        request = Request(
            self.config.api_url,
            data=json.dumps(payload, allow_nan=False).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": self.config.api_key},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.config.request_timeout) as response:
                return response.status, response.read(1_048_577), response.headers
        except HTTPError as exc:
            # Server error bodies may contain telemetry. They are neither logged nor needed.
            with exc:
                return exc.code, b"", exc.headers


def retry_after(headers):
    value = headers.get("Retry-After", "")
    try:
        delay = float(value)
    except (ValueError, TypeError):
        try:
            instant = parsedate_to_datetime(value)
            delay = (instant - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return 0
    # Prevent invalid/infinite or excessively large server hints from wedging the collector.
    return min(300, max(0, delay))


class Sender:
    def __init__(self, config, spool, transport=None):
        self.config = config
        self.spool = spool
        self.transport = transport or Transport(config)

    def _retry(self, headers):
        attempts = int(self.spool.get("retry_count", "0"))
        delay = max(retry_after(headers), min(300, 2 ** min(attempts, 8)) + random.random())
        self.spool.retry_later(delay)
        logger.warning(json.dumps({"event": "delivery_retry", "delay_seconds": round(delay, 2)}))

    def drain(self):
        if time.time() < float(self.spool.get("next_retry_at", "0")):
            return 0
        delivered = 0
        for uid, payload in self.spool.pending(self.config.batch_size):
            try:
                status, body, headers = self.transport.post(payload)
            except (URLError, OSError, TimeoutError):
                self._retry({})
                break
            if status in (200, 201):
                try:
                    receipt = json.loads(body) if len(body) <= 1_048_576 else None
                    event = receipt["event"]
                    valid = (
                        event["event_uid"] == uid
                        and event["endpoint_id"] == payload["endpoint_id"]
                        and re.fullmatch(r"[0-9a-fA-F]{24}", event["id"])
                        and receipt["duplicate"] is (status == 200)
                    )
                except (ValueError, TypeError, KeyError, UnicodeError):
                    valid = False
                if not valid:
                    self._retry({})
                    break
                self.spool.acknowledge(uid)
                delivered += 1
            elif status in (400, 409, 413, 415, 422):
                self.spool.quarantine(uid, "http_{}".format(status))
                logger.error(
                    json.dumps({"event": "event_quarantined", "status": status, "uid": uid})
                )
            elif status in (408, 425, 429) or 500 <= status <= 599:
                self._retry(headers)
                break
            else:
                # Includes 401/403, wrong endpoints, redirects, and unexpected success statuses.
                raise DeliveryBlocked(
                    "Delivery blocked by HTTP {}; queued events retained".format(status)
                )
        return delivered
