from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone

from collectors.common.config import ConfigurationError
from collectors.common.errors import SourceError, SourceGap
from collectors.windows.parser import MAX_XML_BYTES, fingerprint, record_id


@dataclass(frozen=True)
class Batch:
    rows: list
    position: dict
    has_more: bool


class WindowsSource:
    """Read bounded native batches. The caller commits each bookmark with its payloads."""

    def __init__(self, api=None, error_type=OSError):
        if api is None:
            try:
                import pywintypes
                import win32evtlog
            except ImportError as exc:
                raise ConfigurationError(
                    "Install collectors/windows/requirements.txt with your Windows Python"
                ) from exc
            api = win32evtlog
            error_type = pywintypes.error
        self.api = api
        self.native_errors = (OSError, error_type)
        self.stop_record = None

    def _next(self, query, count, stack):
        try:
            handles = self.api.EvtNext(query, count, 1000, 0)
        except self.native_errors as exc:
            if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                return ()
            raise
        for handle in handles:
            stack.callback(handle.Close)
        return handles

    def _xml(self, handle):
        xml = self.api.EvtRender(handle, self.api.EvtRenderEventXml)
        if len(xml.encode("utf-8")) > MAX_XML_BYTES:
            raise SourceError("Windows event exceeds XML size limit")
        return xml

    def _snapshot_end(self):
        with ExitStack() as stack:
            query = self.api.EvtQuery(
                "Security", self.api.EvtQueryChannelPath | self.api.EvtQueryReverseDirection, "*"
            )
            stack.callback(query.Close)
            rows = self._next(query, 1, stack)
            return record_id(self._xml(rows[0])) if rows else 0

    def read(self, position, start, once=False, limit=100, max_bytes=8 * 1024 * 1024):
        if not 1 <= limit <= 100:
            raise ValueError("Native read limit must be between 1 and 100")
        try:
            if once and self.stop_record is None:
                # A fixed record boundary keeps --once finite on busy hosts; no clock filter
                # is applied after bookmarking, so clock corrections cannot skip new records.
                self.stop_record = self._snapshot_end()
            if once and self.stop_record == 0 and not position:
                return Batch([], {}, False)
            conditions = []
            if once:
                conditions.append("EventRecordID <= {}".format(self.stop_record))
            if not position and start > 0:
                stamp = (
                    datetime.fromtimestamp(start, timezone.utc).isoformat().replace("+00:00", "Z")
                )
                conditions.append("TimeCreated[@SystemTime >= '{}']".format(stamp))
            xpath = "*[System[{}]]".format(" and ".join(conditions)) if conditions else "*"
            with ExitStack() as stack:
                query = self.api.EvtQuery(
                    "Security",
                    self.api.EvtQueryChannelPath | self.api.EvtQueryForwardDirection,
                    xpath,
                )
                stack.callback(query.Close)
                bookmark = self.api.EvtCreateBookmark(
                    position.get("bookmark") if position else None
                )
                stack.callback(bookmark.Close)
                if position:
                    try:
                        self.api.EvtSeek(
                            query,
                            0,
                            self.api.EvtSeekRelativeToBookmark | self.api.EvtSeekStrict,
                            bookmark,
                            0,
                        )
                        anchor = self._next(query, 1, stack)
                    except self.native_errors as exc:
                        if getattr(exc, "winerror", None) in (259, 15011, 15012):
                            raise SourceGap("Windows bookmark is no longer present") from exc
                        raise
                    if not anchor or fingerprint(self._xml(anchor[0])) != position.get(
                        "fingerprint"
                    ):
                        raise SourceGap(
                            "Windows bookmark event is missing or its record ID was reused"
                        )
                handles = self._next(query, limit, stack)
                rows = []
                size = 0
                for handle in handles:
                    xml = self._xml(handle)
                    size += len(xml.encode("utf-8"))
                    if size > max_bytes:
                        # Return a smaller complete batch. Uncommitted handles are reread.
                        if not rows:
                            raise SourceError("Windows batch exceeds byte limit")
                        break
                    rows.append(xml)
                    self.api.EvtUpdateBookmark(bookmark, handle)
                if rows:
                    position = {
                        "bookmark": self.api.EvtRender(bookmark, self.api.EvtRenderBookmark),
                        "fingerprint": fingerprint(rows[-1]),
                    }
                # EvtNext can return a partial batch. Only an empty read establishes EOF.
                return Batch(rows, position or {}, bool(rows))
        except self.native_errors as exc:
            if getattr(exc, "winerror", None) in (15011, 15012):
                raise SourceGap(
                    "Windows query became stale; inspect log retention or clearing"
                ) from exc
            # Do not log native exception messages; they may include event or account data.
            raise SourceError(
                "Windows Security log unavailable; check access and Event Log service"
            ) from exc
