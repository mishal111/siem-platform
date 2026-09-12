import base64

import pytest

from app.models import EventFilters, EventInput
from app.repository import InvalidCursor, build_query, decode_cursor


@pytest.mark.parametrize(
    "value", ["!bad", "", "e30=", base64.b64encode(b'{"$where":"x"}').decode()]
)
def test_reject_malformed_cursor(value):
    with pytest.raises(InvalidCursor):
        decode_cursor(value)


def test_filter_values_are_literals():
    query = build_query(EventFilters(username='{"$ne":null}', hostname=".*"))
    assert query == {"username": '{"$ne":null}', "hostname": ".*"}


def test_raw_event_depth_is_bounded(payload):
    nested = {}
    for _ in range(34):
        nested = {"child": nested}
    payload["raw_event"] = nested
    with pytest.raises(ValueError, match="nesting"):
        EventInput.model_validate(payload)
