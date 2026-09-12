import pytest
from collectors.macos.parser import normalize
from collectors.tests.fixtures import ENDPOINT, native
from collectors.tests.windows_fixtures import windows_xml
from collectors.windows.parser import EVENT_TYPES
from collectors.windows.parser import normalize as normalize_windows

from app.models import EventInput


@pytest.mark.parametrize(
    "process,message",
    [
        ("authd", "Synthetic authorization diagnostic"),
        ("sshd", "Failed password for alice from 192.0.2.2 port 22 ssh2"),
        ("sshd-session", "Accepted publickey for bob from 2001:db8::1 port 22 ssh2"),
        ("sudo", "alice : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id"),
        ("syspolicyd", "assessment denied for synthetic test"),
    ],
)
def test_collector_output_matches_backend_contract(process, message):
    payload = normalize(native(process, message), ENDPOINT, "TEST-MAC")
    event = EventInput.model_validate(payload)
    assert event.os == "macos"
    assert event.endpoint_id == ENDPOINT


@pytest.mark.parametrize("code", EVENT_TYPES)
def test_windows_xml_output_matches_backend_contract(code):
    event = EventInput.model_validate(normalize_windows(windows_xml(code), ENDPOINT))
    assert event.os == "windows"
    assert event.event_code == code
    assert event.event_type == EVENT_TYPES[code]
