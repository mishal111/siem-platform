ENDPOINT = "12345678-1234-5678-1234-567812345678"


def native(process="authd", message="Synthetic authorization diagnostic", **overrides):
    """Invented values in a field layout observed on macOS 26.6.1; no private host data."""
    row = {
        "timestamp": "2026-09-10 19:40:51.117154+0530",
        "eventType": "logEvent",
        "eventMessage": message,
        "processImagePath": "/usr/libexec/" + process,
        "processID": 123,
        "bootUUID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "machTimestamp": 123456789,
        "threadID": 100,
        "traceID": 17,
        "subsystem": "com.apple.Authorization",
        "category": "default",
        "messageType": "Default",
    }
    row.update(overrides)
    return row


def event(number=0):
    from collectors.macos.parser import normalize

    return normalize(native(machTimestamp=number), ENDPOINT, "TEST-MAC")
