import unittest

from collectors.macos.parser import ParseError, normalize
from collectors.tests.fixtures import ENDPOINT, native


class ParserTests(unittest.TestCase):
    def parse(self, row):
        return normalize(row, ENDPOINT, "TEST-MAC")

    def test_live_field_shape_and_timezone(self):
        event = self.parse(native())
        self.assertEqual(event["timestamp"], "2026-09-10T14:10:51.117154+00:00")
        self.assertEqual(event["os"], "macos")
        self.assertEqual(event["event_type"], "security_tool_event")
        self.assertNotIn("username", event)
        self.assertNotIn("command_line", event)

    def test_private_identity_is_not_invented(self):
        event = self.parse(
            native("sshd", "Failed password for <private> from <private> port 22 ssh2")
        )
        self.assertEqual(event["event_type"], "login_failure")
        self.assertIsNone(event["username"])
        self.assertIsNone(event["source_ip"])

    def test_ssh_failure_and_success(self):
        for result, expected in (("Failed", "login_failure"), ("Accepted", "login_success")):
            with self.subTest(result=result):
                event = self.parse(
                    native(
                        "sshd-session", result + " password for alice from 192.0.2.2 port 2222 ssh2"
                    )
                )
                self.assertEqual(event["event_type"], expected)
                self.assertEqual(event["username"], "alice")
                self.assertEqual(event["source_ip"], "192.0.2.2")

    def test_ssh_invalid_user_ipv6(self):
        event = self.parse(
            native("sshd", "Failed password for invalid user bob from 2001:db8::2 port 22 ssh2")
        )
        self.assertEqual(event["username"], "bob")
        self.assertEqual(event["source_ip"], "2001:db8::2")

    def test_sudo_command_and_authentication_failure(self):
        event = self.parse(
            native("sudo", "alice : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id")
        )
        self.assertEqual(event["event_type"], "sudo_execution")
        self.assertEqual(event["target_username"], "root")
        self.assertEqual(event["command_line"], "/usr/bin/id")
        failure = self.parse(native("sudo", "alice : 3 incorrect password attempts ; TTY=ttys001"))
        self.assertEqual(failure["event_type"], "login_failure")

    def test_does_not_classify_keywords_outside_expected_sources(self):
        self.assertIsNone(
            self.parse(native("zsh", "Failed password for alice from 192.0.2.1 port 22"))
        )
        self.assertIsNone(
            self.parse(native("sshd", "Example documentation: Failed password for alice"))
        )
        self.assertIsNone(self.parse(native("syspolicyd", "Routine cache lookup")))
        self.assertIsNone(self.parse({"finished": 1, "count": 50}))

    def test_security_tool_denial_is_context_not_alert(self):
        event = self.parse(native("syspolicyd", "assessment denied for synthetic test"))
        self.assertEqual(event["event_type"], "security_tool_event")
        self.assertEqual(event["severity"], "info")

    def test_stable_identity_and_distinct_events(self):
        first = self.parse(native())
        self.assertEqual(first, self.parse(native()))
        self.assertNotEqual(
            first["event_uid"], self.parse(native(machTimestamp=123456790))["event_uid"]
        )
        moved = normalize(native(), ENDPOINT, "RENAMED-MAC")
        self.assertEqual(first["event_uid"], moved["event_uid"])

    def test_bad_selected_record_fails_explicitly(self):
        for row in (
            native(timestamp="no timestamp"),
            native(timestamp="2026-09-10T00:00:00"),
            native(eventMessage=None),
        ):
            with self.subTest(row=row), self.assertRaises(ParseError):
                self.parse(row)

    def test_large_native_unsigned_ids_preserved_as_strings(self):
        event = self.parse(native(traceID=2**64 - 1))
        self.assertEqual(event["raw_event"]["traceID"], str(2**64 - 1))
