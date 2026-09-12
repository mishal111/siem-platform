import unittest

from collectors.common.errors import ParseError
from collectors.tests.windows_fixtures import ENDPOINT, windows_xml
from collectors.windows.parser import EVENT_TYPES, MAX_XML_BYTES, normalize


class WindowsParserTests(unittest.TestCase):
    def test_all_supported_codes_have_native_identity_and_mapping(self):
        for code, kind in EVENT_TYPES.items():
            with self.subTest(code=code):
                event = normalize(windows_xml(code), ENDPOINT)
                self.assertEqual(event["event_type"], kind)
                self.assertEqual(event["event_code"], code)
                self.assertEqual(event["source_record_id"], "100")
                self.assertEqual(event["hostname"], "WIN-LAB")
                self.assertEqual(event["timestamp"], "2026-09-10T12:00:00.123456+00:00")

    def test_login_uses_target_account_and_normalizes_unknown_sid_and_ip(self):
        failed = normalize(windows_xml(), ENDPOINT)
        self.assertEqual(failed["username"], "alice")
        self.assertEqual(failed["user_domain"], "LAB")
        self.assertIsNone(failed["user_sid"])
        self.assertEqual(failed["source_ip"], "192.0.2.20")
        self.assertEqual(failed["raw_event"]["data"]["SubjectUserName"], "operator")
        success = normalize(windows_xml(4624), ENDPOINT)
        self.assertEqual(success["user_sid"], "S-1-5-21-100-200-300-1002")

    def test_process_creation_distinguishes_child_parent_and_emitter(self):
        event = normalize(windows_xml(4688), ENDPOINT)
        self.assertEqual(event["process_id"], 0x1234)
        self.assertEqual(event["parent_process_id"], 0x456)
        self.assertTrue(event["process_name"].endswith("whoami.exe"))
        self.assertEqual(event["command_line"], "whoami /user")
        self.assertIsNone(
            normalize(windows_xml(4688, data={"CommandLine": ""}), ENDPOINT)["command_line"]
        )

    def test_group_actor_group_and_member_are_distinct(self):
        event = normalize(windows_xml(4732), ENDPOINT)
        self.assertEqual(event["username"], "operator")
        self.assertEqual(event["group_name"], "Administrators")
        self.assertEqual(event["group_sid"], "S-1-5-32-544")
        self.assertIsNone(event["target_username"])
        self.assertEqual(event["target_user_sid"], "S-1-5-21-100-200-300-1010")

    def test_log_clearing_reads_userdata_namespace(self):
        event = normalize(windows_xml(1102), ENDPOINT)
        self.assertEqual(event["username"], "operator")
        self.assertEqual(event["severity"], "critical")

    def test_unsupported_provider_channel_and_event_are_skipped(self):
        for options in ({"code": 9999}, {"provider": "Unrelated"}, {"channel": "Application"}):
            self.assertIsNone(normalize(windows_xml(**options), ENDPOINT))

    def test_missing_ip_and_account_are_not_invented(self):
        event = normalize(windows_xml(data={"IpAddress": "-", "TargetUserName": "-"}), ENDPOINT)
        self.assertIsNone(event["source_ip"])
        self.assertIsNone(event["username"])
        self.assertIsNone(normalize(windows_xml(data={"IpAddress": "bad"}), ENDPOINT)["source_ip"])

    def test_stable_identity_preserves_native_precision_and_record_reuse(self):
        first = normalize(windows_xml(), ENDPOINT)
        self.assertEqual(first, normalize(windows_xml(), ENDPOINT))
        for xml in (
            windows_xml(record=101),
            windows_xml(stamp="2026-09-10T12:00:00.1234568Z"),
            windows_xml(stamp="2026-09-11T12:00:00.1234567Z"),
        ):
            self.assertNotEqual(first["event_uid"], normalize(xml, ENDPOINT)["event_uid"])

    def test_invalid_xml_fields_and_entity_expansion_are_rejected(self):
        for xml in (
            "not XML",
            "<!DOCTYPE Event [<!ENTITY x 'test'>]>" + windows_xml(),
            "x" * (MAX_XML_BYTES + 1),
            windows_xml(stamp="bad"),
            windows_xml(stamp="2026-09-10T12:00:00"),
            windows_xml(record=-1),
            windows_xml(data={"ProcessId": "0x8000000000000000"}),
            windows_xml(data={"TargetUserName": "a" * 256}),
        ):
            with self.subTest(xml=xml[:50]), self.assertRaises(ParseError):
                normalize(xml, ENDPOINT)
