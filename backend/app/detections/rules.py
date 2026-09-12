from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    mitre_name: str
    description: str
    threshold: int
    window_seconds: int
    suppression_seconds: int
    version: int = 1


FAILED_LOGINS = Rule(
    "AUTH-BRUTE-001",
    "Repeated failed logins",
    "high",
    "T1110",
    "Brute Force",
    "At least five matching failed logins occurred within five minutes.",
    5,
    300,
    300,
    version=2,
)
SUCCESS_AFTER_FAILURES = Rule(
    "AUTH-SUCCESS-001",
    "Successful login after repeated failures",
    "high",
    "T1110",
    "Brute Force",
    "A successful login followed at least five matching failures in the preceding ten minutes. "
    "This sequence warrants investigation; it does not establish account compromise.",
    5,
    600,
    0,
    version=2,
)
LOG_CLEARING = Rule(
    "WIN-LOG-CLEAR-001",
    "Windows Security audit log cleared",
    "critical",
    "T1070.001",
    "Clear Windows Event Logs",
    "Windows Security event 1102 reported that the audit log was cleared.",
    1,
    0,
    0,
)
ACCOUNT_CREATED = Rule(
    "WIN-ACCOUNT-001",
    "Windows account created",
    "medium",
    "T1136",
    "Create Account",
    "A Windows account was created. Confirm that the actor and target account are authorized.",
    1,
    0,
    0,
)
PRIVILEGED_GROUP = Rule(
    "WIN-GROUP-001",
    "Member added to a privileged Windows group",
    "high",
    "T1098.007",
    "Additional Local or Domain Groups",
    "A member was added to a group identified by a privileged Windows SID. Review the change.",
    1,
    0,
    0,
)
POWERSHELL = Rule(
    "WIN-PS-001",
    "Suspicious PowerShell command",
    "high",
    "T1059.001",
    "PowerShell",
    "A PowerShell process used an encoded command or combined download and expression execution. "
    "Administrative automation can also match; review the command and actor.",
    1,
    0,
    0,
)
RULES = (
    FAILED_LOGINS,
    SUCCESS_AFTER_FAILURES,
    LOG_CLEARING,
    ACCOUNT_CREATED,
    PRIVILEGED_GROUP,
    POWERSHELL,
)
# Windows 4625 often has a null SID even when 4624 resolves the same account's SID.
# Keep SIDs as evidence; correlate authentication by account/domain and source context.
GROUP_FIELDS = ("endpoint_id", "os", "source", "username", "user_domain", "source_ip")


def catalog() -> list[dict]:
    return [
        {
            **asdict(rule),
            "enabled": True,
            "group_by": list(GROUP_FIELDS)
            if rule in (FAILED_LOGINS, SUCCESS_AFTER_FAILURES)
            else ["event_uid"],
            "required_nonempty_fields": ["username", "source_ip"]
            if rule in (FAILED_LOGINS, SUCCESS_AFTER_FAILURES)
            else [],
            "event_requirements": (
                {
                    "os": "windows",
                    "source": "Security",
                    "event_type": "security_log_cleared",
                    "event_code": 1102,
                }
                if rule == LOG_CLEARING
                else {
                    "os": "windows",
                    "source": "Security",
                    "event_type": "account_created",
                    "event_code": 4720,
                }
                if rule == ACCOUNT_CREATED
                else {
                    "os": "windows",
                    "source": "Security",
                    "event_type": "group_membership_changed",
                    "event_code": [4728, 4732, 4756],
                    "group_sid": "privileged SID allowlist",
                }
                if rule == PRIVILEGED_GROUP
                else {
                    "os": "windows",
                    "source": "Security",
                    "event_type": "process_created",
                    "event_code": 4688,
                    "command_line": "encoded command or download plus expression execution",
                    "process_name": ["powershell.exe", "pwsh.exe"],
                }
                if rule == POWERSHELL
                else {"event_type": ["login_failure", "login_success"]}
            ),
        }
        for rule in RULES
    ]
