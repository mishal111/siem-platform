import base64
import re
from pathlib import PureWindowsPath


def privileged_group(sid: str | None) -> bool:
    # Built-in groups with substantial administration rights; no localized-name guessing.
    if sid in {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}:
        return True
    return bool(sid and re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-(512|518|519)", sid))


def suspicious_powershell(process: str | None, command: str | None) -> bool:
    if PureWindowsPath(process or "").name.lower() not in {
        "powershell.exe",
        "pwsh.exe",
        "powershell",
        "pwsh",
    }:
        return False
    if not command:
        return False
    tokens = re.findall(r""""[^"]*"|'[^']*'|\S+""", command)
    for index, token in enumerate(tokens):
        if token.lower() in {"-command", "-c", "-file", "-f"}:
            break
        if token.lower() in {"-encodedcommand", "-enc", "-ec"} and index + 1 < len(tokens):
            encoded = tokens[index + 1].strip("\"'")
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-16-le")
            except (ValueError, UnicodeError):
                continue
            if decoded.strip():
                return True
    script = re.search(r"(?is)(?:^|\s)-(?:command|c)\s+(.+)$", command)
    script = script[1].strip() if script else command
    if len(script) > 1 and script[0] == script[-1] and script[0] in "\"'":
        script = script[1:-1]
    # Ignore literal strings and comments: printing documentation is not execution.
    code = re.sub(r"""(?s)'(?:''|[^'])*'|"(?:`.|[^"`])*"|\#[^\r\n]*""", " ", script)
    execute = re.search(r"(?i)(?<![\w$-])(?:iex|invoke-expression)(?=\s|\()", code)
    download = re.search(
        r"(?i)\.(?:DownloadString|DownloadFile)\s*\(|\b(?:Invoke-WebRequest|iwr)\b", code
    )
    return bool(execute and download)


def matching_rule(event, account_rule, group_rule, powershell_rule):
    if event["os"] != "windows" or event["source"] != "Security":
        return None
    kind, code = event["event_type"], event.get("event_code")
    if kind == "account_created" and code == 4720:
        return account_rule
    if (
        kind == "group_membership_changed"
        and code in (4728, 4732, 4756)
        and privileged_group(event.get("group_sid"))
    ):
        return group_rule
    if (
        kind == "process_created"
        and code == 4688
        and suspicious_powershell(event.get("process_name"), event.get("command_line"))
    ):
        return powershell_rule
    return None
