import json
import os
import selectors
import subprocess
import time

from collectors.common.errors import SourceError

# Deliberately excludes the full Unified Log stream and routine Gatekeeper chatter.
PREDICATE = (
    '(process == "authd" OR process == "sshd" OR process == "sshd-session" OR process == "sudo" '
    'OR ((process == "syspolicyd" OR process == "XProtectService" '
    'OR process == "XProtectRemediator") '
    'AND (eventMessage CONTAINS[c] "malware" OR eventMessage CONTAINS[c] "assessment denied" '
    'OR eventMessage CONTAINS[c] "execution denied" OR eventMessage CONTAINS[c] "quarantined")))'
)


class MacOSSource:
    def read(self, start, end, timeout=20, max_bytes=8 * 1024 * 1024):
        command = [
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--info",
            "--no-pager",
            "--start",
            "@{}".format(int(start)),
            "--end",
            "@{}".format(int(end)),
            "--timezone",
            "UTC",
            "--predicate",
            PREDICATE,
        ]
        output = bytearray()
        started = time.monotonic()
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        if time.monotonic() - started > timeout:
                            raise SourceError("Log query timed out; checkpoint retained")
                        if not selector.select(timeout=0.2):
                            continue
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > max_bytes:
                            raise SourceError("Log query exceeded byte limit; checkpoint retained")
                if process.wait(timeout=max(0.1, timeout - (time.monotonic() - started))):
                    raise SourceError("macOS log access failed; checkpoint retained")
            except subprocess.TimeoutExpired as exc:
                raise SourceError("Log query timed out; checkpoint retained") from exc
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        try:
            return [json.loads(line) for line in output.splitlines() if line.strip()]
        except (ValueError, UnicodeError) as exc:
            raise SourceError("Invalid NDJSON from macOS; checkpoint retained") from exc
