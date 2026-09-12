"""Create local development secrets without printing or overwriting them (Python 3.9+)."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = ROOT / ".env"
    template = (ROOT / ".env.example").read_text()
    template = template.replace(
        "replace-with-a-random-secret-at-least-32-characters", secrets.token_hex(32)
    ).replace(
        "replace-with-a-different-random-secret-at-least-32-characters", secrets.token_hex(32)
    )
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(".env already exists; left unchanged.")
        return
    with os.fdopen(descriptor, "w") as handle:
        handle.write(template)
    print("Created .env with separate random collector and analyst keys (mode 0600).")


if __name__ == "__main__":
    main()
