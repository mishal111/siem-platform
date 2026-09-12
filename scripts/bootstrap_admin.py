"""Create the first local admin and keep its generated password in an owner-only file."""

import argparse
import json
import os
import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment", action="store_true")
    args = parser.parse_args()
    destination = (
        ROOT
        / ".local"
        / ("deployment-admin-credentials.json" if args.deployment else "admin-credentials.json")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        print(
            "Credentials file already exists; no account or password was changed: "
            + str(destination)
        )
        return 0
    credentials = {
        "username": "admin",
        "password": secrets.token_urlsafe(24),
        "api_url": "https://localhost:8443" if args.deployment else "http://127.0.0.1:8000",
    }
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(credentials, stream, indent=2)
        stream.write("\n")
    command = ["docker", "compose"]
    if args.deployment:
        command += ["-f", "deploy/compose.yml"]
    command += [
        "exec",
        "-T",
        "backend",
        "python",
        "-m",
        "app.admin",
        credentials["username"],
        "--password-stdin",
    ]
    result = subprocess.run(
        command, cwd=ROOT, input=credentials["password"] + "\n", text=True, capture_output=True
    )
    if result.returncode:
        print(
            "Admin creation failed. The credential file is retained for recovery; "
            "the account may already exist. No password was printed."
        )
        return 1
    print("Created local admin. Read its credentials locally from: " + str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
