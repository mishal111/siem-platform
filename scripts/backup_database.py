"""Back up with API/worker paused; optionally verify an isolated restore."""

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", action="store_true")
    parser.add_argument("--verify-restore", action="store_true")
    args = parser.parse_args()
    prefix = ["docker", "compose"] + (["-f", "deploy/compose.yml"] if args.deployment else [])
    database = "siem"
    if not args.deployment:
        # Read the Compose-resolved non-secret database name from a small server command.
        result = subprocess.run(
            prefix
            + [
                "exec",
                "-T",
                "backend",
                "python",
                "-c",
                "from app.config import Settings; print(Settings().mongo_db)",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            print("Start the backend before taking a backup")
            return 1
        database = result.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", database):
        raise SystemExit("Invalid database name")

    def command(arguments, **options):
        result = subprocess.run(prefix + arguments, cwd=ROOT, stderr=subprocess.PIPE, **options)
        if result.returncode:
            raise RuntimeError("Database backup/restore command failed")
        return result

    running = command(
        ["ps", "--status", "running", "--services"], stdout=subprocess.PIPE, text=True
    ).stdout.splitlines()
    writers = [name for name in ("backend", "worker") if name in running]
    directory = ROOT / ".local" / "backups"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    label = "hardened" if args.deployment else "development"
    filename = (
        label
        + "-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
        + ".archive.gz"
    )
    destination = directory / filename
    restore_database = "siem_restorecheck_" + uuid4().hex
    auth = (
        "db.getSiblingDB('admin').auth('siem_root', "
        "require('fs').readFileSync('/run/secrets/mongo_root_password','utf8').trim());"
        if args.deployment
        else ""
    )
    restored = False
    try:
        if writers:
            command(["stop"] + writers, stdout=subprocess.DEVNULL)
        config = ["--config=/run/secrets/mongo_tools_config"] if args.deployment else []
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            command(
                ["exec", "-T", "mongodb", "mongodump", "--db=" + database, "--archive", "--gzip"]
                + config,
                stdout=stream,
            )
        if args.verify_restore:
            # Offline restore needs broader privileges than the application's readWrite role.
            auth_config = ["--config=/run/secrets/mongo_restore_config"] if args.deployment else []
            restored = True
            with destination.open("rb") as stream:
                command(
                    [
                        "exec",
                        "-T",
                        "mongodb",
                        "mongorestore",
                        "--archive",
                        "--gzip",
                        "--nsFrom=" + database + ".*",
                        "--nsTo=" + restore_database + ".*",
                    ]
                    + auth_config,
                    stdin=stream,
                    stdout=subprocess.DEVNULL,
                )
            # Exclude TTL-managed sessions/throttles, which can expire during restore.
            compare = (
                auth
                + "const source = db.getSiblingDB("
                + json.dumps(database)
                + "); const restored = db.getSiblingDB("
                + json.dumps(restore_database)
                + "); for (const name of source.getCollectionNames().filter("
                "n => !n.startsWith('system.') && !['sessions','login_throttles'].includes(n))) {"
                " if (source.getCollection(name).countDocuments({}) !== "
                "restored.getCollection(name).countDocuments({})) {"
                " throw new Error('Restore count mismatch'); } } print('Restore verified');"
            )
            command(
                ["exec", "-T", "mongodb", "mongosh", "--quiet", "--file", "/dev/stdin"],
                input=compare.encode(),
                stdout=subprocess.DEVNULL,
            )
        print(
            json.dumps(
                {
                    "backup": str(destination),
                    "bytes": destination.stat().st_size,
                    "isolated_restore_verified": args.verify_restore,
                }
            )
        )
        return 0
    except (OSError, RuntimeError):
        print("Backup or restore verification failed; inspect the local archive before using it")
        return 1
    finally:
        try:
            if restored:
                cleanup = (
                    auth + "db.getSiblingDB(" + json.dumps(restore_database) + ").dropDatabase();"
                )
                command(
                    ["exec", "-T", "mongodb", "mongosh", "--quiet", "--file", "/dev/stdin"],
                    input=cleanup.encode(),
                    stdout=subprocess.DEVNULL,
                )
        finally:
            if writers:
                command(["up", "-d", "--wait"] + writers, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
