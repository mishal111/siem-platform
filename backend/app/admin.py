"""Local administration only. Passwords are accepted through a hidden prompt or stdin."""

import argparse
import getpass
import json
import sys

from fastapi import HTTPException
from pydantic import ValidationError
from pymongo.errors import PyMongoError

from app.config import Settings
from app.identity import UserCreate
from app.repository import EventRepository


def main():
    parser = argparse.ArgumentParser(description="Create a SIEM user with local server access")
    parser.add_argument("username")
    parser.add_argument("--role", choices=["admin", "analyst", "viewer"], default="admin")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read a password from stdin instead of a hidden prompt",
    )
    args = parser.parse_args()
    repository = None
    try:
        password = (
            sys.stdin.readline().rstrip("\r\n")
            if args.password_stdin
            else getpass.getpass("New password (12–128 characters): ")
        )
        if not args.password_stdin and password != getpass.getpass("Confirm password: "):
            print("Passwords do not match", file=sys.stderr)
            return 1
        data = UserCreate(username=args.username, password=password, role=args.role)
        repository = EventRepository(Settings())
        repository.initialize()
        user = repository.identity.create_user(data, "local-admin-cli")
        print(json.dumps({"created": user.username, "id": user.id, "role": user.role}))
        return 0
    except HTTPException as exc:
        print(exc.detail, file=sys.stderr)
        return 1
    except (ValidationError, PyMongoError, OSError):
        print("User creation failed; check input and database configuration", file=sys.stderr)
        return 1
    finally:
        if repository:
            repository.close()


if __name__ == "__main__":
    raise SystemExit(main())
