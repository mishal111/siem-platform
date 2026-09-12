"""Create local deployment secret files without printing credentials (Python 3.9+)."""

import json
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / ".local" / "deployment-secrets"
    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists():
        restore_config = directory / "mongo_restore_config"
        if not restore_config.exists() and (directory / "mongo_root_password").is_file():
            root_password = (directory / "mongo_root_password").read_text().strip()
            descriptor = os.open(restore_config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(
                    "uri: "
                    + json.dumps(
                        "mongodb://siem_root:{}@mongodb:27017/?authSource=admin".format(
                            root_password
                        )
                    )
                    + "\n"
                )
            restore_config.chmod(0o444)
            print("Added the restore-tool configuration using the existing database secret.")
        print("Deployment secrets directory already exists; nothing was overwritten.")
        return
    directory.mkdir(mode=0o700)
    password = secrets.token_hex(32)
    root_password = secrets.token_hex(32)
    uri = "mongodb://siem_app:{}@mongodb:27017/siem?authSource=siem".format(password)
    values = {
        "mongo_root_password": root_password,
        "mongo_app_password": password,
        "mongo_uri": uri,
        "mongo_tools_config": "uri: " + json.dumps(uri) + "\n",
        "mongo_restore_config": "uri: "
        + json.dumps("mongodb://siem_root:{}@mongodb:27017/?authSource=admin".format(root_password))
        + "\n",
    }
    for name, value in values.items():
        # Compose file secrets are bind mounts; non-root containers must be able to read them.
        # Host access is protected by the enclosing owner-only directory.
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value)
        (directory / name).chmod(0o444)
    print("Created deployment secrets in an owner-only directory; credentials were not printed.")


if __name__ == "__main__":
    main()
