"""Build a collector-only ZIP from an explicit allowlist; never include local state or keys."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def main():
    output = ROOT / ".local" / "windows-collector.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [
        path
        for path in (ROOT / "collectors").rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and (
            path.suffix in (".py", ".md", ".toml")
            or path.name == "requirements.txt"
            or path == ROOT / "collectors/windows/.env.example"
        )
    ]
    files.append(ROOT / "docs/windows-collector.md")
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, str(path.relative_to(ROOT)))
    print(f"Created {output} ({len(files)} source/documentation files)")


if __name__ == "__main__":
    main()
