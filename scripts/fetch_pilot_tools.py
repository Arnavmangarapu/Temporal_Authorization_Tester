"""Fetch pinned official Linux x86_64 binaries; verify archives before extraction."""

import hashlib
import json
import lzma
from pathlib import Path
import shutil
import urllib.request
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    destination = root / "artifacts" / "tools"
    destination.mkdir(parents=True, exist_ok=True)
    for item in json.loads((root / "integrations" / "tools.lock.json").read_text()):
        archive = destination / item["name"]
        if not archive.exists():
            partial = archive.with_name(archive.name + ".partial")
            try:
                with urllib.request.urlopen(item["url"], timeout=60) as response, partial.open("wb") as output:
                    shutil.copyfileobj(response, output)
                partial.replace(archive)
            finally:
                partial.unlink(missing_ok=True)
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != item["sha256"]:
            raise SystemExit(f"Checksum mismatch: {archive.name}; remove the archive and retry.")
        if item["key"] == "pocketbase":
            with zipfile.ZipFile(archive) as source:
                (destination / "pocketbase").write_bytes(source.read("pocketbase"))
            (destination / "pocketbase").chmod(0o700)
        elif item["key"] == "gitea":
            with lzma.open(archive, "rb") as source, (destination / "gitea").open("wb") as output:
                shutil.copyfileobj(source, output)
            (destination / "gitea").chmod(0o700)
        print(f"Verified {item['key']} {item['version']}")


if __name__ == "__main__":
    main()
