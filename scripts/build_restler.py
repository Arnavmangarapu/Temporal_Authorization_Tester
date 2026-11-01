"""Fetch the pinned official source and build its unmodified Dockerfile."""

import io
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.request


COMMIT = "6d984deedbc54aad957fa3da0c7e9e5df23a2aee"
IMAGE = "temporal-auth-restler:6d984dee"


def main():
    root = Path(__file__).resolve().parents[1] / "artifacts" / "tools" / "restler-source"
    if root.exists() and not (root / ".temporal-source-commit").exists():
        raise SystemExit("Source directory already exists without the expected marker; use a fresh directory.")
    if not root.exists():
        root.mkdir(parents=True)
        with urllib.request.urlopen(f"https://api.github.com/repos/microsoft/restler-fuzzer/tarball/{COMMIT}", timeout=60) as response:
            data = response.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
            for member in source.getmembers():
                parts = PurePosixPath(member.name).parts[1:]
                if not parts:
                    continue
                member.name = str(PurePosixPath(*parts))
                source.extract(member, root, filter="data")
        (root / ".temporal-source-commit").write_text(COMMIT + "\n")
    if (root / ".temporal-source-commit").read_text().strip() != COMMIT:
        raise SystemExit("Unexpected RESTler source marker.")
    subprocess.run(["docker", "build", "--tag", IMAGE, str(root)], check=True)


if __name__ == "__main__":
    main()
