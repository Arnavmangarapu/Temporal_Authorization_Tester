"""Build the historical Dolibarr bug/fix pair from checksum-verified archives."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory
import urllib.request


def digest(path):
    with path.open("rb") as source: return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    templates = root / "integrations/dolibarr"
    lock = json.loads((templates / "source.lock.json").read_text())
    tools = root / "artifacts/tools/dolibarr-26066"
    tools.mkdir(parents=True, exist_ok=True)
    # Re-extract each verified archive into a temporary directory. A modified
    # development extraction must not silently become a published fixture image.
    with TemporaryDirectory(prefix="temporal-dolibarr-build-") as temporary:
        working = Path(temporary)
        sources = {}
        for variant, data in lock["revisions"].items():
            archive = tools / (data["commit"] + ".tar.gz")
            if not archive.exists():
                partial = archive.with_suffix(".partial")
                try:
                    with urllib.request.urlopen("https://codeload.github.com/Dolibarr/dolibarr/tar.gz/" + data["commit"], timeout=60) as response, partial.open("wb") as output:
                        shutil.copyfileobj(response, output)
                    partial.replace(archive)
                finally: partial.unlink(missing_ok=True)
            if digest(archive) != data["archive_sha256"]: raise SystemExit("Unexpected source archive digest: " + variant)
            with tarfile.open(archive) as source: source.extractall(working, filter="data")
            sources[variant] = working / ("dolibarr-" + data["commit"])
            if digest(sources[variant] / lock["changed_file"]) != data["handler_sha256"]:
                raise SystemExit("Unexpected upstream handler: " + variant)
        def inventory(directory):
            return {str(p.relative_to(directory)): digest(p) for p in directory.rglob("*") if p.is_file()}
        before, after = (inventory(sources[v]) for v in ("buggy", "fixed"))
        changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
        if changed != [lock["changed_file"]]: raise SystemExit("Source pair differs outside the declared fix")
        context = working / "context"; context.mkdir()
        shutil.copytree(sources["buggy"] / "htdocs", context / "htdocs")
        shutil.copyfile(sources["fixed"] / lock["changed_file"], context / "api_multicurrencies.fixed.php")
        for name in ("Dockerfile", "conf.php", "bootstrap.php"):
            shutil.copyfile(templates / name, context / name)
        manifest = {"source_lock": lock, "source_difference_verified": changed, "images": {},
                    "fixture_sha256": {str(p.relative_to(root)): digest(p) for p in templates.iterdir() if p.is_file()}}
        for variant in ("buggy", "fixed"):
            image = "temporal-auth-dolibarr-26066:" + variant
            with (tools / ("build-" + variant + ".log")).open("wb") as log:
                subprocess.run(["docker", "build", "--target", variant, "-t", image, str(context)], stdout=log, stderr=log, check=True)
            info = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
            actual = subprocess.check_output(["docker", "run", "--rm", "--entrypoint", "sha256sum", image,
                "/var/www/html/multicurrency/class/api_multicurrencies.class.php"], text=True).split()[0]
            if actual != lock["revisions"][variant]["handler_sha256"]: raise SystemExit("Built handler mismatch")
            manifest["images"][variant] = {"id": info["Id"], "handler_sha256": actual}
            print(variant, info["Id"], flush=True)
        (tools / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__": main()
