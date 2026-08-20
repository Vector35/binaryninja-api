#!/usr/bin/env python3
"""Validate the contents and metadata of Binary Ninja Python distributions."""

import argparse
from email.parser import BytesParser
from pathlib import Path
import tarfile

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
import zipfile


PROJECT_DIRECTORY = Path(__file__).resolve().parent.parent


def _project_version() -> str:
    with (PROJECT_DIRECTORY / "pyproject.toml").open("rb") as project_file:
        return tomllib.load(project_file)["project"]["version"]


def _one(directory: Path, pattern: str) -> Path:
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {pattern!r} in {directory}, found {len(matches)}")
    return matches[0]


def validate_wheel(wheel: Path, version: str) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        required = {
            "binaryninja/__init__.py",
            "binaryninja/_binaryninjacore.py",
            "binaryninja/_binaryninjacore_loader.py",
            "binaryninja/enums.py",
            "binaryninja/py.typed",
        }
        missing = required - names
        if missing:
            raise RuntimeError(f"wheel is missing required files: {sorted(missing)}")
        if any(name.startswith("examples/") for name in names):
            raise RuntimeError("standalone examples must not be installed by the wheel")
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        if metadata["Version"] != version:
            raise RuntimeError(f"wheel version {metadata['Version']} does not match project version {version}")


def validate_sdist(sdist: Path) -> None:
    with tarfile.open(sdist, "r:gz") as archive:
        names = archive.getnames()
        required_suffixes = {
            "/_build_backend.py",
            "/examples/manifest.toml",
            "/scripts/set_version.py",
            "/tests/test_examples.py",
            "/binaryninja/_binaryninjacore.py",
            "/binaryninja/enums.py",
        }
        for suffix in required_suffixes:
            if not any(name.endswith(suffix) for name in names):
                raise RuntimeError(f"source distribution is missing {suffix.lstrip('/')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default="dist", type=Path)
    args = parser.parse_args()
    version = _project_version()
    normalized_version = version.replace("-", "_")
    wheel = _one(args.directory, f"binaryninja_api-{normalized_version}-*.whl")
    sdist = _one(args.directory, f"binaryninja_api-{normalized_version}.tar.gz")
    validate_wheel(wheel, version)
    validate_sdist(sdist)
    print(f"validated {wheel.name} and {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
