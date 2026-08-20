#!/usr/bin/env python3
"""Set or validate the Python distribution version against the API release tag."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


PROJECT_DIRECTORY = Path(__file__).resolve().parent.parent
VERSION_PATTERN = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")


def project_version() -> str:
    with (PROJECT_DIRECTORY / "pyproject.toml").open("rb") as project_file:
        return tomllib.load(project_file)["project"]["version"]


def release_tag_version() -> str:
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=PROJECT_DIRECTORY,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    match = VERSION_PATTERN.search(result.stdout.strip())
    if match is None:
        raise RuntimeError(f"the nearest API tag does not contain a core version: {result.stdout.strip()!r}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="PEP 440 distribution version to set")
    parser.add_argument("--check", action="store_true", help="compare the project version with the nearest API tag")
    args = parser.parse_args()

    if args.check:
        expected = release_tag_version()
        actual = project_version()
        if actual != expected:
            print(f"distribution version {actual} does not match release tag version {expected}", file=sys.stderr)
            return 1
        print(f"distribution version {actual} matches the API release tag")
        return 0

    if args.version is None:
        parser.error("provide a version or use --check")
    if VERSION_PATTERN.fullmatch(args.version) is None:
        parser.error("version must use Binary Ninja's major.minor.build form")

    uv = os.environ.get("UV") or shutil.which("uv")
    if uv is None:
        parser.error("uv was not found; put it on PATH or set UV to the executable path")
    subprocess.run([uv, "version", args.version], cwd=PROJECT_DIRECTORY, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
