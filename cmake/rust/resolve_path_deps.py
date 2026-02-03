"""Resolve path dependencies from a Cargo.toml for CMake rebuild tracking.

Uses ``cargo metadata`` to find all local path dependencies for a crate.
Outputs one absolute directory path per line on stdout, suitable for
consumption by CMake's execute_process().

Usage:
    python3 resolve_path_deps.py \
        --manifest-path <path/to/Cargo.toml> \
        --cargo <cargo command tokens ...>
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Resolve path dependencies via cargo metadata"
    )
    parser.add_argument(
        "--manifest-path", required=True, help="Path to crate Cargo.toml"
    )
    parser.add_argument(
        "--cargo", nargs="+", default=["cargo"], help="Cargo command tokens"
    )
    args = parser.parse_args()

    manifest = str(Path(args.manifest_path).resolve())

    result = subprocess.run(
        [*args.cargo, "metadata", "--no-deps", "--format-version", "1",
         "--manifest-path", manifest],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)

    metadata = json.loads(result.stdout)

    for pkg in metadata["packages"]:
        if pkg["manifest_path"] == manifest:
            for dep in pkg["dependencies"]:
                if dep.get("path"):
                    print(dep["path"])
            break


if __name__ == "__main__":
    main()
