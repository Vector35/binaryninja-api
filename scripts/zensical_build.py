#!/usr/bin/env python3
"""Build the docs, then emit redirect stubs from docs/zensical.toml.

Extra arguments are forwarded to `zensical build`.
"""
import subprocess
import sys
from pathlib import Path

API_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = API_ROOT / "docs"
CONFIG = DOCS_ROOT / "zensical.toml"
SITE_DIR = DOCS_ROOT / "site"


def main() -> int:
    result = subprocess.run([sys.executable, "-m", "zensical", "build", "--strict",
                             "-f", str(CONFIG)] + sys.argv[1:])
    if result.returncode != 0:
        return result.returncode

    return subprocess.run([sys.executable, str(API_ROOT / "scripts" / "zensical_redirects.py"),
                           "--config", str(CONFIG), "--site-dir", str(SITE_DIR)]).returncode


if __name__ == "__main__":
    sys.exit(main())
