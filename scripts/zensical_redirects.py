#!/usr/bin/env python3
"""Emit redirect HTML stubs from a Zensical configuration."""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from posixpath import relpath as posix_relpath

# TODO: drop the tomli fallback once we require Python > 3.10 (tomllib is stdlib there).
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

REDIRECT_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <link rel="canonical" href="{target_html}">
    <script>location.replace({target_js} + location.search + location.hash)</script>
    <meta http-equiv="refresh" content="0; url={target_html}">
</head>
<body>
You're being redirected to a <a href="{target_html}">new destination</a>.
</body>
</html>
"""


def md_to_html(path: str) -> str:
    return path[:-3] + ".html" if path.endswith(".md") else path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Path to zensical.toml")
    parser.add_argument("--site-dir", required=True, type=Path, help="Built site directory")
    args = parser.parse_args()

    with args.config.open("rb") as fp:
        config = tomllib.load(fp)
    redirect_maps = (
        config.get("project", {}).get("plugins", {}).get("redirects", {}).get("redirect_maps", {})
    )
    if not redirect_maps:
        return 0

    written = 0
    for src, dst in redirect_maps.items():
        src_html = args.site_dir / md_to_html(src)
        dst_rel = posix_relpath(md_to_html(dst), start=str(Path(md_to_html(src)).parent))
        src_html.parent.mkdir(parents=True, exist_ok=True)
        src_html.write_text(
            REDIRECT_TEMPLATE.format(
                target_html=html.escape(dst_rel, quote=True),
                target_js=json.dumps(dst_rel),
            )
        )
        written += 1
    print(f"zensical_redirects: wrote {written} redirect stub(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
