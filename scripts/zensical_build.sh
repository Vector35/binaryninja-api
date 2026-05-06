#!/bin/bash
# Build the docs, then emit redirect stubs from zensical.toml.
# Extra arguments are forwarded to `zensical build`.
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
CONFIG="$DIR/zensical.toml"
SITE_DIR="$DIR/site"

zensical build -f "$CONFIG" "$@"
python3 "$DIR/scripts/zensical_redirects.py" --config "$CONFIG" --site-dir "$SITE_DIR"
