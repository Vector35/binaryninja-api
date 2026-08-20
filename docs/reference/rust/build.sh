#!/bin/bash
# Build Rust documentation for the Binary Ninja version imported by Python.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DOC_DIR="$SCRIPT_DIR/build/doc"

cd "$API_ROOT"

CARGO_TOML="rust/Cargo.toml"
CARGO_LOCK="Cargo.lock"
BACKUP_DIR=""

if ! git diff --quiet "$CARGO_TOML" "$CARGO_LOCK" 2>/dev/null; then
    echo "Error: Uncommitted changes detected in $CARGO_TOML or $CARGO_LOCK"
    echo "Please commit or stash your changes before running this script."
    exit 1
fi

echo "Getting Binary Ninja version..."
BN_VERSION=$(python3 -c "import binaryninja; v = binaryninja.core_version_info(); print(f'{v.major}.{v.minor}.{v.build}')")
echo "Binary Ninja version: $BN_VERSION"

cleanup() {
    echo "Restoring $CARGO_TOML and $CARGO_LOCK..."
    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
        cp "$BACKUP_DIR/Cargo.toml" "$CARGO_TOML"
        cp "$BACKUP_DIR/Cargo.lock" "$CARGO_LOCK"
        rm -rf "$BACKUP_DIR"
    fi
}
trap cleanup EXIT

BACKUP_DIR=$(mktemp -d)
cp "$CARGO_TOML" "$BACKUP_DIR/Cargo.toml"
cp "$CARGO_LOCK" "$BACKUP_DIR/Cargo.lock"

echo "Updating version to $BN_VERSION in $CARGO_TOML..."
python3 - "$CARGO_TOML" "$BN_VERSION" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
source, count = re.subn(
    r'^version = ".*"',
    f'version = "{sys.argv[2]}"',
    source,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f"expected one package version in {path}, found {count}")
path.write_text(source)
PY

echo "Cleaning $DOC_DIR directory..."
rm -rf "$DOC_DIR"

CUSTOM_CSS="$BACKUP_DIR/binaryninja-rustdoc.css"
cp docs/manual/brand.css "$CUSTOM_CSS"
printf '\n' >> "$CUSTOM_CSS"
cat docs/reference/rust/rustdoc-brand.css >> "$CUSTOM_CSS"

echo "Building documentation..."
RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }--extend-css $CUSTOM_CSS" \
    cargo doc --no-deps --target-dir "$SCRIPT_DIR/build" "$@"

echo "Copying brand assets..."
mkdir -p "$DOC_DIR/brand"
cp docs/manual/brand.css "$DOC_DIR/brand/"
cp docs/manual/fonts/OpenSans-Regular.ttf "$DOC_DIR/brand/"
cp docs/manual/fonts/OpenSans-Italic.ttf "$DOC_DIR/brand/"
cp docs/manual/fonts/OpenSans-Bold.ttf "$DOC_DIR/brand/"
cp docs/manual/fonts/OpenSans-BoldItalic.ttf "$DOC_DIR/brand/"
cp docs/manual/fonts/roboto-mono-v22-latin-regular.woff2 "$DOC_DIR/brand/"
cp docs/manual/fonts/roboto-mono-v22-latin-italic.woff2 "$DOC_DIR/brand/"
cp docs/manual/fonts/roboto-mono-v22-latin-700.woff2 "$DOC_DIR/brand/"
cp docs/manual/fonts/roboto-mono-v22-latin-700italic.woff2 "$DOC_DIR/brand/"
cp docs/manual/img/favicon.ico docs/manual/img/favicon-32x32.png "$DOC_DIR/brand/"
cp docs/manual/img/logo-vertical-light.svg docs/manual/img/logo-vertical-dark.svg "$DOC_DIR/brand/"
cp docs/manual/img/wordmark-white.svg "$DOC_DIR/brand/"

echo "Creating redirect index.html..."
cat > "$DOC_DIR/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="0; url=binaryninja/index.html">
    <link rel="icon" href="brand/favicon-32x32.png">
    <link rel="stylesheet" href="brand/brand.css">
    <title>Binary Ninja Rust Documentation</title>
    <style>
        html { height: 100%; }
        body {
            margin: 0;
            min-height: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
            background: var(--bn-night);
            color: var(--bn-white-smoke);
            font-family: "Open Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        img { width: min(420px, 80vw); }
        a { color: var(--bn-link-dark); }
    </style>
    <script>
        window.location.replace("binaryninja/index.html" + window.location.search + window.location.hash);
    </script>
</head>
<body>
    <img src="brand/wordmark-white.svg" alt="Binary Ninja">
    <p>Redirecting to the <a href="binaryninja/index.html">Binary Ninja Rust documentation</a>...</p>
</body>
</html>
EOF

echo "Documentation built successfully with redirect at docs/reference/rust/build/doc/index.html"
