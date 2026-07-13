#!/bin/bash
# Build Rust documentation and create redirect index.html
# Note that you should make sure "import binaryninja" will return the 
# correct version for the docs you want to upload.

set -e

CARGO_TOML="rust/Cargo.toml"
CARGO_LOCK="Cargo.lock"

# Check for uncommitted changes to Cargo.toml or Cargo.lock
if ! git diff --quiet "$CARGO_TOML" "$CARGO_LOCK" 2>/dev/null; then
    echo "Error: Uncommitted changes detected in $CARGO_TOML or $CARGO_LOCK"
    echo "Please commit or stash your changes before running this script."
    exit 1
fi

# Get Binary Ninja version from Python one-liner
echo "Getting Binary Ninja version..."
BN_VERSION=$(python3 -c "import binaryninja; v = binaryninja.core_version_info(); print(f'{v.major}.{v.minor}.{v.build}')")
echo "Binary Ninja version: $BN_VERSION"

# Function to restore Cargo.toml and Cargo.lock on exit
cleanup() {
    echo "Restoring $CARGO_TOML and $CARGO_LOCK..."
    git checkout "$CARGO_TOML" "$CARGO_LOCK" 2>/dev/null || true
}
trap cleanup EXIT

# Update version in Cargo.toml
echo "Updating version to $BN_VERSION in $CARGO_TOML..."
sed -i '' "s/^version = \".*\"/version = \"$BN_VERSION\"/" "$CARGO_TOML"

# Clean out old docs
echo "Cleaning target/doc directory..."
rm -rf target/doc

# Build the documentation (without dependencies by default)
echo "Building documentation..."
RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }--html-in-header $(pwd)/rust/doc-header.html" cargo doc --no-deps "$@"

# Copy brand assets referenced by doc-header.html and the crate doc attrs
echo "Copying brand assets..."
mkdir -p target/doc/brand
cp docs/brand.css rust/rustdoc-brand.css target/doc/brand/
cp docs/fonts/OpenSans-Regular.ttf target/doc/brand/
cp docs/fonts/OpenSans-Italic.ttf target/doc/brand/
cp docs/fonts/OpenSans-Bold.ttf target/doc/brand/
cp docs/fonts/OpenSans-BoldItalic.ttf target/doc/brand/
cp docs/fonts/roboto-mono-v22-latin-regular.woff2 target/doc/brand/
cp docs/fonts/roboto-mono-v22-latin-italic.woff2 target/doc/brand/
cp docs/fonts/roboto-mono-v22-latin-700.woff2 target/doc/brand/
cp docs/fonts/roboto-mono-v22-latin-700italic.woff2 target/doc/brand/
cp docs/img/favicon.ico docs/img/favicon-32x32.png target/doc/brand/
cp docs/img/logo-vertical-light.svg docs/img/logo-vertical-dark.svg target/doc/brand/
cp docs/img/wordmark-white.svg target/doc/brand/

# Create redirect index.html
echo "Creating redirect index.html..."
cat > target/doc/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="0; url=/binaryninja/index.html">
    <link rel="icon" href="/brand/favicon-32x32.png">
    <link rel="stylesheet" href="/brand/brand.css">
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
        window.location.href = "/binaryninja/index.html";
    </script>
</head>
<body>
    <img src="/brand/wordmark-white.svg" alt="Binary Ninja">
    <p>Redirecting to the <a href="/binaryninja/index.html">Binary Ninja Rust documentation</a>...</p>
</body>
</html>
EOF

echo "Documentation built successfully with redirect at target/doc/index.html"
