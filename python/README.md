# Binary Ninja Python API

This directory is the uv project for the Binary Ninja Python bindings. It packages the pure-Python `binaryninja`
module, but does not redistribute Binary Ninja Core or a product license. The installed package must be paired with a
compatible Binary Ninja installation.

## Develop and build

The low-level API and enum modules are generated from `binaryninjacore.h`. Generated copies are tracked so a clean
checkout can produce a complete source distribution and wheel, while the build backend rejects a package build if
either generated file is missing. Refresh them after changing the core API:

```sh
cmake --build cmake-build-default --target generator_copy
cd api/python
uv sync --locked
uv build --no-sources
```

The distributions are written to `dist/`. The wheel is platform-independent Python code, but it requires a matching
native core at runtime. `uv sync` creates an editable development installation and uses this project's lockfile; it is
independent of the documentation and parent build/test Python projects.

For release builds, set the distribution version to the matching Binary Ninja core version before building:

```sh
uv run python scripts/set_version.py 6.0.10507
```

The script delegates to `uv version`, updating both `pyproject.toml` and `uv.lock`. The package exposes the installed
distribution version as `binaryninja.__distribution_version__`; `binaryninja.__version__` remains the loaded core's
version. Generated bindings also verify that their expected core ABI is within the loaded core's supported ABI range.

Before publishing, run the validation commands below and publish only to the package index selected by the release
pipeline, for example `uv publish --publish-url <index>`. Repository configuration intentionally does not contain an
upload URL or credential, preventing an ordinary local build from selecting a publication destination implicitly.

## Locate Binary Ninja Core

When bundled with Binary Ninja, the package finds the adjacent native core automatically. For an independent wheel or
editable installation, set `BN_INSTALL_DIR` to the application or installation directory:

```sh
BN_INSTALL_DIR="/Applications/Binary Ninja.app" \
  uv run python -c "import binaryninja; print(binaryninja.__version__)"
```

For unusual layouts, `BINARYNINJACORE_PATH` may name the native core library directly. For deterministic headless runs,
especially in CI, isolate the process from user state and repository plugins:

```sh
BN_INSTALL_DIR="/Applications/Binary Ninja.app" \
BN_DISABLE_USER_PLUGINS=1 \
BN_DISABLE_USER_SETTINGS=1 \
BN_DISABLE_REPOSITORY_PLUGINS=1 \
  uv run python examples/cli_dis.py x86 55
```

Headless analysis requires a license with headless API support.

## Examples

The [`examples`](examples) directory contains three kinds of example:

- **Standalone:** command-line programs such as `bin_info.py`, `cli_dis.py`, `cli_lift.py`, `bindiff.py`,
  `feature_map.py`, `print_syscalls.py`, and `raw_binary_base_detection.py`.
- **Core plugins:** architecture hooks, binary views, render layers, workflow extensions, notification callbacks, and
  other examples that do not directly depend on the UI module.
- **UI plugins:** examples using `binaryninjaui`, including panes, sidebars, graph views, keybindings, tooltips, and the
  triage view. UI plugins must run inside Binary Ninja and must import `binaryninjaui` before `PySide6`.

The machine-readable [`examples/manifest.toml`](examples/manifest.toml) classifies every example and records optional
dependencies. Tests ensure newly added examples are classified and UI examples preserve the required import order.

Install the lightweight example dependencies with:

```sh
uv sync --group examples
```

This installs Pillow for `feature_map.py`. The angr example is intentionally kept in a separate, heavier group with a
narrower Python range:

```sh
uv sync --group examples-angr
```

UI dependencies are supplied by Binary Ninja. Do not independently install `binaryninjaui` or a different PySide6
build into the product runtime.

To load a plugin example, copy or symlink it into the Binary Ninja user plugin directory and restart Binary Ninja:

- macOS: `~/Library/Application Support/Binary Ninja/plugins`
- Windows: `%APPDATA%\\Binary Ninja\\plugins`
- Linux: `~/.binaryninja/plugins`

The examples are included in the source distribution for discoverability and continue to be bundled with the product,
but they are not installed into site-packages by the wheel.

## Validation

Run the uv-native checks from this directory:

```sh
uv lock --check
uv run ruff check _build_backend.py binaryninja/_binaryninjacore_loader.py examples scripts tests ../scripts/install_api.py
uv run pytest
uv build --no-sources
uv run python scripts/validate_dist.py dist
```

When `BN_INSTALL_DIR` is set, the test suite additionally runs representative headless examples against the installed
core. Loader tests do not require a Binary Ninja installation and exercise environment precedence, product layouts,
unsupported platforms, missing libraries, and load failures.

## Installed-product compatibility

The product's `scripts/install_api.py` helper now prefers installing a bundled or explicitly supplied wheel. Its `.pth`
mode remains available for older product layouts and UI bindings, but is reported as a compatibility installation so it
cannot be confused with the `binaryninja-api` distribution. The script detects the headless API and UI module
independently.
