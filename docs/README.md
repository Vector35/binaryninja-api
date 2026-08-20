# Documentation

- `manual/` contains the authored user and developer guide.
- `reference/python/` contains the Python API reference build.
- `reference/cpp/` contains the C++ API reference build.
- `reference/rust/` contains the Rust API reference build.

The Python documentation dependencies are managed with uv. From this directory:

```sh
uv sync
uv run make all
```

Use `manual`, `python-reference`, `cpp-reference`, or `rust-reference` to build one surface. See
[`manual/dev/documentation.md`](manual/dev/documentation.md) for prerequisites and output locations.
