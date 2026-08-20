# Building Documentation

## CLA

To contribute to the Binary Ninja documentation, first sign the [contribution license agreement] and send it to [Vector 35].

## Prerequisites

The Python documentation tools are managed with [poetry]. Building every documentation surface requires:

- Python 3.10 or newer and [poetry].
- Doxygen 1.12 or newer available on `PATH` for the C++ API reference.
- A matching Binary Ninja installation whose `binaryninja` Python module can be imported. The API revision must match the installation's `api_REVISION.txt`.

`poetry install` installs [zensical], [sphinx], and [breathe]. It does not install Doxygen or Binary Ninja.

## Building

```bash
git clone https://github.com/Vector35/binaryninja-api/
cd binaryninja-api
poetry install
poetry run make -C docs all
```

The user documentation is written to `site/`, the Python API reference to
`docs/reference/python/build/html/`, and the C++ API reference to `docs/reference/cpp/html/`.
Use the `manual`, `python-reference`, `cpp-reference`, or `reference` targets to build only one documentation surface.

`scripts/zensical_build.py` runs `zensical build` and then writes the redirect stubs described by `[project.plugins.redirects.redirect_maps]` in `zensical.toml`.

## Changing
Changing documentation for the API itself is fairly straightforward. Use [doxygen style comment blocks](https://www.doxygen.nl/manual/docblocks.html) in C++ and C, and [restructured text blocks](https://sphinx-tutorial.readthedocs.io/step-1/) for Python source. The authored manual is located directly in `docs/`, while the Python and C++ API reference build projects live in `docs/reference/`.

!!! Tip "Tip"
    When updating user documentation, the `poetry run zensical serve` feature is particularly helpful for live previews.

[contribution license agreement]: https://binary.ninja/cla.pdf
[Vector 35]: https://vector35.com/
[poetry]: https://python-poetry.org/
[zensical]: https://zensical.org/
[breathe]: https://github.com/michaeljones/breathe
[sphinx]:  https://www.sphinx-doc.org/en/master/
[doxygen]: https://www.doxygen.nl
