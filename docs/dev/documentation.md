# Building Documentation

## CLA

To contribute to the Binary Ninja documentation, first sign the [contribution license agreement] and send it to [Vector 35].

## Prerequisites

- [sphinx]
- [breathe]
- [properdocs]
- [doxygen]
- The following plugins: `mkdocs-callouts mkdocs-click mkdocs-include-markdown-plugin mkdocs-material mkdocs-glightbox mkdocs-htmlproofer-plugin mkdocs-redirects`

## Building

    git clone https://github.com/Vector35/binaryninja-api/
    cd binaryninja-api
    properdocs build
    echo User documentation available in site/
    cd api-docs
    make html
    echo API documentation available in build/html

## Changing
Changing documentation for the API itself is fairly straightforward. Use [doxygen style comment blocks](https://www.doxygen.nl/manual/docblocks.html) in C++ and C, and [restructured text blocks](https://sphinx-tutorial.readthedocs.io/step-1/) for python for the source. The user documentation is located in the `api/docs/` folder and the API documentation is generated from the config in the `api/api-docs` folder.

???+ Info "Tip"
    When updating user documentation, the `properdocs serve` feature is particularly helpful.

[contribution license agreement]: https://binary.ninja/cla.pdf
[Vector 35]: https://vector35.com/
[properdocs]: https://properdocs.org/
[breathe]: https://github.com/michaeljones/breathe
[sphinx]:  https://www.sphinx-doc.org/en/master/
[doxygen]: https://www.doxygen.nl
