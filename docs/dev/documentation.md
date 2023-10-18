# Building Documentation

## CLA

To contribute to the Binary Ninja documentation, first sign the [contribution license agreement] and send it to [Vector 35].

## Prerequisites

- [sphinx]
- [breathe]
- [mkdocs]
- [doxygen]


## Building

    git clone https://github.com/Vector35/binaryninja-api/
    cd binaryninja-api
    cd api
    mkdocs build
    echo User documentation available in site/
    cd api-docs
    make html
    echo API documentation available in build/html

## Changing
Changing documentation for the API itself is fairly straight forward. Use [doxygen style comment blocks](https://www.stack.nl/~dimitri/doxygen/manual/docblocks.html) in C++ and C, and [restructured text blocks](http://thomas-cokelaer.info/tutorials/sphinx/docstring_python.html) for python for the source. The user documentation is located in the `api/docs/` folder and the API documentation is generated from the config in the `api/api-docs` folder.

???+ Warning "Tip"
    When updating user documentation, the `mkdocs serve` feature is particularly helpful.

[contribution license agreement]: https://binary.ninja/cla.pdf
[Vector 35]: https://vector35.com/
[mkdocs]: http://www.mkdocs.org/
[breathe]: https://github.com/michaeljones/breathe
[sphinx]: http://www.sphinx-doc.org/en/stable/index.html
[doxygen]: http://www.stack.nl/~dimitri/doxygen/
[doxblocks]: doxygen
