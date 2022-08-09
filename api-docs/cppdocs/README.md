# CPP Docs

We are currently experimenting with two different document generation systems. You'll see artifacts for both of them in this directory. Currently, the documentation available [online](https://api.binary.ninja/cpp) uses [Doxygen](https://www.doxygen.nl/index.html) but we plan eventually to move to [Breathe](https://breathe.readthedocs.io/en/latest/) / [Sphinx](https://www.sphinx-doc.org/en/master/).

## Doxygen

Generating documentation with Doxygen couldn't be simpler. Just install it and run:

```
$ doxygen
```

From this directory. The output will be stored in `html/`


## Breathe/Sphinx

The requirements are already described in our [documentation](https://docs.binary.ninja/dev/documentation.html). Instead, however simply navigate to this directory and use:

```
sphinx-build -b html . html/
```

Note that Sphinx will take significantly longer due to some performance issues with breathe and doxygen generated XML. This is the main reason this is not our primary workflow.
