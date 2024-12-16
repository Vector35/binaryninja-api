# CPP Docs

We currently use `doxygen` for our C++ documentation generation.

Generating documentation with Doxygen couldn't be simpler. Just install it and run:

```
$ doxygen
```

From this directory. The output will be stored in `html/`

## Installing doxygen

The theme for our documentation works best with doxygen 1.12.0

### macOS (Homebrew)

```
$ wget https://raw.githubusercontent.com/Homebrew/homebrew-core/41828ee36b96e35b63b2a4c8cfc2df2c3728944a/Formula/doxygen.rb
$ shasum -a 256 doxygen.rb
4d1294c815cf0f76c55b14c5f47c25f523bd860a7cc9b077cce9589d84678396  doxygen.rb
$ brew install ./doxygen.rb
```
