# CPP Docs

We currently use `doxygen` for our C++ documentation generation.

> Note: Using anything newer than doxygen 1.9.4 will cause minor issues with the website whenever the selected theme conflicts with the OS/browser light/dark mode selection.

Generating documentation with Doxygen couldn't be simpler. Just install it and run:

```
$ doxygen
```

From this directory. The output will be stored in `html/`

## Installing doxygen

The theme for our documentation works best with doxygen 1.9.0 - 1.9.4

### macOS (Homebrew)

```
wget https://raw.githubusercontent.com/Homebrew/homebrew-core/41828ee36b96e35b63b2a4c8cfc2df2c3728944a/Formula/doxygen.rb`
brew install ./doxygen.rb
```
