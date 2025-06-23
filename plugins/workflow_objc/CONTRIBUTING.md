# Contribution Guidelines

Contributions in the form of issues and pull requests are welcome! See the
sections below if you are contributing code.

## Conventions

Refer to the [WebKit Style Guide](https://webkit.org/code-style-guidelines/)
when in doubt.

## Formatting

Let `clang-format` take care of it. The built-in WebKit style is used.

```sh
clang-format -i --style=WebKit <file>
```

- Split long lines when it improves readability. 80 columns is the preferred
maximum line length, but use some judgement and don't split lines just because a
semicolon exceeds the length limit, etc.

## Testing

If you are making changes to the core analysis library, run the test suite and
ensure that there are no unexpected changes to analysis behavior.
