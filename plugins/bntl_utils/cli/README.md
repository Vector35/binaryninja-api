# Headless BNTL Processor

Provides headless support for generating, inspecting, and validating Binary Ninja type libraries (BNTL).

### Building

> Assuming you have the following:
> - A compatible Binary Ninja with headless usage (see [this documentation](https://docs.binary.ninja/dev/batch.html#batch-processing-and-other-automation-tips) for more information)
> - Clang
> - Rust (currently tested for 1.91.1)
> - Set `BINARYNINJADIR` env variable to your installation directory (see [here](https://docs.binary.ninja/guide/#binary-path) for more details)
    >   - If this is not set, the -sys crate will try and locate using the default installation path and last run location.

1. Clone this repository (`git clone https://github.com/Vector35/binaryninja-api/tree/dev`)
2. Build in release (`cargo build --release`)

If compilation fails because it could not link against binaryninjacore than you should double-check you set `BINARYNINJADIR` correctly.

Once it finishes you now will have a `bntl_cli` binary in `target/release` for use.

### Usage

> Assuming you already have the `bntl_cli` binary and a valid headless compatible Binary Ninja license.

#### Create

Generate a new type library from local files or remote projects.

Examples:

- `./bntl_cli create sqlite3.dll "windows-x86_64" ./headers/ ./output/`
    - Places a single `sqlite.dll.bntl` file in the `output` directory, as headers have no dependency names associated they will be named `sqlite.dll`.
- `./bntl_cli create myproject "windows-x86_64" binaryninja://enterprise/https://enterprise.com/23ce5eaa-f532-4a93-80f2-a7d7f0aed040/ ./output/`
    - Downloads and processes all files in the project, placing potentially multiple `.bntl` files in the `output` directory.
- `./bntl_cli create sqlite3.dll "windows-x86_64" ./winmd/ ./output/`
  - `winmd` files are also supported as input, they will be processed together. You also probably want to provide some apiset schema files as well.
- `./bntl_cli create sqlite3.dll "windows-x86_64" ./headers/ ./output/ --include-directories ./system_headers/`
  - You can also specify additional include directories to search for referenced headers.

#### Dump

Export a type library back into a C header file for inspection.

Examples:

- `./bntl_cli dump sqlite3.dll.bntl ./output/sqlite.h`

#### Diff

Compare two type libraries and generate a .diff file.

Examples:

- `./bntl_cli diff sqlite3.dll.bntl sqlite3.dll.bntl ./output/sqlite.diff`

#### Validate

Check type libraries for common errors, ensuring all referenced types exist across specified platforms.

Examples:

- `./bntl_cli validate ./typelibs/ ./output/`
  - Pass in a directory containing `.bntl` files to validate, outputting a JSON file for each type library containing any errors.
