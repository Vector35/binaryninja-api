# Headless WARP Processor

Provides headless support for generating WARP signatures using Binary Ninja.

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

Once it finishes you now will have a `warp_headless` binary in `target/release` for use.

### Usage

> Assuming you already have the `warp_headless` binary and a valid headless compatible Binary Ninja license.

To create a signature file simply pass the input as the first positional argument to `warp_headless`, as well as the output file using `-o` or `--output`:

- A regular binary
- An archive of binaries (`.a`, `.lib`, `.rlib`)
- A directory of binaries
- A BNDB
- A WARP file

Examples: 

- `./warp_headless -o ./results mylibrary.a`
  - Places a `mylibrary.warp` file in the `results` directory
- `./warp_headless -o ./signatures.warp ./all-libs/`
  - Provided files can be merged into a single output file
- `./warp_headless -o ./signatures.warp ./all-libs/ mylibrary.bndb`
  - Multiple inputs can be provided in any order

Once its finished you should see a `.warp` file in the provided output location, this can be moved into the corresponding signature folder (see the [user docs](https://docs.binary.ninja/dev/annotation.html?h=install+path#signature-library) for more info)

If you encounter malloc errors or instability try and adjust the number of parallel threads using `RAYON_NUM_THREADS` environment variable (ex. `RAYON_NUM_THREADS=1 ./warp_headless -o ./sigs.warp mylib.a`)