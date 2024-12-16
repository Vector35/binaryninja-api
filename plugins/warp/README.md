# warp_ninja

Provides integration with [WARP](https://github.com/Vector35/warp), more specifically the function identification and associated type information.

## Batch Processing

`sigem` (see code at `src/bin/sigem.rs`) allows for batch processing binaries for signature generation.

The only real "magic" here is the cross-linking of symbols in archives, this means that static libraries will have much finer constraint matching.

Duplicate functions will be removed to save space, any input will always produce a single output signature file, if you want separate signature files, invoke individually.

### Building

> Assuming you have the following:
> - A compatible Binary Ninja with headless usage (see [this documentation](https://docs.binary.ninja/dev/batch.html#batch-processing-and-other-automation-tips) for more information)
> - Clang
> - Rust (currently tested for 1.83.0)
> - Set `BINARYNINJADIR` env variable to your install directory (see [here](https://docs.binary.ninja/guide/#binary-path) for more details)

1. Clone this repository (`git clone https://github.com/Vector35/binaryninja-api/tree/dev`)
2. Navigate to this plugin (`cd plugins/warp`)
3. Build in release (`cargo build --release`)

If compilation fails because it could not link against binaryninjacore than you should double-check you set `BINARYNINJADIR` correctly.

Once it finishes you now will have a `sigem` binary in `target/release` for use.

### Usage

> Assuming you already have the `sigem` binary and a valid headless compatible Binary Ninja license.

To create a signature file simply pass the input as the first positional argument to `sigem`:

- A regular binary
- An archive of binaries (`.a`, `.lib`, `.rlib`)
- A directory of binaries
- A BNDB

Example: `./sigem mylibrary.a` or `./sigem ./all-libs/`

Once its finished you should see a `.sbin` file next to the input file, this can be moved into the corresponding signature folder (see the [user docs](https://docs.binary.ninja/dev/annotation.html?h=install+path#signature-library) for more info)

If you encounter malloc errors or instability try and adjust the number of parallel threads using `RAYON_NUM_THREADS` environment variable (ex. `RAYON_NUM_THREADS=1 ./sigem mylib.a`)