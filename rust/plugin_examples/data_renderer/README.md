# Data Renderer Example

This example implements a simple data renderer for the Mach-O load command LC_UUID.
You can try the renderer by loading the `/bin/cat` binary from macOS.

We're implementing a functionality similar to the one described in the Python data renderer blog post: 
https://binary.ninja/2024/04/08/customizing-data-display.html.

## Building

```sh
# Build from the root directory (binaryninja-api)
cargo build --manifest-path rust/plugin_examples/data_renderer/Cargo.toml
# Link binary on macOS
ln -sf $PWD/target/debug/libexample_data_renderer.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins
```

## Result

The following Mach-O load command be will be transformed from

```c
struct uuid __macho_load_command_[10] = 
{
    enum load_command_type_t cmd = LC_UUID
    uint32_t cmdsize = 0x18
    uint8_t uuid[0x10] = 
    {
        [0x0] =  0x74
        [0x1] =  0xa0
        [0x2] =  0x3a
        [0x3] =  0xbd
        [0x4] =  0x1e
        [0x5] =  0x19
        [0x6] =  0x32
        [0x7] =  0x67
        [0x8] =  0x9a
        [0x9] =  0xdc
        [0xa] =  0x42
        [0xb] =  0x99
        [0xc] =  0x4e
        [0xd] =  0x26
        [0xe] =  0xa2
        [0xf] =  0xb7
    }
}
```

into the following representation

```c
struct uuid __macho_load_command_[10] = 
{
    enum load_command_type_t cmd = LC_UUID
    uint32_t cmdsize = 0x18
    uint8_t uuid[0x10] = UUID("74a03abd-1e19-3267-9adc-42994e26a2b7")
}
```

You can compare the shown UUID with the output of otool:
```sh
otool -arch all -l /bin/cat
```