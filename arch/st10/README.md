# C166/ST10 Architecture Plugin for Binary Ninja
A Binary Ninja architecture plugin providing support for the C166/ST10 family of instructions.

## Overview
This architecture plugin provides support for the disassembling and lifting of Infineon C16x/STMicro ST10 instructions.

### Features
- Full disassembly support for the C16x/ST10 family of instructions
- Partial lifting to Binary Ninja's low level IL
- Support for the C166-classic, C166-vx, and C166-v2 calling conventions
- EXTended mode support
- Customizable DPP registers

## Installation
### Binary Download
The easiest way to use this plugin is to download and install a pre-compiled release binary.
1. Dowload the shared library corresponding to your OS/arch from the latest [GitHub Release](https://github.com/idaholab/bn-st10-arch/releases)
2. Copy the downloaded binary to your Binary Ninja plugin directory (e.g. `~/.binaryninja/plugins/`)
3. Start Binary Ninja

### Manual Build and Installation
#### Prerequisites
- Binary Ninja (minimum version: `5.1.8104`)
- CMake 3.15 or higher
- C++20 compatible compiler

#### Build from Source & Install
```bash
# Clone the binja API
git clone https://github.com/Vector35/binaryninja-api.git
cd binaryninja-api

# Set up CMake files
echo -e "\nadd_subdirectory(plugins)" >> CMakeLists.txt
echo -e "\nadd_subdirectory(bn-st10-arch)" >> plugins/CMakeLists.txt

# Download C166 architecture source
cd plugins
git clone https://github.com/idaholab/bn-st10-arch.git
cd ..

# Build
cmake -DCMAKE_BUILD_TYPE=release -DHEADLESS=yes .
cmake --build . --target all -j

# Install
cp out/bin/libc166.so ~/.binaryninja/plugins/libc166.so
```

## Usage
### Opening Files
1. Open Binary Ninja and select "Open with Options..."
2. Under "Load Options", set your entry point offset and image base
3. Choose your desired architecture + calling convention from the "Platform" dropdown menu
   - Options are: `c166tc` (Tasking classic), `c166tvx` (Tasking VX), and `c166v2` (Tasking v2)
   - Note: you can change your calling convention later if desired
4. Open the binary file and wait for auto-analysis to complete

> Note that you may need to manually define functions or customize your binary view for the file to load properly

### Changing your calling convention
At any time, you can change the calling convention as follows:
1. At the top menu bar, click `Plugins -> C166 Architecture -> Change Calling Convention`
2. Select desired convention from the drop-down menu and allow the BNDB to reanalyze

### Set DPP register values
The C166 architecture supports setting global values for the 4 DPP registers. By default, these values are 0.
You will need to identify the values your sample uses and set these appropriately. Usually, these are set somewhere 
near your entry point.

You can modify these values for the BNDB as a whole, or for just a range of addresses.
1. At the top menu bar, click `Plugins -> C166 Architecture -> Apply DPP`
2. Select your scope and DPP values, then allow the BNDB to reanalyze

### Set EXT values
You can set EXT values for a range of addresses by:
1. Highlight the instructions you want to modify
2. At the top menu bar, click `Plugins -> C166 Architecture -> Apply EXT[P/S/R]`
3. Select your scope and DPP values, then allow the BNDB to reanalyze

### Save & Restore instruction states
If you wish to save your current instruction state information (EXT/DPP states):
1. At the top menu bar, click `Plugins -> C166 Architecture -> Save C166 StateMap`

To restore a saved state:
1. At the top menu bar, click `Plugins -> C166 Architecture -> Restore C166 StateMap`

## Development
### Building for Development
To build with debug symbols, follow the instructions above to build from source but change the build type to debug:
```bash
cmake -DCMAKE_BUILD_TYPE=debug -DHEADLESS=yes .
```

### Contributing
Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a [Pull Request](https://github.com/idaholab/bn-st10-arch/pulls)

## Limitations
While every effort was made to ensure the accuracy of this plugin, you may still encounter bugs such as:
- Improperly disassembled instructions
- Missing instructions
- Typos

If you encounter a bug, please consider opening an issue or pull request!

Additionally, not all instructions have been lifted to LLIL. We welcome pull requests to help complete this task!

## Resources
- [Binary Ninja C++ API Documentation](https://api.binary.ninhttps://api.binary.ninja/cpp/index.html)
- [C166 Instruction Set Reference](https://www.keil.com/dd/docs/datashts/infineon/c166sv2um.pdf)

## License
Licensed under MIT.

See [LICENSE](LICENSE) file for details.

## Credits
Please see the [NOTICE](NOTICE.txt) file for details.

## Support
If you encounter issues with this repository, please create an [issue](https://github.com/idaholab/bn-st10-arch/issues).
