# Binary Ninja

## Third Party Open Source

Vector 35 is grateful for the following open source packages that are used in Binary Ninja directly or indirectly:

* Documentation tooling
    - [sphinx-rtd-theme] ([sphinx-rtd-theme license] - MIT)
    - [breathe] ([breathe license] - BSD)
    - [doxygen] ([doxygen license] - GPLv2)
    - [sphinx] ([sphinx license] - BSD and others)
    - [zensical] ([zensical license] - MIT)

The previous tools are used to generate our documentation but are not distributed with Binary Ninja.

* Fonts
    - [Bebas Neue] ([Bebas Neue license] - SIL Open Font License 1.1)
    - [DejaVu Sans Code] ([DejaVu Sans Code license] - multiple open-source licenses)
    - [Font Awesome] ([Font Awesome license] - SIL Open Font License 1.1 / MIT)
    - [Inter] ([Inter license] - SIL Open Font License 1.1)
    - [Noto Color Emoji] ([Noto Color Emoji license] - SIL Open Font License 1.1)
    - [Open Sans] ([Open Sans license] - Apache 2.0)
    - [Roboto Mono] ([Roboto Mono license] - Apache 2.0)
    - [Source Code Pro] ([Source Code Pro license] - SIL Open Font License 1.1)

* UI
    - [qt] ([qt license] - LGPLv3 / note, please see our [qt build instructions below](open-source.md#building-qt))
    - [libxcb] ([libxcb license] - MIT)
    - [rlcompleter] ([python license] - Python Software Foundation License 2)
    - [QCheckboxCombo] ([QCheckboxCombo License] - MIT)

* Core
    - [abseil-cpp] ([abseil-cpp license] - Apache 2.0)
    - [BinExport] ([binexport license] - Apache 2.0) - Google project, [Vector 35 fork]
    - [jsoncpp] ([jsoncpp license] - Public Domain / MIT)
    - [llvm] ([llvm license] - BSD-style)
    - [lzf] ([lzf license] - BSD)
    - [python] ([python license] - Python Software Foundation License 2 -- a Python 3.10 built without GPL components is currently shipped with Windows builds only, other platforms leverage existing Python installs)
    - [sqlite] ([sqlite license] - public domain)
    - [zlib] ([zlib license] - zlib license)
    - [rapidjson] ([rapidjson license] - MIT)
    - [jemalloc] ([jemalloc license] - 2-clause BSD)
    - [curl] ([curl license] - MIT)
    - [xxHash] ([xxHash License] - 2-clause BSD)
    - [botan] ([botan license] - 2-clause BSD)
    - [fmt] ([fmt license] - MIT)
    - [ConvertUTF] ([ConvertUTF license] - Unicode License) - UTF conversion routines from Unicode, Inc. (LLVM's maintained copy)
    - [dtl] ([dtl license] - BSD)
    - [JSON for Modern C++] ([JSON for Modern C++ license] - MIT)
    - [zstd] ([zstd license] - BSD)
    - [openssl] ([openssl license] - Apache 2.0)
    - [sentry-native] ([sentry-native license] - MIT)

* Other
    - [yasm] ([yasm license] - 2-clause BSD) used for assembling x86 and x64
    - [xed] ([xed license] - Apache License 2.0) used for disassembling x86, x64, and x16
    - [capstone] ([capstone license] - 3-clause BSD) used in the [PPC architecture module] as an example of how to wrap an external disassembler
    - [flatbuffer] ([flatbuffer license] - Apache License 2.0) used in the binary format for the function fingerprint libraries
    - [deprecation] ([deprecation license] - Apache License 2.0) used in the Python API for marking deprecated functions/properties/classes
    - [GraalVM CE] ([GraalVM CE license] - GPLv2 with the "Classpath" Exception) used in building the Ghidra DB FFI for the Ghidra plugin
    - [zstd-rs] ([zstd-rs license] - MIT) used by the IDB import plugin

## Rust Licenses

Due to its different document generation system, all our rust dependencies and their licenses are collected in:

* [Binary Ninja Core Rust Licenses](./rust-binaryninjacore.html)
* [Binary Ninja API Rust Licenses](./rust-binaryninja-api.html)
* [Tricore Rust Licenses](./rust-tricore.html)
* [C-SKY Rust Licenses](./rust-csky.html)
* [Ghidra Import Rust Licenses](./rust-ghidra-import.html)
* [Hexagon Rust Licenses](./rust-hexagon.html)
* [NDS32 Rust Licenses](./rust-nds32.html)

## First Party Open Source

* Several components of Binary Ninja developed by Vector 35 directly are released under open source licenses, noted as below:
    - [API / Documentation] ([api license] - MIT) APIs (Python, C, C++) and Documentation (User, API, etc)
    - [Rust API] ([rust api license] - Apache License 2.0)
    - LIB Files ([api license] - MIT) .lib files included with the native windows builds of Binary Ninja are released under the same MIT license as the API itself, distinct from the standard EULA
    - [Views] ([views license] - Apache License 2.0) Binary views included with the product
    - [Architectures] ([architectures license] - Apache License 2.0) Architecture support included with the product
    - [DWARF Import] - ([dwarf import license] - MIT)
    - [DWARF Export] - ([dwarf export license] - MIT)
    - [IDB Import] - ([idb import license] - MIT)
    - [SCC] - ([scc license] - MIT)
    - [Ghidra DB FFI] - ([Ghidra DB FFI license] - Apache License 2.0)

## Building Qt

Binary Ninja uses [Qt 6.11] under an LGPLv3 license which requires that we host the original sources used to build Qt for
our application along with instructions on how that source may be re-built and can replace the version of Qt shipped
with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 6 from Git] page.
2. Download the Qt 6.11.1 [tarball] from binary.ninja. The Qt code has a [patch] applied but is ABI compatible with the
   official Qt release.
3. Next, build Qt with the [qt-build] repository. Alternatively, build Qt using the aforementioned instructions.
4. On macOS, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.
5. Finally, replace the built libraries:
     - On macOS, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Network.dll`, and `Qt6Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`.
     - On Linux, replace the `libQt6Core.so.6`, `libQt6DBus.so.6`, `libQt6Gui.so.6`, `libQt6Network.so.6`, `libQt6Widgets.so.6`, `libQt6XcbQpa.so.6` files wherever Binary Ninja was extracted.

[Building Qt 6 from Git]: https://wiki.qt.io/Building_Qt_6_from_Git
[Qt 6.11]: https://www.qt.io/licensing/open-source-lgpl-obligations
[abseil-cpp]: https://github.com/abseil/abseil-cpp
[abseil-cpp license]: https://github.com/abseil/abseil-cpp/blob/master/LICENSE
[Bebas Neue]: https://github.com/dharmatype/Bebas-Neue
[Bebas Neue license]: ../fonts/BebasNeue-LICENSE.txt
[BinExport]: https://github.com/google/binexport
[binexport license]: https://github.com/google/binexport/blob/main/LICENSE
[Vector 35 fork]: https://github.com/Vector35/binexport
[capstone]: https://github.com/aquynh/capstone
[capstone license]: https://github.com/aquynh/capstone/blob/master/LICENSE.TXT
[breathe license]: https://github.com/michaeljones/breathe/blob/master/LICENSE
[sphinx-rtd-theme license]: https://github.com/Vector35/sphinx_rtd_theme/blob/master/LICENSE
[sphinx-rtd-theme]: https://github.com/Vector35/sphinx_rtd_theme
[breathe]: https://github.com/michaeljones/breathe
[DejaVu Sans Code license]: https://github.com/SSNikolaevich/DejaVuSansCode/blob/master/LICENSE
[DejaVu Sans Code]: https://github.com/SSNikolaevich/DejaVuSansCode
[doxygen license]: https://github.com/doxygen/doxygen/blob/master/LICENSE
[doxygen]: https://www.doxygen.nl
[flatbuffer]: https://github.com/google/flatbuffers
[flatbuffer license]: https://github.com/google/flatbuffers/blob/master/LICENSE
[Font Awesome]: https://github.com/FortAwesome/Font-Awesome/tree/v4.7.0
[Font Awesome license]: https://github.com/FortAwesome/Font-Awesome/blob/v4.7.0/README.md#license
[Inter]: https://github.com/rsms/inter
[Inter license]: https://github.com/rsms/inter/blob/master/LICENSE.txt
[fmt]: https://github.com/fmtlib/fmt/tree/11.2.0
[fmt license]: https://github.com/fmtlib/fmt/blob/11.2.0/LICENSE
[jsoncpp]: https://github.com/open-source-parsers/jsoncpp
[jsoncpp license]: https://github.com/open-source-parsers/jsoncpp/blob/master/LICENSE
[llvm]: http://llvm.org/releases/3.8.1/
[llvm license]: http://llvm.org/releases/3.8.1/LICENSE.TXT
[lzf license]: http://oldhome.schmorp.de/marc/liblzf.html
[lzf]: http://oldhome.schmorp.de/marc/liblzf.html
[Open Sans license]: ../fonts/OpenSans-LICENSE.txt
[Open Sans]: https://fonts.google.com/specimen/Open+Sans
[PPC architecture module]: https://github.com/Vector35/ppc-capstone
[python]: https://github.com/python/cpython
[python license]: https://github.com/python/cpython/blob/master/LICENSE
[qt license]: https://www.qt.io/licensing/open-source-lgpl-obligations
[qt]: https://www.qt.io/download/
[rapidjson]: http://rapidjson.org/
[rapidjson license]: https://github.com/Tencent/rapidjson/blob/master/license.txt
[rlcompleter]: https://github.com/python/cpython/blob/master/Lib/rlcompleter.py
[Roboto Mono]: https://fonts.google.com/specimen/Roboto+Mono
[Roboto Mono license]: ../fonts/RobotoMono-LICENSE.txt
[Source Code Pro license]: https://github.com/adobe-fonts/source-code-pro/blob/master/LICENSE.md
[Source Code Pro]: https://github.com/adobe-fonts/source-code-pro
[Noto Color Emoji license]: https://github.com/googlefonts/noto-emoji/blob/main/fonts/LICENSE
[Noto Color Emoji]: https://github.com/googlefonts/noto-emoji
[sphinx license]: https://github.com/sphinx-doc/sphinx/blob/master/LICENSE.rst
[zensical]: https://zensical.org/
[zensical license]: https://github.com/zensical/zensical/blob/main/LICENSE
[sphinx]: https://www.sphinx-doc.org/en/master/
[sqlite license]: https://www.sqlite.org/copyright.html
[sqlite]: https://www.sqlite.org/index.html
[tarball]: https://binary.ninja/qt6.11.1.tar.xz
[patch]: https://binary.ninja/qt6.11.1.patch
[qt-build]: https://github.com/Vector35/qt-build
[yasm license]: https://github.com/yasm/yasm/blob/master/BSD.txt
[yasm]: https://github.com/yasm/yasm
[xed]: http://www.github.com/intelxed/xed/
[xed license]: http://www.github.com/intelxed/xed/blob/master/LICENSE
[zlib license]: http://www.zlib.net/zlib_license.html
[zlib]: http://www.zlib.net/
[jemalloc]: https://github.com/jemalloc/jemalloc
[jemalloc license]: https://github.com/jemalloc/jemalloc/blob/master/COPYING
[libxcb]: https://gitlab.freedesktop.org/xorg/lib/libxcb
[libxcb license]: https://gitlab.freedesktop.org/xorg/lib/libxcb/-/blob/master/COPYING
[curl license]: https://github.com/curl/curl/blob/master/COPYING
[curl]: https://github.com/curl/curl
[QCheckboxCombo]: https://github.com/CuriousCrow/QCheckboxCombo
[QCheckboxCombo License]: https://github.com/CuriousCrow/QCheckboxCombo/blob/master/LICENSE
[xxHash]: https://github.com/Cyan4973/xxHash
[xxHash license]: https://github.com/Cyan4973/xxHash/blob/release/LICENSE
[botan]: https://github.com/randombit/botan
[botan license]: https://github.com/randombit/botan/blob/master/license.txt
[dtl]: https://github.com/cubicdaiya/dtl/
[dtl license]: https://github.com/cubicdaiya/dtl/blob/master/COPYING
[JSON for Modern C++]: https://github.com/nlohmann/json/
[JSON for Modern C++ license]: https://github.com/nlohmann/json/blob/develop/LICENSE.MIT
[zstd]: https://github.com/facebook/zstd/
[zstd license]: https://github.com/facebook/zstd/blob/dev/LICENSE
[ConvertUTF]: https://github.com/llvm/llvm-project/blob/main/llvm/lib/Support/ConvertUTF.cpp
[ConvertUTF license]: https://www.unicode.org/license.txt
[zstd-rs]: https://github.com/gyscos/zstd-rs
[zstd-rs license]: https://github.com/gyscos/zstd-rs/blob/main/LICENSE
[deprecation]: https://github.com/briancurtin/deprecation
[deprecation license]: https://github.com/briancurtin/deprecation/blob/master/LICENSE
[API / Documentation]: https://github.com/vector35/binaryninja-api
[api license]: https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt
[Rust API]: https://github.com/Vector35/binaryninja-api/tree/dev/rust
[rust api license]: https://github.com/Vector35/binaryninja-api/blob/dev/rust/LICENSE
[Views]: https://github.com/Vector35/?q=view-&type=all&language=&sort=
[views license]: https://github.com/Vector35/view-pe/blob/main/LICENSE
[Architectures]: https://github.com/Vector35/?q=arch-&type=all&language=&sort=
[architectures license]: https://github.com/Vector35/arch-armv7/blob/master/LICENSE
[DWARF Import]: https://github.com/Vector35/binaryninja-api/tree/dev/plugins/dwarf/dwarf_import
[dwarf import license]: https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt
[DWARF Export]: https://github.com/Vector35/binaryninja-api/tree/dev/plugins/dwarf/dwarf_export
[dwarf export license]: https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt
[IDB Import]: https://github.com/Vector35/binaryninja-api/tree/dev/plugins/idb_import
[idb import license]: https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt
[SCC]: https://github.com/Vector35/scc/
[scc license]: https://github.com/Vector35/scc/blob/master/LICENSE.txt
[openssl]: https://github.com/openssl/openssl
[openssl license]: https://github.com/openssl/openssl/blob/master/LICENSE.txt
[Ghidra DB FFI]: https://github.com/Vector35/ghidra-db-ffi
[Ghidra DB FFI license]: https://github.com/Vector35/ghidra-db-ffi/blob/main/LICENSE
[GraalVM CE]: https://github.com/oracle/graal/
[GraalVM CE license]: https://github.com/oracle/graal/blob/master/LICENSE
[sentry-native]: https://github.com/getsentry/sentry-native
[sentry-native license]: https://github.com/getsentry/sentry-native/blob/master/LICENSE
