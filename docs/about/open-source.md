# Binary Ninja

## Third Party Open Source

Vector 35 is grateful for the following open source packages that are used in Binary Ninja directly or indirectly:

* Documentation
    - [breathe-rtd-theme] ([breathe-rtd-theme license] - MIT)
    - [breathe] ([breathe license] - BSD)
    - [doxygen] ([doxygen license] - GPLv2)
    - [mkdocs-material] ([mkdocs-material License] - BSD)
    - [mkdocs] ([mkdocs license] - BSD)
    - [sphinx] ([sphinx license] - BSD and others)

The previous tools are used in the generation of our documentation, but are not distributed themselves and are merely listed here in acknowledgement for the value they provide.

* UI
    - [dejavusanscode] ([dejavusanscode license] - multiple open licenses)
    - [opensans] ([opensans license] - Apache 2.0)
    - [qt] ([qt license] - LGPLv3 / note, please see our [qt build instructions below](open-source.md#building-qt))
    - [libxcb] ([libxcb license] - MIT)
    - [sourcecodepro] ([sourcecodepro license] - SIL open font license)
    - [rlcompleter] ([python license] - Python Software Foundation License 2)
    - [QCheckboxCombo] ([QCheckboxCombo License] - MIT)
    - [NotoColorEmoji] ([NotoColorEmoji License] - SIL open font license)

* Core
    - [abseil-cpp] ([abseil-cpp license] - Apache 2.0)
    - [pulldown-cmark] ([pulldown-cmark license] - MIT)
    - [jsoncpp] ([jsoncpp] - Public Domain / MIT)
    - [llvm] ([llvm license] - BSD-style)
    - [lzf] ([lzf license] - BSD)
    - [python] ([python license] - Python Software Foundation License 2 -- a Python 3.10 built without GPL components is currently shipped with Windows builds only, other platforms leverage existing Python installs)
    - [sqlite] ([sqlite license] - public domain)
    - [zlib] ([zlib license] - zlib license)
    - [rapidjson] ([rapidjson license] - MIT)
    - [jemalloc] ([jemalloc license] - 2-clause BSD)
    - [Rust] ([Rust license] - MIT)
    - [curl-rust] ([curl-rust license] - MIT)
    - [curl] ([curl license] - MIT)
    - [nom] ([nom license] - MIT)
    - [xxHash] ([xxHash License] - 2-clause BSD)
    - [pdb (Rust crate)] ([pdb license] - Apache 2.0 / MIT)
    - [botan] ([botan license] - 2-clause BSD)
    - [num-bigint] ([num-bigint license] - Apache 2.0 / MIT)
    - [num-integer] ([num-integer license] - Apache 2.0 / MIT)
    - [num-traits] ([num-traits license] - Apache 2.0 / MIT)

* Other
    - [yasm] ([yasm license] - 2-clause BSD) used for assembling x86 and x64
    - [xed] ([xed license] - Apache License 2.0) used for disassembling x86, x64, and x16
    - [capstone] ([capstone license] - 3-clause BSD) used in the [PPC architecture module] as an example of how to wrap an external disassembler
    - [flatbuffer] ([flatbuffer license] - Apache License 2.0) used in the binary format for the function fingerprint libraries
    - [deprecation] ([deprecation license] - Apache License 2.0) used in the Python API for marking deprecated functions/properties/classes

## First Party Open Source

* Several components of Binary Ninja developed by Vector 35 directly are released under open source licenses, noted as below:
    - [API / Documentation] ([api license] - MIT) All APIs (Python, Rust, C, C++) and Documentation (User, API, etc)</li>
    - LIB Files ([api license] - MIT) .lib files included with the native windows builds of Binary Ninja are released under the same MIT license as the API itself, distinct from the standard EULA
    - [Views] ([views license] - Apache License 2.0) Binary views included with the product 
    - [Architectures] ([architectures license] - Apache License 2.0) Architecture support included with the product

## Building Qt

Binary Ninja uses [Qt 6.4] under an LGPLv3 license which requires that we host the original sources used to build Qt for our application along with instructions on how that source may be re-built and can replace the version of Qt shipped with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 6 from Git] page.
2. Download the Qt 6.4.3 [tarball] from binary.ninja. The Qt code has a [patch] applied but is ABI compatible with the official Qt release.
3. Next, build Qt with the [qt-build] repository. Alternatively, build Qt using the aforementioned instructions.
4. On macOS, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.
5. Finally, replace the built libraries:
     - On macOS, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Network.dll`, and `Qt6Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`.
     - On Linux, replace the `libQt6Core.so.6`, `libQt6DBus.so.6`, `libQt6Gui.so.6`, `libQt6Network.so.6`, `libQt6Widgets.so.6`, `libQt6XcbQpa.so.6` files wherever Binary Ninja was extracted.

[Building Qt 6 from Git]: https://wiki.qt.io/Building_Qt_6_from_Git
[Qt 6.4]: https://www.qt.io/qt-licensing-terms/
[abseil-cpp]: https://github.com/abseil/abseil-cpp
[abseil-cpp license]: https://github.com/abseil/abseil-cpp/blob/master/LICENSE
[capstone]: https://github.com/aquynh/capstone
[capstone license]: https://github.com/aquynh/capstone/blob/master/LICENSE.TXT
[breathe license]: https://github.com/michaeljones/breathe/blob/master/LICENSE
[breathe-rtd-theme license]: https://github.com/snide/sphinx_rtd_theme/blob/master/LICENSE
[breathe-rtd-theme]: https://github.com/snide/sphinx_rtd_theme/
[breathe]: https://github.com/michaeljones/breathe
[dejavusanscode license]: https://github.com/SSNikolaevich/DejaVuSansCode/blob/master/LICENSE
[dejavusanscode]: https://github.com/SSNikolaevich/DejaVuSansCode
[pulldown-cmark license]: https://github.com/raphlinus/pulldown-cmark/blob/master/LICENSE
[pulldown-cmark]: https://github.com/raphlinus/pulldown-cmark
[doxygen license]: https://github.com/doxygen/doxygen/blob/master/LICENSE
[doxygen]: http://www.stack.nl/~dimitri/doxygen/
[flatbuffer]: https://github.com/google/flatbuffers
[flatbuffer license]: https://github.com/google/flatbuffers/blob/master/LICENSE
[jsoncpp]: https://github.com/open-source-parsers/jsoncpp
[jsoncpp license]: https://github.com/open-source-parsers/jsoncpp/blob/master/LICENSE
[llvm]: http://llvm.org/releases/3.8.1/
[llvm license]: http://llvm.org/releases/3.8.1/LICENSE.TXT
[lzf license]: http://oldhome.schmorp.de/marc/liblzf.html
[lzf]: http://oldhome.schmorp.de/marc/liblzf.html
[mkdocs license]: https://github.com/mkdocs/mkdocs/blob/master/LICENSE
[mkdocs-material license]: https://github.com/squidfunk/mkdocs-material/blob/master/LICENSE
[mkdocs-material]: https://github.com/squidfunk/mkdocs-material
[mkdocs]: http://www.mkdocs.org/
[opensans license]: http://www.apache.org/licenses/LICENSE-2.0.html
[opensans]: https://www.google.com/fonts/specimen/Open+Sans
[PPC architecture module]: https://github.com/Vector35/ppc-capstone
[python]: https://github.com/python/cpython
[python license]: https://github.com/python/cpython/blob/master/LICENSE
[qt license]: https://www.qt.io/qt-licensing-terms/
[qt]: https://www.qt.io/download/
[rapidjson]: http://rapidjson.org/
[rapidjson license]: https://github.com/Tencent/rapidjson/blob/master/license.txt
[rlcompleter]: https://github.com/python/cpython/blob/master/Lib/rlcompleter.py
[sourcecodepro license]:  https://github.com/adobe-fonts/source-code-pro/blob/master/LICENSE.md
[sourcecodepro]: https://github.com/adobe-fonts/source-code-pro
[NotoColorEmoji license]:  https://github.com/googlefonts/noto-emoji/blob/main/fonts/LICENSE
[NotoColorEmoji]: https://github.com/googlefonts/noto-emoji
[sphinx license]: https://github.com/sphinx-doc/sphinx/blob/master/LICENSE
[sphinx]: http://www.sphinx-doc.org/en/stable/index.html
[sqlite license]: https://www.sqlite.org/copyright.html
[sqlite]: https://www.sqlite.org/index.html
[tarball]: https://binary.ninja/qt6.4.3.tar.xz
[patch]: https://binary.ninja/qt6.4.3.patch
[qt-build]: https://github.com/Vector35/qt-build
[yasm license]: https://github.com/yasm/yasm/blob/master/BSD.txt
[yasm]: http://yasm.tortall.net/
[xed]: http://www.github.com/intelxed/xed/
[xed license]: http://www.github.com/intelxed/xed/blob/master/LICENSE
[zlib license]: http://www.zlib.net/zlib_license.html
[zlib]: http://www.zlib.net/
[jemalloc]: https://github.com/jemalloc/jemalloc
[jemalloc license]: https://github.com/jemalloc/jemalloc/blob/master/COPYING
[libxcb]: https://gitlab.freedesktop.org/xorg/lib/libxcb
[libxcb license]: https://gitlab.freedesktop.org/xorg/lib/libxcb/-/blob/master/COPYING
[Rust license]: https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
[Rust]: https://www.rust-lang.org/
[curl-rust license]: https://github.com/alexcrichton/curl-rust/blob/master/LICENSE
[curl-rust]: https://github.com/alexcrichton/curl-rust
[curl license]: https://github.com/curl/curl/blob/master/COPYING
[curl]: https://github.com/curl/curl
[nom license]: https://github.com/Geal/nom/blob/master/LICENSE
[nom]: https://github.com/Geal/nom
[QCheckboxCombo]: https://github.com/CuriousCrow/QCheckboxCombo
[QCheckboxCombo License]: https://github.com/CuriousCrow/QCheckboxCombo/blob/master/LICENSE
[xxHash]: https://github.com/Cyan4973/xxHash
[xxHash license]: https://github.com/Cyan4973/xxHash/blob/release/LICENSE
[pdb (Rust crate)]: https://github.com/willglynn/pdb
[pdb license]: https://github.com/willglynn/pdb/blob/master/LICENSE-APACHE
[botan]: https://github.com/randombit/botan
[botan license]: https://github.com/randombit/botan/blob/master/license.txt
[deprecation]: https://github.com/briancurtin/deprecation
[deprecation license]: https://github.com/briancurtin/deprecation/blob/master/LICENSE
[num-bigint]: https://github.com/rust-num/num-bigint
[num-bigint license]: https://github.com/rust-num/num-bigint/blob/master/LICENSE-MIT
[num-integer]: https://github.com/rust-num/num-integer
[num-integer license]: https://github.com/rust-num/num-integer/blob/master/LICENSE-MIT
[num-traits]: https://github.com/rust-num/num-traits
[num-traits license]: https://github.com/rust-num/num-traits/blob/master/LICENSE-MIT
[API / Documentation]: https://github.com/vector35/binaryninja-api
[api license]: https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt
[Views]: https://github.com/Vector35/?q=view-&type=all&language=&sort=
[views license]: https://github.com/Vector35/view-pe/blob/main/LICENSE
[Architectures]: https://github.com/Vector35/?q=arch-&type=all&language=&sort=
[architectures license]: https://github.com/Vector35/arch-armv7/blob/master/LICENSE