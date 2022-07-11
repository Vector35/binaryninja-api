# Binary Ninja

## Open Source

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
    - [discount] ([discount license] - BSD)
    - [jsoncpp] ([jsoncpp] - Public Domain / MIT)
    - [libmspack] ([libmspack license] - LGPL, v2)
    - [llvm] ([llvm license] - BSD-style)
    - [lzf] ([lzf license] - BSD)
    - [python] ([python license] - Python Software Foundation License 2 -- a Python 2.7 built without GPL components is currently shipped with Windows builds only, other platforms leverage existing Python installs)
    - [sqlite] ([sqlite license] - public domain)
    - [zlib] ([zlib license] - zlib license)
    - [rapidjson] ([rapidjson license] - MIT)
    - [jemalloc] ([jemalloc license] - 2-clause BSD)
    - [Rust] ([Rust license] - MIT)
    - [curl-rust] ([curl-rust license] - MIT)
    - [curl] ([curl license] - MIT)
    - [nom] ([nom license] - MIT)
    - [xxHash] ([xxHash License] - 2-clause BSD)

* Other
    - [yasm] ([yasm license] - 2-clause BSD) used for assembling x86 and x64
    - [xed] ([xed license] - Apache License 2.0) used for disassembling x86, x64, and x16
    - [capstone] ([capstone license] - 3-clause BSD) used in the [PPC architecture module] as an example of how to wrap an external disassembler
    - [flatbuffer] ([flatbuffer license] - Apache License 2.0) used in the binary format for the function fingerprint libraries

* Upvector update library
    - [tomcrypt] ([tomcrypt license] - public domain)


## Building Qt

Binary Ninja uses [Qt 6.3] under an LGPLv3 license which requires that we host the original sources used to build Qt for our application along with instructions on how that source may be re-built and can replace the version of Qt shipped with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 6 from Git] page.
2. Download the Qt 6.3.1 [tarball] from binary.ninja. The Qt code has a [patch] applied but is ABI compatible with the official Qt release.
3. Next, build Qt with the [qt-build] repository. Alternatively, build Qt using the aforementioned instructions.
4. On macOS, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.  We recommend a tool such as [unsign].
5. Finally, replace the built libraries:
     - On macOS, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Network.dll`, and `Qt6Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`.
     - On Linux, replace the `libQt6Core.so.6`, `libQt6DBus.so.6`, `libQt6Gui.so.6`, `libQt6Network.so.6`, `libQt6Widgets.so.6`, `libQt6XcbQpa.so.6` files wherever Binary Ninja was extracted.

[Building Qt 6 from Git]: https://wiki.qt.io/Building_Qt_6_from_Git
[Qt 6.3]: https://www.qt.io/qt-licensing-terms/
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
[discount license]: http://www.pell.portland.or.us/~orc/Code/discount/COPYRIGHT.html
[discount]: http://www.pell.portland.or.us/~orc/Code/discount/
[doxygen license]: https://github.com/doxygen/doxygen/blob/master/LICENSE
[doxygen]: http://www.stack.nl/~dimitri/doxygen/
[flatbuffer]: https://github.com/google/flatbuffers
[flatbuffer license]: https://github.com/google/flatbuffers/blob/master/LICENSE.txt
[jsoncpp]: https://github.com/open-source-parsers/jsoncpp
[jsoncpp license]: https://github.com/open-source-parsers/jsoncpp/blob/master/LICENSE
[libmspack]: https://www.cabextract.org.uk/libmspack/
[libmspack license]: https://www.cabextract.org.uk/libmspack/#license
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
[tarball]: https://binary.ninja/qt6.3.1.tar.xz
[patch]: https://binary.ninja/qt6.3.1.patch
[qt-build]: https://github.com/Vector35/qt-build
[tomcrypt license]: https://github.com/libtom/libtomcrypt/blob/develop/LICENSE
[tomcrypt]:  https://github.com/libtom/libtomcrypt
[unsign]: https://github.com/steakknife/unsign
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
