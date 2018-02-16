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
    - [sourcecodepro] ([sourcecodepro license] - SIL open font license)

* Core
    - [discount] ([discount license] - BSD)
    - [libcurl] ([libcurl license] - MIT/X derivative)
    - [libgit2] ([libgit2 license] - GPLv2 with linking exception)
    - [libmspack] ([libmspack license] - LGPL, v2)
    - [llvm] ([llvm license] - BSD-style)
    - [lzf] ([lzf license] - BSD)
    - [jemalloc] ([jemalloc license] - BSD)
    - [openssl] ([openssl license] - openssl license)
    - [sqlite] ([sqlite license] - public domain)
    - [zlib] ([zlib license] - zlib license)

* Other
    - [yasm] ([yasm license] - 2-clause BSD) used for assembling x86 and x64
    - [capstone] ([capstone license] - 3-clause BSD) used in the PPC architecture module as an example of how to wrap an external disassembler

* Upvector update library
    - [tomcrypt] ([tomcrypt license] - public domain)


## Building Qt

Binary Ninja uses [Qt 5.10] under an LGPLv3 license which requires that we host the original sources used to build Qt for our application along with instructions on how that source may be re-built and can replace the version of Qt shipped with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 5 from Git] page.
2. Download the Qt 5.10.0 [tarball] from binary.ninja. (Note this is an unmodified 5.10 identical to that available from Qt's source control, but must be hosted locally according to the [Qt 5.10] terms.)
3. Next, build QT using the aforementioned instructions.
4. On OS X, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.  We recommend a tool such as [unsign].
5. Finally, replace the built libraries:
     - On OS X, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt5core.dll`, `Qt5Gui.dll`, `Qt5Network.dll`, and `Qt5Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`
     - On Linux, replace the `libQt5Core.so.5`, `libQt5DBus.so.5`, `libQt5Gui.so.5`, `libQt5Network.so.5`, `libQt5Widgets.so.5`, `libQt5XcbQpa.so.5` files wherever Binary Ninja was extracted

[Building Qt 5 from Git]: https://wiki.qt.io/Building-Qt-5-from-Git
[Qt 5.10]: https://www.qt.io/qt-licensing-terms/
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
[libcurl]: https://curl.haxx.se/
[libcurl license]: https://curl.haxx.se/docs/copyright.html 
[libgit2]: https://libgit2.github.com/
[libgit2 license]: https://github.com/libgit2/libgit2/blob/master/COPYING
[libmspack]: https://www.cabextract.org.uk/libmspack/
[libmspack license]: https://www.cabextract.org.uk/libmspack/#license
[llvm]: http://llvm.org/releases/3.8.1/
[llvm license]: http://llvm.org/releases/3.8.1/LICENSE.TXT
[jemalloc]: http://jemalloc.net/
[jemalloc license]: https://github.com/jemalloc/jemalloc/blob/dev/COPYING
[lzf license]: http://oldhome.schmorp.de/marc/liblzf.html
[lzf]: http://oldhome.schmorp.de/marc/liblzf.html
[mkdocs license]: https://github.com/mkdocs/mkdocs/blob/master/LICENSE
[mkdocs-material license]: https://github.com/squidfunk/mkdocs-material/blob/master/LICENSE
[mkdocs-material]: https://github.com/squidfunk/mkdocs-material
[mkdocs]: http://www.mkdocs.org/
[opensans license]: http://www.apache.org/licenses/LICENSE-2.0.html
[opensans]: https://www.google.com/fonts/specimen/Open+Sans
[openssl license]: https://www.openssl.org/source/license.html
[openssl]: https://www.openssl.org/
[qt license]: https://www.qt.io/qt-licensing-terms/
[qt]: https://www.qt.io/download/
[sourcecodepro license]:  https://github.com/adobe-fonts/source-code-pro/blob/master/LICENSE.txt
[sourcecodepro]: https://github.com/adobe-fonts/source-code-pro
[sphinx license]: https://github.com/sphinx-doc/sphinx/blob/master/LICENSE
[sphinx]: http://www.sphinx-doc.org/en/stable/index.html
[sqlite license]: https://www.sqlite.org/copyright.html
[sqlite]: https://www.sqlite.org/index.html
[tarball]: https://binary.ninja/qt5.10.0.tar.xz
[tomcrypt license]: https://github.com/libtom/libtomcrypt/blob/develop/LICENSE
[tomcrypt]:  https://github.com/libtom/libtomcrypt
[unsign]: https://github.com/steakknife/unsign
[yasm license]: https://github.com/yasm/yasm/blob/master/BSD.txt
[yasm]: http://yasm.tortall.net/
[zlib license]: http://www.zlib.net/zlib_license.html
[zlib]: http://www.zlib.net/
