# Binary Ninja

## Open Source

Vector 35 is grateful for the following open source packages that are used in Binary Ninja directly or indirectly:

* Documentation
    - [mkdocs] ([mkdocs license] - BSD)
    - [mkdocs-material] ([mkdocs-material License] - BSD)
    - [breathe] ([breathe license] - BSD)
    - [breathe-rtd-theme] ([breathe-rtd-theme license] - MIT)
    - [sphinx] ([sphinx license] - BSD and others)
    - [doxygen] ([doxygen license] - GPLv2)

The previous tools are used in the generation of our documentation, but are not distributed themselves and are merely listed here in acknowledgement for the value they provide.

* UI
    - [qt] ([qt license] - LGPLv3 / note, please see our [qt build instructions below](open-source.md#building-qt))
    - [sourcecodepro] ([sourcecodepro license] - SIL open font license)
    - [opensans] ([opensans license] - Apache 2.0)
    - [dejavusanscode] ([dejavusanscode license] - multiple open licenses)

* Core
    - [lzf] ([lzf license] - BSD)
    - [zlib] ([zlib license] - zlib license)
    - [openssl] ([openssl license] - openssl license)
    - [discount] ([discount license] - BSD)

* Upvector update Library
    - [tomcrypt] ([tomcrypt license] - public domain)


## Building Qt

Binary Ninja uses [Qt 5.6] under an LGPLv3 license which requires that we host the original sources used to build Qt for our application along with instructions on how that source may be re-built and can replace the version of Qt shipped with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 5 from Git] page.
2. Download the Qt 5.6.0 [tarball] from binary.ninja. (Note this is an unmodified 5.6 identical to that available from Qt's source control, but must be hosted locally according to the [Qt 5.6] terms.)
3. Next, build QT using the aforementioned instructions.
4. On OS X, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.  We recommend a tool such as [unsign].
5. Finally, replace the built libraries:
     - On OS X, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt5core.dll`, `Qt5Gui.dll`, `Qt5Network.dll`, and `Qt5Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`
     - On Linux, replace the `libQt5Core.so.5`, `libQt5DBus.so.5`, `libQt5Gui.so.5`, `libQt5Network.so.5`, `libQt5Widgets.so.5`, `libQt5XcbQpa.so.5` files wherever Binary Ninja was extracted

[mkdocs]: http://www.mkdocs.org/
[mkdocs license]: https://github.com/mkdocs/mkdocs/blob/master/LICENSE
[mkdocs-material]: https://github.com/squidfunk/mkdocs-material
[mkdocs-material license]: https://github.com/squidfunk/mkdocs-material/blob/master/LICENSE
[breathe]: https://github.com/michaeljones/breathe
[breathe license]: https://github.com/michaeljones/breathe/blob/master/LICENSE
[breathe-rtd-theme]: https://github.com/snide/sphinx_rtd_theme/
[breathe-rtd-theme license]: https://github.com/snide/sphinx_rtd_theme/blob/master/LICENSE
[sphinx]: http://www.sphinx-doc.org/en/stable/index.html
[sphinx license]: https://github.com/sphinx-doc/sphinx/blob/master/LICENSE
[doxygen]: http://www.stack.nl/~dimitri/doxygen/
[doxygen license]: https://github.com/doxygen/doxygen/blob/master/LICENSE
[qt]: https://www.qt.io/download/
[qt license]: https://www.qt.io/qt-licensing-terms/
[lzf]: http://oldhome.schmorp.de/marc/liblzf.html
[lzf license]: http://oldhome.schmorp.de/marc/liblzf.html
[discount]: http://www.pell.portland.or.us/~orc/Code/discount/
[discount license]: http://www.pell.portland.or.us/~orc/Code/discount/COPYRIGHT.html
[zlib]: http://www.zlib.net/
[zlib license]: http://www.zlib.net/zlib_license.html
[openssl]: https://www.openssl.org/
[openssl license]: https://www.openssl.org/source/license.html
[tomcrypt]:  https://github.com/libtom/libtomcrypt
[tomcrypt license]: https://github.com/libtom/libtomcrypt/blob/develop/LICENSE
[sourcecodepro]: https://github.com/adobe-fonts/source-code-pro
[sourcecodepro license]:  https://github.com/adobe-fonts/source-code-pro/blob/master/LICENSE.txt
[opensans]: https://www.google.com/fonts/specimen/Open+Sans
[opensans license]: http://www.apache.org/licenses/LICENSE-2.0.html
[dejavusanscode]: https://github.com/SSNikolaevich/DejaVuSansCode
[dejavusanscode license]: https://github.com/SSNikolaevich/DejaVuSansCode/blob/master/LICENSE
[Qt 5.6]: https://www.qt.io/qt-licensing-terms/
[Building Qt 5 from Git]: https://wiki.qt.io/Building-Qt-5-from-Git
[tarball]: https://binary.ninja/qt5.6.0.tar.xz
[unsign]: https://github.com/steakknife/unsign
