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
    - [jsoncpp] ([jsoncpp] - Public Domain / MIT)
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
    - [dtl] ([dtl license] - BSD)
    - [JSON for Modern C++] ([JSON for Modern C++ license] - MIT)
    - [zstd] ([zstd license] - BSD)

* Core (Rust)
    - [Rust] ([Rust license] - Apache 2.0 / MIT)
    - [pdb-patched] ([pdb-patched license] - Apache 2.0 / MIT -- This repository contains the changes we've made to the PDB crate)
    - [addr2line] ([addr2line license] - APACHE 2.0 / MIT)
    - [adler] ([adler license] - APACHE 2.0 / MIT / BSD Zero Clause)
    - [aead] ([aead license] - APACHE 2.0 / MIT)
    - [aes] ([aes license] - APACHE 2.0 / MIT)
    - [aes-gcm] ([aes-gcm license] - APACHE 2.0 / MIT)
    - [ahash] ([ahash license] - APACHE 2.0 / MIT)
    - [aho-corasick] ([aho-corasick license] - MIT / Unlicense)
    - [anstyle] ([anstyle license] - APACHE 2.0 / MIT)
    - [anyhow] ([anyhow license] - APACHE 2.0 / MIT)
    - [async-compression] ([async-compression license] - APACHE 2.0 / MIT)
    - [autocfg] ([autocfg license] - APACHE 2.0 / MIT)
    - [backtrace] ([backtrace license] - APACHE 2.0 / MIT)
    - [base64] ([base64 license] - APACHE 2.0 / MIT)
    - [bincode] ([bincode license] - MIT)
    - [bindgen] ([bindgen license] - BSD 3-Clause)
    - [bitflags] ([bitflags license] - APACHE 2.0 / MIT)
    - [bitstream-io] ([bitstream-io license] - APACHE 2.0 / MIT)
    - [block-buffer] ([block-buffer license] - APACHE 2.0 / MIT)
    - [byteorder] ([byteorder license] - MIT / Unlicense)
    - [bytes] ([bytes license] - MIT)
    - [cab] ([cab license] - MIT)
    - [cc] ([cc license] - APACHE 2.0 / MIT)
    - [cexpr] ([cexpr license] - APACHE 2.0 / MIT)
    - [cfg-if] ([cfg-if license] - APACHE 2.0 / MIT)
    - [cipher] ([cipher license] - APACHE 2.0 / MIT)
    - [clang] ([clang license] - APACHE 2.0)
    - [clang-sys] ([clang-sys license] - APACHE 2.0)
    - [clap] ([clap license] - APACHE 2.0 / MIT)
    - [clap_builder] ([clap_builder license] - APACHE 2.0 / MIT)
    - [clap_derive] ([clap_derive license] - APACHE 2.0 / MIT)
    - [clap_lex] ([clap_lex license] - APACHE 2.0 / MIT)
    - [code_fuzzy_match] ([code_fuzzy_match license] - MIT)
    - [core-foundation-sys] ([core-foundation-sys license] - APACHE 2.0 / MIT)
    - [core-foundation] ([core-foundation license] - APACHE 2.0 / MIT)
    - [cpp_demangle] ([cpp_demangle license] - APACHE 2.0 / MIT)
    - [cpufeatures] ([cpufeatures license] - APACHE 2.0 / MIT)
    - [crc] ([crc license] - APACHE 2.0 / MIT)
    - [crc-catalog] ([crc-catalog license] - APACHE 2.0 / MIT)
    - [crc32fast] ([crc32fast license] - APACHE 2.0 / MIT)
    - [crypto-common] ([crypto-common license] - APACHE 2.0 / MIT)
    - [ctr] ([ctr license] - APACHE 2.0 / MIT)
    - [cty] ([cty license] - APACHE 2.0 / MIT)
    - [curl-sys] ([curl-sys license] - MIT)
    - [curl] ([curl license] - MIT)
    - [data-encoding] ([data-encoding license] - MIT)
    - [deranged] ([deranged license] - MIT)
    - [derive_more] ([derive_more license] - MIT)
    - [digest] ([digest license] - APACHE 2.0 / MIT)
    - [displaydoc] ([displaydoc license] - APACHE 2.0 / MIT)
    - [either] ([either license] - APACHE 2.0 / MIT)
    - [encoding_rs] ([encoding_rs license] - APACHE 2.0 / MIT / BSD 3-Clause)
    - [equivalent] ([equivalent license] - APACHE 2.0 / MIT)
    - [errno] ([errno license] - APACHE 2.0 / MIT)
    - [fallible-iterator] ([fallible-iterator license] - APACHE 2.0 / MIT)
    - [flate2] ([flate2 license] - APACHE 2.0 / MIT)
    - [fnv] ([fnv license] - APACHE 2.0 / MIT)
    - [form_urlencoded] ([form_urlencoded license] - APACHE 2.0 / MIT)
    - [futures] ([futures license] - APACHE 2.0 / MIT)
    - [futures-channel] ([futures-channel license] - APACHE 2.0 / MIT)
    - [futures-core] ([futures-core license] - APACHE 2.0 / MIT)
    - [futures-executor] ([futures-executor license] - APACHE 2.0 / MIT)
    - [futures-io] ([futures-io license] - APACHE 2.0 / MIT)
    - [futures-macro] ([futures-macro license] - APACHE 2.0 / MIT)
    - [futures-sink] ([futures-sink license] - APACHE 2.0 / MIT)
    - [futures-task] ([futures-task license] - APACHE 2.0 / MIT)
    - [futures-util] ([futures-util license] - APACHE 2.0 / MIT)
    - [generic-array] ([generic-array license] - MIT)
    - [getopts] ([getopts license] - APACHE 2.0 / MIT)
    - [getrandom] ([getrandom license] - APACHE 2.0 / MIT)
    - [ghash] ([ghash license] - APACHE 2.0 / MIT)
    - [gimli] ([gimli license] - APACHE 2.0 / MIT)
    - [glob] ([glob license] - APACHE 2.0 / MIT)
    - [h2] ([h2 license] - MIT)
    - [hashbrown] ([hashbrown license] - APACHE 2.0 / MIT)
    - [heck] ([heck license] - APACHE 2.0 / MIT)
    - [home] ([home license] - APACHE 2.0 / MIT)
    - [http] ([http license] - APACHE 2.0 / MIT)
    - [http-body] ([http-body license] - MIT)
    - [httparse] ([httparse license] - APACHE 2.0 / MIT)
    - [httpdate] ([httpdate license] - APACHE 2.0 / MIT)
    - [hyper] ([hyper license] - MIT)
    - [hyper-rustls] ([hyper-rustls license] - APACHE 2.0 / MIT / ISC)
    - [icu_collections] ([icu_collections license] - MIT)
    - [icu_locid] ([icu_locid license] - MIT)
    - [icu_locid_transform] ([icu_locid_transform license] - MIT)
    - [icu_locid_transform_data] ([icu_locid_transform_data license] - MIT)
    - [icu_normalizer] ([icu_normalizer license] - MIT)
    - [icu_normalizer_data] ([icu_normalizer_data license] - MIT)
    - [icu_properties] ([icu_properties license] - MIT)
    - [icu_properties_data] ([icu_properties_data license] - MIT)
    - [icu_provider] ([icu_provider license] - MIT)
    - [icu_provider_macros] ([icu_provider_macros license] - MIT)
    - [idna] ([idna license] - APACHE 2.0 / MIT)
    - [idna_adapter] ([idna_adapter license] - APACHE 2.0 / MIT)
    - [indexmap] ([indexmap license] - APACHE 2.0 / MIT)
    - [input_buffer] ([input_buffer license] - APACHE 2.0 / MIT)
    - [ipnet] ([ipnet license] - APACHE 2.0 / MIT)
    - [iset] ([iset license] - MIT)
    - [itertools] ([itertools license] - APACHE 2.0 / MIT)
    - [itoa] ([itoa license] - APACHE 2.0 / MIT)
    - [jobserver] ([jobserver license] - APACHE 2.0 / MIT)
    - [keyring] ([keyring license] - APACHE 2.0 / MIT)
    - [lazy_static] ([lazy_static license] - APACHE 2.0 / MIT)
    - [lazycell] ([lazycell license] - APACHE 2.0 / MIT)
    - [libc] ([libc license] - APACHE 2.0 / MIT)
    - [libloading] ([libloading license] - ISC)
    - [libz-sys] ([libz-sys license] - APACHE 2.0 / MIT)
    - [litemap] ([litemap license] - MIT)
    - [log] ([log license] - APACHE 2.0 / MIT)
    - [lzma] ([lzma license] - WTFPL)
    - [lzma-rs] ([lzma-rs license] - MIT)
    - [lzxd] ([lzxd license] - APACHE 2.0 / MIT)
    - [machine-uid] ([machine-uid license] - MIT)
    - [markdown] ([markdown license] - MIT)
    - [memchr] ([memchr license] - MIT / Unlicense)
    - [mime] ([mime license] - MIT)
    - [mime_guess] ([mime_guess license] - MIT)
    - [minimal-lexical] ([minimal-lexical license] - APACHE 2.0 / MIT)
    - [miniz_oxide] ([miniz_oxide license] - APACHE 2.0 / MIT / ZLIB)
    - [mio] ([mio license] - MIT)
    - [nom] ([nom license] - MIT)
    - [num-bigint] ([num-bigint license] - APACHE 2.0 / MIT)
    - [num-conv] ([num-conv license] - MIT)
    - [num-derive] ([num-derive license] - APACHE 2.0 / MIT)
    - [num-integer] ([num-integer license] - APACHE 2.0 / MIT)
    - [num-traits] ([num-traits license] - APACHE 2.0 / MIT)
    - [num_cpus] ([num_cpus license] - APACHE 2.0 / MIT)
    - [object] ([object license] - APACHE 2.0 / MIT)
    - [once_cell] ([once_cell license] - APACHE 2.0 / MIT)
    - [opaque-debug] ([opaque-debug license] - APACHE 2.0 / MIT)
    - [pdb] ([pdb license] - APACHE 2.0 / MIT)
    - [peeking_take_while] ([peeking_take_while license] - APACHE 2.0 / MIT)
    - [pem] ([pem license] - MIT)
    - [percent-encoding] ([percent-encoding license] - APACHE 2.0 / MIT)
    - [pin-project] ([pin-project license] - APACHE 2.0 / MIT)
    - [pin-project-internal] ([pin-project-internal license] - APACHE 2.0 / MIT)
    - [pin-project-lite] ([pin-project-lite license] - APACHE 2.0 / MIT)
    - [pin-utils] ([pin-utils license] - APACHE 2.0 / MIT)
    - [pkg-config] ([pkg-config license] - APACHE 2.0 / MIT)
    - [polyval] ([polyval license] - APACHE 2.0 / MIT)
    - [powerfmt] ([powerfmt license] - MIT)
    - [ppv-lite86] ([ppv-lite86 license] - APACHE 2.0 / MIT)
    - [prettyplease] ([prettyplease license] - APACHE 2.0 / MIT)
    - [proc-macro2] ([proc-macro2 license] - APACHE 2.0 / MIT)
    - [pulldown-cmark] ([pulldown-cmark license] - MIT)
    - [pulldown-cmark-escape] ([pulldown-cmark-escape license] - MIT)
    - [quote] ([quote license] - APACHE 2.0 / MIT)
    - [rand] ([rand license] - APACHE 2.0 / MIT)
    - [rand_chacha] ([rand_chacha license] - APACHE 2.0 / MIT)
    - [rand_core] ([rand_core license] - APACHE 2.0 / MIT)
    - [rational] ([rational license] - MIT)
    - [regex] ([regex license] - APACHE 2.0 / MIT)
    - [regex-automata] ([regex-automata license] - APACHE 2.0 / MIT)
    - [regex-syntax] ([regex-syntax license] - APACHE 2.0 / MIT)
    - [reqwest] ([reqwest license] - APACHE 2.0 / MIT)
    - [ring] ([ring license] - ISC / MIT)
    - [rot13] ([rot13 license] - APACHE 2.0 / MIT)
    - [rustc-demangle] ([rustc-demangle license] - APACHE 2.0 / MIT)
    - [rustc-hash] ([rustc-hash license] - APACHE 2.0 / MIT)
    - [rustix] ([rustix license] - APACHE 2.0 / MIT)
    - [rustls] ([rustls license] - APACHE 2.0 / MIT / ISC)
    - [rustls-native-certs] ([rustls-native-certs license] - APACHE 2.0 / MIT / ISC)
    - [rustls-pemfile] ([rustls-pemfile license] - APACHE 2.0 / MIT / ISC)
    - [rustls-webpki] ([rustls-webpki license] - MIT)
    - [ruzstd] ([ruzstd license] - MIT)
    - [ryu] ([ryu license] - Apache 2.0 / BSL 1)
    - [scroll] ([scroll license] - MIT)
    - [sct] ([sct license] - APACHE 2.0 / MIT / ISC)
    - [search] ([search license] - MIT)
    - [secrets] ([secrets license] - APACHE 2.0 / MIT)
    - [security-framework-sys] ([security-framework-sys license] - APACHE 2.0 / MIT)
    - [security-framework] ([security-framework license] - APACHE 2.0 / MIT)
    - [serde] ([serde license] - APACHE 2.0 / MIT)
    - [serde_derive] ([serde_derive license] - APACHE 2.0 / MIT)
    - [serde_json] ([serde_json license] - APACHE 2.0 / MIT)
    - [serde_repr] ([serde_repr license] - APACHE 2.0 / MIT)
    - [serde_urlencoded] ([serde_urlencoded license] - APACHE 2.0 / MIT)
    - [sha1] ([sha1 license] - APACHE 2.0 / MIT)
    - [shlex] ([shlex license] - APACHE 2.0 / MIT)
    - [slab] ([slab license] - MIT)
    - [smallvec] ([smallvec license] - APACHE 2.0 / MIT)
    - [socket2] ([socket2 license] - APACHE 2.0 / MIT)
    - [spin] ([spin license] - MIT)
    - [stable_deref_trait] ([stable_deref_trait license] - APACHE 2.0 / MIT)
    - [static_assertions] ([static_assertions license] - APACHE 2.0 / MIT)
    - [strsim] ([strsim license] - MIT)
    - [subtle] ([subtle license] - BSD 3-Clause)
    - [syn] ([syn license] - APACHE 2.0 / MIT)
    - [sync_wrapper] ([sync_wrapper license] - APACHE 2.0)
    - [synstructure] ([synstructure license] - MIT)
    - [system-configuration] ([system-configuration license] - APACHE 2.0 / MIT)
    - [system-configuration-sys] ([system-configuration-sys license] - APACHE 2.0 / MIT)
    - [thiserror] ([thiserror license] - APACHE 2.0 / MIT)
    - [thiserror-impl] ([thiserror-impl license] - APACHE 2.0 / MIT)
    - [time] ([time license] - APACHE 2.0 / MIT)
    - [time-core] ([time-core license] - MIT)
    - [tinystr] ([tinystr license] - MIT)
    - [tinyvec] ([tinyvec license] - APACHE 2.0 / MIT / ZLIB)
    - [tinyvec_macros] ([tinyvec_macros license] - APACHE 2.0 / MIT / ZLIB)
    - [tokio] ([tokio license] - MIT)
    - [tokio-macros] ([tokio-macros license] - MIT)
    - [tokio-rustls] ([tokio-rustls license] - APACHE 2.0 / MIT)
    - [tokio-tungstenite] ([tokio-tungstenite license] - MIT)
    - [tokio-util] ([tokio-util license] - MIT)
    - [tower-service] ([tower-service license] - MIT)
    - [tracing] ([tracing license] - MIT)
    - [tracing-attributes] ([tracing-attributes license] - MIT)
    - [tracing-core] ([tracing-core license] - MIT)
    - [try-lock] ([try-lock license] - MIT)
    - [tungstenite] ([tungstenite license] - APACHE 2.0 / MIT)
    - [twox-hash] ([twox-hash license] - MIT)
    - [typenum] ([typenum license] - APACHE 2.0 / MIT)
    - [unicase] ([unicase license] - APACHE 2.0 / MIT)
    - [unicode-bidi] ([unicode-bidi license] - APACHE 2.0 / MIT)
    - [unicode-ident] ([unicode-ident license] - APACHE 2.0 / MIT / Unicode)
    - [unicode-normalization] ([unicode-normalization license] - APACHE 2.0 / MIT)
    - [unicode-width] ([unicode-width license] - APACHE 2.0 / MIT)
    - [universal-hash] ([universal-hash license] - APACHE 2.0 / MIT)
    - [untrusted] ([untrusted license] - ISC)
    - [url] ([url license] - APACHE 2.0 / MIT)
    - [utf-8] ([utf-8 license] - APACHE 2.0 / MIT)
    - [utf16_iter] ([utf16_iter license] - APACHE 2.0 / MIT)
    - [utf8_iter] ([utf8_iter license] - APACHE 2.0 / MIT)
    - [utf8parse] ([utf8parse license] - APACHE 2.0 / MIT)
    - [uuid] ([uuid license] - APACHE 2.0 / MIT)
    - [vcpkg] ([vcpkg license] - APACHE 2.0 / MIT)
    - [version_check] ([version_check license] - APACHE 2.0 / MIT)
    - [want] ([want license] - MIT)
    - [webpki] ([webpki license] - ISC)
    - [webpki-roots] ([webpki-roots license] - MPL 2.0)
    - [websocket] ([websocket license] - MIT)
    - [which] ([which license] - MIT)
    - [write16] ([write16 license] - APACHE 2.0 / MIT)
    - [writeable] ([writeable license] - UNICODE V3)
    - [x509-signature] ([x509-signature license] - APACHE 2.0 / MIT)
    - [yoke] ([yoke license] - UNICODE V3)
    - [zerocopy] ([zerocopy license] - APACHE 2.0 / MIT)
    - [zerofrom] ([zerofrom license] - UNICODE V3)
    - [zerovec] ([zerovec license] - UNICODE V3)
    - [zstd-rs] ([zstd-rs license] - MIT)

* Other
    - [yasm] ([yasm license] - 2-clause BSD) used for assembling x86 and x64
    - [xed] ([xed license] - Apache License 2.0) used for disassembling x86, x64, and x16
    - [capstone] ([capstone license] - 3-clause BSD) used in the [PPC architecture module] as an example of how to wrap an external disassembler
    - [flatbuffer] ([flatbuffer license] - Apache License 2.0) used in the binary format for the function fingerprint libraries
    - [deprecation] ([deprecation license] - Apache License 2.0) used in the Python API for marking deprecated functions/properties/classes

## First Party Open Source

* Several components of Binary Ninja developed by Vector 35 directly are released under open source licenses, noted as below:
    - [API / Documentation] ([api license] - MIT) APIs (Python, C, C++) and Documentation (User, API, etc)</li>
    - [Rust API] ([rust api license] - Apache License 2.0)
    - LIB Files ([api license] - MIT) .lib files included with the native windows builds of Binary Ninja are released under the same MIT license as the API itself, distinct from the standard EULA
    - [Views] ([views license] - Apache License 2.0) Binary views included with the product
    - [Architectures] ([architectures license] - Apache License 2.0) Architecture support included with the product
    - [DWARF Import] - ([dwarf import license] - Apache License 2.0)
    - [DWARF Export] - ([dwarf export license] - Apache License 2.0)
    - [IDB Import] - ([idb import license] - Apache License 2.0)

## Building Qt

Binary Ninja uses [Qt 6.8] under an LGPLv3 license which requires that we host the original sources used to build Qt for
our application along with instructions on how that source may be re-built and can replace the version of Qt shipped
with Binary Ninja.

Please note that we offer no support for running Binary Ninja with modified Qt libraries.

1. Follow the installation requirements on the [Building Qt 6 from Git] page.
2. Download the Qt 6.8.2 [tarball] from binary.ninja. The Qt code has a [patch] applied but is ABI compatible with the
   official Qt release.
3. Next, build Qt with the [qt-build] repository. Alternatively, build Qt using the aforementioned instructions.
4. On macOS, you will need to disable the code-signing signature since it would otherwise prevent changes to binaries or shared libraries.
5. Finally, replace the built libraries:
     - On macOS, replace the `QtCore.framework`, `QtDBus.framework`, `QtGui.framework`, `QtNetwork.framework`, `QtPrintSupport.framework`, `QtWidgets.framework` folders inside of `/Applications/Binary Ninja.app/Contents/Frameworks`
     - On Windows, replace the `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Network.dll`, and `Qt6Widgets.dll` files in `C:\Program Files\Vector35\BinaryNinja\`.
     - On Linux, replace the `libQt6Core.so.6`, `libQt6DBus.so.6`, `libQt6Gui.so.6`, `libQt6Network.so.6`, `libQt6Widgets.so.6`, `libQt6XcbQpa.so.6` files wherever Binary Ninja was extracted.

[Building Qt 6 from Git]: https://wiki.qt.io/Building_Qt_6_from_Git
[Qt 6.8]: https://www.qt.io/licensing/open-source-lgpl-obligations
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
[doxygen license]: https://github.com/doxygen/doxygen/blob/master/LICENSE
[doxygen]: https://www.doxygen.nl
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
[qt license]: https://www.qt.io/licensing/open-source-lgpl-obligations
[qt]: https://www.qt.io/download/
[rapidjson]: http://rapidjson.org/
[rapidjson license]: https://github.com/Tencent/rapidjson/blob/master/license.txt
[rlcompleter]: https://github.com/python/cpython/blob/master/Lib/rlcompleter.py
[sourcecodepro license]:  https://github.com/adobe-fonts/source-code-pro/blob/master/LICENSE.md
[sourcecodepro]: https://github.com/adobe-fonts/source-code-pro
[NotoColorEmoji license]:  https://github.com/googlefonts/noto-emoji/blob/main/fonts/LICENSE
[NotoColorEmoji]: https://github.com/googlefonts/noto-emoji
[sphinx license]: https://github.com/sphinx-doc/sphinx/blob/master/LICENSE.rst
[sphinx]: http://www.sphinx-doc.org/en/stable/index.html
[sqlite license]: https://www.sqlite.org/copyright.html
[sqlite]: https://www.sqlite.org/index.html
[tarball]: https://binary.ninja/qt6.8.2.tar.xz
[patch]: https://binary.ninja/qt6.8.2.patch
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
[DWARF Import]: https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples/dwarf/dwarf_import
[dwarf import license]: https://github.com/Vector35/binaryninja-api/blob/dev/rust/LICENSE
[DWARF Export]: https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples/dwarf/dwarf_export
[dwarf export license]: https://github.com/Vector35/binaryninja-api/blob/dev/rust/LICENSE
[IDB Import]: https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples/idb_import
[idb import license]: https://github.com/Vector35/binaryninja-api/blob/dev/rust/LICENSE

[Rust]: https://www.rust-lang.org/
[Rust license]: https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
[pdb-patched]: https://github.com/Vector35/pdb-rs
[pdb-patched license]: https://github.com/Vector35/pdb-rs/blob/master/LICENSE-APACHE

[addr2line]: https://github.com/gimli-rs/addr2line
[addr2line license]: https://github.com/gimli-rs/addr2line/blob/master/LICENSE-MIT
[adler]: https://github.com/jonas-schievink/adler
[adler license]: https://github.com/jonas-schievink/adler/blob/master/LICENSE-MIT
[aead]: https://github.com/RustCrypto/traits/tree/master/aead
[aead license]: https://github.com/RustCrypto/traits/blob/master/aead/LICENSE-MIT
[aes]: https://github.com/RustCrypto/block-ciphers/tree/master/aes
[aes license]: https://github.com/RustCrypto/block-ciphers/blob/master/aes/LICENSE-MIT
[aes-gcm]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[aes-gcm license]: https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/LICENSE-MIT
[ahash]: https://github.com/tkaitchuck/ahash
[ahash license]: https://github.com/tkaitchuck/aHash/blob/master/LICENSE-MIT
[aho-corasick]: https://github.com/BurntSushi/aho-corasick
[aho-corasick license]: https://github.com/BurntSushi/aho-corasick/blob/master/LICENSE-MIT
[anstyle]: https://github.com/rust-cli/anstyle
[anstyle license]: https://opensource.org/license/mit
[anyhow]: https://github.com/dtolnay/anyhow
[anyhow license]: https://github.com/dtolnay/anyhow/blob/master/LICENSE-MIT
[async-compression]: https://github.com/Nullus157/async-compression
[async-compression license]: https://github.com/Nullus157/async-compression/blob/main/LICENSE-MIT
[autocfg]: https://github.com/cuviper/autocfg
[autocfg license]: https://github.com/cuviper/autocfg/blob/master/LICENSE-MIT
[backtrace]: https://github.com/rust-lang/backtrace-rs
[backtrace license]: https://github.com/rust-lang/backtrace-rs/blob/master/LICENSE-MIT
[base64]: https://github.com/marshallpierce/rust-base64
[base64 license]: https://github.com/marshallpierce/rust-base64/blob/master/LICENSE-MIT
[bincode]: https://github.com/bincode-org/bincode
[bincode license]: https://github.com/bincode-org/bincode/blob/trunk/LICENSE.md
[bindgen]: https://github.com/rust-lang/rust-bindgen
[bindgen license]: https://github.com/rust-lang/rust-bindgen/blob/main/LICENSE
[bitflags]: https://github.com/bitflags/bitflags
[bitflags license]: https://github.com/bitflags/bitflags/blob/main/LICENSE-MIT
[bitstream-io]: https://github.com/tuffy/bitstream-io
[bitstream-io license]: https://github.com/tuffy/bitstream-io/blob/master/LICENSE-MIT
[block-buffer]: https://github.com/RustCrypto/utils/tree/master/block-buffer
[block-buffer license]: https://github.com/RustCrypto/utils/blob/master/block-buffer/LICENSE-MIT
[byteorder]: https://github.com/BurntSushi/byteorder
[byteorder license]: https://github.com/BurntSushi/byteorder/blob/master/LICENSE-MIT
[bytes]: https://github.com/tokio-rs/bytes
[bytes license]: https://github.com/tokio-rs/bytes/blob/master/LICENSE
[cab]: https://github.com/mdsteele/rust-cab
[cab license]: https://github.com/mdsteele/rust-cab/blob/master/LICENSE
[cc]: https://github.com/rust-lang/cc-rs
[cc license]: https://github.com/rust-lang/cc-rs/blob/main/LICENSE-MIT
[cexpr]: https://github.com/jethrogb/rust-cexpr
[cexpr license]: https://github.com/jethrogb/rust-cexpr/blob/master/LICENSE-MIT
[cfg-if]: https://github.com/alexcrichton/cfg-if
[cfg-if license]: https://github.com/rust-lang/cfg-if/blob/main/LICENSE-MIT
[cipher]: https://github.com/RustCrypto/traits/tree/master/cipher
[cipher license]: https://github.com/RustCrypto/traits/blob/master/cipher/LICENSE-MIT
[clang]: https://github.com/KyleMayes/clang-rs
[clang license]: https://github.com/KyleMayes/clang-rs/blob/master/LICENSE.txt
[clang-sys]: https://github.com/KyleMayes/clang-sys
[clang-sys license]: https://github.com/KyleMayes/clang-sys/blob/master/LICENSE.txt
[clap]: https://github.com/clap-rs/clap
[clap license]: https://github.com/clap-rs/clap/blob/master/LICENSE-MIT
[clap_builder]: https://github.com/clap-rs/clap
[clap_builder license]: https://github.com/clap-rs/clap/blob/master/LICENSE-MIT
[clap_derive]: https://github.com/clap-rs/clap
[clap_derive license]: https://github.com/clap-rs/clap/blob/master/LICENSE-MIT
[clap_lex]: https://github.com/clap-rs/clap
[clap_lex license]: https://github.com/clap-rs/clap/blob/master/LICENSE-MIT
[code_fuzzy_match license]: https://github.com/D0ntPanic/code-fuzzy-match/blob/master/LICENSE
[core-foundation-sys]: https://github.com/servo/core-foundation-rs
[core-foundation-sys license]: https://github.com/servo/core-foundation-rs/blob/main/LICENSE-MIT
[core-foundation]: https://github.com/servo/core-foundation-rs
[core-foundation license]: https://github.com/servo/core-foundation-rs/blob/main/LICENSE-MIT
[cpp_demangle]: https://github.com/gimli-rs/cpp_demangle
[cpp_demangle license]: https://github.com/gimli-rs/cpp_demangle/blob/master/LICENSE-MIT
[cpufeatures]: https://github.com/RustCrypto/utils/tree/master/cpufeatures
[cpufeatures license]: https://github.com/RustCrypto/utils/blob/master/cpufeatures/LICENSE-MIT
[crc]: https://github.com/mrhooray/crc-rs
[crc license]: https://github.com/mrhooray/crc-rs/blob/master/LICENSE-MIT
[crc-catalog]: https://github.com/akhilles/crc-catalog
[crc-catalog license]: https://github.com/akhilles/crc-catalog/blob/master/LICENSES/MIT.txt
[crc32fast]: https://github.com/srijs/rust-crc32fast
[crc32fast license]: https://github.com/srijs/rust-crc32fast/blob/master/LICENSE-MIT
[crypto-common]: https://github.com/RustCrypto/traits/tree/master/crypto-common
[crypto-common license]: https://github.com/RustCrypto/traits/blob/master/crypto-common/LICENSE-MIT
[ctr]: https://github.com/RustCrypto/block-modes/tree/master/ctr
[ctr license]: https://github.com/RustCrypto/block-modes/blob/master/ctr/LICENSE-MIT
[cty]: https://github.com/japaric/cty
[cty license]: https://github.com/japaric/cty/blob/master/LICENSE-MIT
[curl-sys]: https://github.com/alexcrichton/curl-rust
[curl-sys license]: https://github.com/alexcrichton/curl-rust/blob/main/LICENSE
[curl]: https://github.com/alexcrichton/curl-rust
[curl license]: https://github.com/alexcrichton/curl-rust/blob/main/LICENSE
[data-encoding]: https://github.com/ia0/data-encoding
[data-encoding license]: https://github.com/ia0/data-encoding/blob/main/LICENSE
[deranged]: https://github.com/jhpratt/deranged
[deranged license]: https://github.com/jhpratt/deranged/blob/main/LICENSE-MIT
[derive_more]: https://github.com/JelteF/derive_more
[derive_more license]: https://github.com/JelteF/derive_more/blob/master/LICENSE
[digest]: https://github.com/RustCrypto/traits/tree/master/digest
[digest license]: https://github.com/RustCrypto/traits/blob/master/digest/LICENSE-MIT
[displaydoc]: https://github.com/yaahc/displaydoc
[displaydoc license]: https://github.com/yaahc/displaydoc/blob/master/LICENSE-MIT
[either]: https://github.com/rayon-rs/either
[either license]: https://github.com/rayon-rs/either/blob/main/LICENSE-MIT
[encoding_rs]: https://github.com/hsivonen/encoding_rs
[encoding_rs license]: https://github.com/hsivonen/encoding_rs/blob/master/LICENSE-MIT
[equivalent]: https://github.com/cuviper/equivalent
[equivalent license]: https://github.com/indexmap-rs/equivalent/blob/master/LICENSE-MIT
[errno]: https://github.com/lambda-fairy/rust-errno
[errno license]: https://github.com/lambda-fairy/rust-errno/blob/main/LICENSE-MIT
[fallible-iterator]: https://github.com/sfackler/rust-fallible-iterator
[fallible-iterator license]: https://github.com/sfackler/rust-fallible-iterator/blob/master/LICENSE-MIT
[flate2]: https://github.com/rust-lang/flate2-rs
[flate2 license]: https://github.com/rust-lang/flate2-rs/blob/main/LICENSE-MIT
[fnv]: https://github.com/servo/rust-fnv
[fnv license]: https://github.com/servo/rust-fnv/blob/main/LICENSE-MIT
[form_urlencoded]: https://github.com/servo/rust-url
[form_urlencoded license]: https://github.com/servo/rust-url/blob/main/LICENSE-MIT
[futures]: https://github.com/rust-lang/futures-rs
[futures license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-channel]: https://github.com/rust-lang/futures-rs/tree/master/futures-channel
[futures-channel license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-core]: https://github.com/rust-lang/futures-rs/tree/master/futures-core
[futures-core license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-executor]: https://github.com/rust-lang/futures-rs/tree/master/futures-executor
[futures-executor license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-io]: https://github.com/rust-lang/futures-rs/tree/master/futures-io
[futures-io license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-macro]: https://github.com/rust-lang/futures-rs/tree/master/futures-macro
[futures-macro license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-sink]: https://github.com/rust-lang/futures-rs/tree/master/futures-sink
[futures-sink license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-task]: https://github.com/rust-lang/futures-rs/tree/master/futures-task
[futures-task license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[futures-util]: https://github.com/rust-lang/futures-rs/tree/master/futures-util
[futures-util license]: https://github.com/rust-lang/futures-rs/blob/master/LICENSE-MIT
[generic-array]: https://github.com/fizyk20/generic-array.git
[generic-array license]: https://github.com/fizyk20/generic-array/blob/master/LICENSE
[getopts]: https://github.com/rust-lang/getopts
[getopts license]: https://github.com/rust-lang/getopts/blob/master/LICENSE-MIT
[getrandom]: https://github.com/rust-random/getrandom
[getrandom license]: https://github.com/rust-random/getrandom/blob/master/LICENSE-MIT
[ghash]: https://github.com/RustCrypto/universal-hashes/tree/master/ghash
[ghash license]: https://github.com/RustCrypto/universal-hashes/blob/master/ghash/LICENSE-MIT
[gimli]: https://github.com/gimli-rs/gimli
[gimli license]: https://github.com/gimli-rs/gimli/blob/master/LICENSE-MIT
[glob]: https://github.com/rust-lang/glob
[glob license]: https://github.com/rust-lang/glob/blob/master/LICENSE-MIT
[h2]: https://github.com/hyperium/h2
[h2 license]: https://github.com/hyperium/h2/blob/master/LICENSE
[hashbrown]: https://github.com/rust-lang/hashbrown
[hashbrown license]: https://github.com/rust-lang/hashbrown/blob/master/LICENSE-MIT
[heck]: https://github.com/withoutboats/heck
[heck license]: https://github.com/withoutboats/heck/blob/master/LICENSE-MIT
[home]: https://github.com/rust-lang/cargo/tree/master/crates/home
[home license]: https://github.com/rust-lang/cargo/blob/master/LICENSE-MIT
[http]: https://github.com/hyperium/http
[http license]: https://github.com/hyperium/http/blob/master/LICENSE-MIT
[http-body]: https://github.com/hyperium/http-body
[http-body license]: https://github.com/hyperium/http-body/blob/master/LICENSE
[httparse]: https://github.com/seanmonstar/httparse
[httparse license]: https://github.com/seanmonstar/httparse/blob/master/LICENSE-MIT
[httpdate]: https://github.com/pyfisch/httpdate
[httpdate license]: https://github.com/pyfisch/httpdate/blob/main/LICENSE-MIT
[hyper]: https://github.com/hyperium/hyper
[hyper license]: https://github.com/hyperium/hyper/blob/master/LICENSE
[hyper-rustls]: https://github.com/rustls/hyper-rustls
[hyper-rustls license]: https://github.com/rustls/hyper-rustls/blob/main/LICENSE-MIT
[icu_collections]: https://github.com/unicode-org/icu4x
[icu_collections license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_locid]: https://github.com/unicode-org/icu4x
[icu_locid license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_locid_transform]: https://github.com/unicode-org/icu4x
[icu_locid_transform license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_locid_transform_data]: https://github.com/unicode-org/icu4x
[icu_locid_transform_data license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_normalizer]: https://github.com/unicode-org/icu4x
[icu_normalizer license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_normalizer_data]: https://github.com/unicode-org/icu4x
[icu_normalizer_data license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_properties]: https://github.com/unicode-org/icu4x
[icu_properties license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_properties_data]: https://github.com/unicode-org/icu4x
[icu_properties_data license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_provider]: https://github.com/unicode-org/icu4x
[icu_provider license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[icu_provider_macros]: https://github.com/unicode-org/icu4x
[icu_provider_macros license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[idna]: https://github.com/servo/rust-url/
[idna license]: https://github.com/servo/rust-url/blob/main/LICENSE-MIT
[idna_adapter]: https://github.com/hsivonen/idna_adapter
[idna_adapter license]: https://github.com/hsivonen/idna_adapter/blob/main/LICENSE-MIT
[indexmap]: https://github.com/indexmap-rs/indexmap
[indexmap license]: https://github.com/indexmap-rs/indexmap/blob/master/LICENSE-MIT
[input_buffer]: https://github.com/snapview/input_buffer
[input_buffer license]: https://github.com/snapview/input_buffer/blob/master/LICENSE-MIT
[ipnet]: https://github.com/krisprice/ipnet
[ipnet license]: https://github.com/krisprice/ipnet/blob/master/LICENSE-MIT
[iset]: https://github.com/tprodanov/iset
[iset license]: https://github.com/tprodanov/iset/blob/master/LICENSE
[itertools]: https://github.com/rust-itertools/itertools
[itertools license]: https://github.com/rust-itertools/itertools/blob/master/LICENSE-MIT
[itoa]: https://github.com/dtolnay/itoa
[itoa license]: https://github.com/dtolnay/itoa/blob/master/LICENSE-MIT
[jobserver]: https://github.com/rust-lang/jobserver-rs
[jobserver license]: https://github.com/rust-lang/jobserver-rs/blob/main/LICENSE-MIT
[keyring]: https://github.com/hwchen/keyring-rs
[keyring license]: https://github.com/hwchen/keyring-rs/blob/master/LICENSE-MIT
[lazy_static]: https://github.com/rust-lang-nursery/lazy-static.rs
[lazy_static license]: https://github.com/rust-lang-nursery/lazy-static.rs/blob/master/LICENSE-MIT
[lazycell]: https://github.com/indiv0/lazycell
[lazycell license]: https://github.com/indiv0/lazycell/blob/master/LICENSE-MIT
[libc]: https://github.com/rust-lang/libc
[libc license]: https://github.com/rust-lang/libc/blob/main/LICENSE-MIT
[libloading]: https://github.com/nagisa/rust_libloading/
[libloading license]: https://github.com/nagisa/rust_libloading/blob/master/LICENSE
[libz-sys]: https://github.com/rust-lang/libz-sys
[libz-sys license]: https://github.com/rust-lang/libz-sys/blob/main/LICENSE-MIT
[litemap]: https://github.com/unicode-org/icu4x
[litemap license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[log]: https://github.com/rust-lang/log
[log license]: https://github.com/rust-lang/log/blob/master/LICENSE-MIT
[lzma]: https://github.com/meh/rust-lzma
[lzma license]: http://www.wtfpl.net/
[lzma-rs]: https://github.com/gendx/lzma-rs
[lzma-rs license]: https://github.com/gendx/lzma-rs/blob/master/LICENSE
[lzxd]: https://github.com/Lonami/lzxd
[lzxd license]: https://github.com/Lonami/lzxd/blob/master/LICENSE-MIT
[machine-uid]: https://github.com/Hanaasagi/machine-uid
[machine-uid license]: https://github.com/Hanaasagi/machine-uid/blob/master/LICENSE
[markdown]: https://github.com/wooorm/markdown-rs
[markdown license]: https://github.com/wooorm/markdown-rs/blob/main/license
[memchr]: https://github.com/BurntSushi/memchr
[memchr license]: https://github.com/BurntSushi/memchr/blob/master/LICENSE-MIT
[mime]: https://github.com/hyperium/mime
[mime license]: https://github.com/hyperium/mime/blob/master/LICENSE
[mime_guess]: https://github.com/abonander/mime_guess
[mime_guess license]: https://github.com/abonander/mime_guess/blob/master/LICENSE
[minimal-lexical]: https://github.com/Alexhuszagh/minimal-lexical
[minimal-lexical license]: https://github.com/Alexhuszagh/minimal-lexical/blob/main/LICENSE-MIT
[miniz_oxide]: https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide
[miniz_oxide license]: https://github.com/Frommi/miniz_oxide/blob/master/miniz_oxide/LICENSE-MIT.md
[mio]: https://github.com/tokio-rs/mio
[mio license]: https://github.com/tokio-rs/mio/blob/master/LICENSE
[nom]: https://github.com/rust-bakery/nom
[nom license]: https://github.com/rust-bakery/nom/blob/main/LICENSE
[num-bigint]: https://github.com/rust-num/num-bigint
[num-bigint license]: https://github.com/rust-num/num-bigint/blob/master/LICENSE-MIT
[num-conv]: https://github.com/jhpratt/num-conv
[num-conv license]: https://github.com/jhpratt/num-conv/blob/main/LICENSE-MIT
[num-derive]: https://github.com/rust-num/num-derive
[num-derive license]: https://github.com/rust-num/num-derive/blob/master/LICENSE-MIT
[num-integer]: https://github.com/rust-num/num-integer
[num-integer license]: https://github.com/rust-num/num-integer/blob/master/LICENSE-MIT
[num-traits]: https://github.com/rust-num/num-traits
[num-traits license]: https://github.com/rust-num/num-traits/blob/master/LICENSE-MIT
[num_cpus]: https://github.com/seanmonstar/num_cpus
[num_cpus license]: https://github.com/seanmonstar/num_cpus/blob/master/LICENSE-MIT
[object]: https://github.com/gimli-rs/object
[object license]: https://github.com/gimli-rs/object/blob/master/LICENSE-MIT
[once_cell]: https://github.com/matklad/once_cell
[once_cell license]: https://github.com/matklad/once_cell/blob/master/LICENSE-MIT
[opaque-debug]: https://github.com/RustCrypto/utils/tree/master/opaque-debug
[opaque-debug license]: https://github.com/RustCrypto/utils/blob/master/opaque-debug/LICENSE-MIT
[pdb]: https://github.com/getsentry/pdb
[pdb license]: https://github.com/getsentry/pdb/blob/master/LICENSE-MIT
[peeking_take_while]: https://github.com/fitzgen/peeking_take_while
[peeking_take_while license]: https://github.com/fitzgen/peeking_take_while/blob/master/LICENSE-MIT
[pem]: https://github.com/jcreekmore/pem-rs
[pem license]: https://github.com/jcreekmore/pem-rs/blob/master/LICENSE.md
[percent-encoding]: https://github.com/servo/rust-url/
[percent-encoding license]: https://github.com/servo/rust-url/blob/main/LICENSE-MIT
[pin-project]: https://github.com/taiki-e/pin-project
[pin-project license]: https://github.com/taiki-e/pin-project/blob/main/LICENSE-MIT
[pin-project-internal]: https://github.com/taiki-e/pin-project/tree/main/pin-project-internal
[pin-project-internal license]: https://github.com/taiki-e/pin-project/blob/main/pin-project-internal/LICENSE-MIT
[pin-project-lite]: https://github.com/taiki-e/pin-project-lite
[pin-project-lite license]: https://github.com/taiki-e/pin-project-lite/blob/main/LICENSE-MIT
[pin-utils]: https://github.com/rust-lang-nursery/pin-utils
[pin-utils license]: https://github.com/rust-lang/pin-utils/blob/master/LICENSE-MIT
[pkg-config]: https://github.com/rust-lang/pkg-config-rs
[pkg-config license]: https://github.com/rust-lang/pkg-config-rs/blob/master/LICENSE-MIT
[polyval]: https://github.com/RustCrypto/universal-hashes/tree/master/polyval
[polyval license]: https://github.com/RustCrypto/universal-hashes/blob/master/polyval/LICENSE-MIT
[powerfmt]: https://github.com/jhpratt/powerfmt
[powerfmt license]: https://github.com/jhpratt/powerfmt/blob/main/LICENSE-MIT
[ppv-lite86]: https://github.com/cryptocorrosion/cryptocorrosion
[ppv-lite86 license]: https://github.com/cryptocorrosion/cryptocorrosion/blob/master/LICENSE-MIT
[prettyplease]: https://github.com/dtolnay/prettyplease
[prettyplease license]: https://github.com/dtolnay/prettyplease/blob/master/LICENSE-MIT
[proc-macro2]: https://github.com/dtolnay/proc-macro2
[proc-macro2 license]: https://github.com/dtolnay/proc-macro2/blob/master/LICENSE-MIT
[pulldown-cmark]: https://github.com/raphlinus/pulldown-cmark
[pulldown-cmark license]: https://github.com/pulldown-cmark/pulldown-cmark/blob/master/LICENSE
[pulldown-cmark-escape]: https://github.com/raphlinus/pulldown-cmark
[pulldown-cmark-escape license]: https://github.com/pulldown-cmark/pulldown-cmark/blob/master/LICENSE
[quote]: https://github.com/dtolnay/quote
[quote license]: https://github.com/dtolnay/quote/blob/master/LICENSE-MIT
[rand]: https://github.com/rust-random/rand
[rand license]: https://github.com/rust-random/rand/blob/master/LICENSE-MIT
[rand_chacha]: https://github.com/rust-random/rand
[rand_chacha license]: https://github.com/rust-random/rand/blob/master/LICENSE-MIT
[rand_core]: https://github.com/rust-random/rand
[rand_core license]: https://github.com/rust-random/rand/blob/master/LICENSE-MIT
[rational]: https://github.com/ijagberg/rational
[rational license]: https://github.com/ijagberg/rational/blob/main/LICENSE
[regex]: https://github.com/rust-lang/regex
[regex license]: https://github.com/rust-lang/regex/blob/master/LICENSE-MIT
[regex-automata]: https://github.com/rust-lang/regex/tree/master/regex-automata
[regex-automata license]: https://github.com/rust-lang/regex/blob/master/LICENSE-MIT
[regex-syntax]: https://github.com/rust-lang/regex/tree/master/regex-syntax
[regex-syntax license]: https://github.com/rust-lang/regex/blob/master/LICENSE-MIT
[reqwest]: https://github.com/seanmonstar/reqwest
[reqwest license]: https://github.com/seanmonstar/reqwest/blob/master/LICENSE-MIT
[ring]: https://github.com/briansmith/ring
[ring license]: https://github.com/briansmith/ring/blob/main/LICENSE
[rot13]: https://github.com/marekventur/rust-rot13
[rot13 license]: https://github.com/marekventur/rust-rot13/blob/master/LICENSE-MIT
[rustc-demangle]: https://github.com/rust-lang/rustc-demangle
[rustc-demangle license]: https://github.com/rust-lang/rustc-demangle/blob/main/LICENSE-MIT
[rustc-hash]: https://github.com/rust-lang/rustc-hash
[rustc-hash license]: https://github.com/rust-lang/rustc-hash/blob/master/LICENSE-MIT
[rustix]: https://github.com/bytecodealliance/rustix
[rustix license]: https://github.com/bytecodealliance/rustix/blob/main/LICENSE-MIT
[rustls]: https://github.com/rustls/rustls
[rustls license]: https://github.com/rustls/rustls/blob/main/LICENSE
[rustls-native-certs]: https://github.com/rustls/rustls-native-certs
[rustls-native-certs license]: https://github.com/rustls/rustls-native-certs/blob/main/LICENSE
[rustls-pemfile]: https://github.com/rustls/pemfile
[rustls-pemfile license]: https://github.com/rustls/pemfile/blob/main/LICENSE
[rustls-webpki]: https://github.com/rustls/webpki
[rustls-webpki license]: https://github.com/rustls/webpki/blob/main/LICENSE
[ruzstd]: https://github.com/KillingSpark/zstd-rs
[ruzstd license]: https://github.com/KillingSpark/zstd-rs/blob/master/LICENSE
[ryu]: https://github.com/dtolnay/ryu
[ryu license]: https://github.com/dtolnay/ryu/blob/master/LICENSE-APACHE
[scroll]: https://github.com/m4b/scroll
[scroll license]: https://github.com/m4b/scroll/blob/master/LICENSE
[sct]: https://github.com/rustls/sct.rs
[sct license]: https://github.com/rustls/sct.rs/blob/main/LICENSE-MIT
[search]: https://github.com/ValuONE/search
[search license]: https://opensource.org/license/mit
[secrets]: https://github.com/stouset/secrets
[secrets license]: https://github.com/stouset/secrets/blob/master/LICENSE-MIT
[security-framework]: https://github.com/kornelski/rust-security-framework
[security-framework license]: https://github.com/kornelski/rust-security-framework/blob/main/LICENSE-MIT
[security-framework-sys]: https://github.com/kornelski/rust-security-framework
[security-framework-sys license]: https://github.com/kornelski/rust-security-framework/blob/main/LICENSE-MIT
[serde]: https://github.com/serde-rs/serde
[serde license]: https://github.com/serde-rs/serde/blob/master/LICENSE-MIT
[serde_derive]: https://github.com/serde-rs/serde
[serde_derive license]: https://github.com/serde-rs/serde/blob/master/LICENSE-MIT
[serde_json]: https://github.com/serde-rs/json
[serde_json license]: https://github.com/serde-rs/json/blob/master/LICENSE-MIT
[serde_repr]: https://github.com/dtolnay/serde-repr
[serde_repr license]: https://github.com/dtolnay/serde-repr/blob/master/LICENSE-MIT
[serde_urlencoded]: https://github.com/nox/serde_urlencoded
[serde_urlencoded license]: https://github.com/nox/serde_urlencoded/blob/master/LICENSE-MIT
[sha1]: https://github.com/RustCrypto/hashes/tree/master/sha1
[sha1 license]: https://github.com/RustCrypto/hashes/blob/master/sha1/LICENSE-MIT
[shlex]: https://github.com/comex/rust-shlex
[shlex license]: https://github.com/comex/rust-shlex/blob/master/LICENSE-MIT
[slab]: https://github.com/tokio-rs/slab
[slab license]: https://github.com/tokio-rs/slab/blob/master/LICENSE
[smallvec]: https://github.com/servo/rust-smallvec
[smallvec license]: https://github.com/servo/rust-smallvec/blob/v2/LICENSE-MIT
[socket2]: https://github.com/rust-lang/socket2
[socket2 license]: https://github.com/rust-lang/socket2/blob/master/LICENSE-MIT
[spin]: https://github.com/mvdnes/spin-rs
[spin license]: https://github.com/mvdnes/spin-rs/blob/master/LICENSE
[stable_deref_trait]: https://github.com/storyyeller/stable_deref_trait
[stable_deref_trait license]: https://github.com/Storyyeller/stable_deref_trait/blob/master/LICENSE-MIT
[static_assertions]: https://github.com/nvzqz/static-assertions-rs
[static_assertions license]: https://github.com/nvzqz/static-assertions/blob/master/LICENSE-MIT
[strsim]: https://github.com/rapidfuzz/strsim-rs
[strsim license]: https://github.com/rapidfuzz/strsim-rs/blob/main/LICENSE
[subtle]: https://github.com/dalek-cryptography/subtle
[subtle license]: https://github.com/dalek-cryptography/subtle/blob/main/LICENSE
[syn]: https://github.com/dtolnay/syn
[syn license]: https://github.com/dtolnay/syn/blob/master/LICENSE-MIT
[synstructure]: https://github.com/mystor/synstructure
[synstructure license]: https://github.com/mystor/synstructure/blob/main/LICENSE
[sync_wrapper]: https://github.com/Actyx/sync_wrapper
[sync_wrapper license]: https://github.com/Actyx/sync_wrapper/blob/master/LICENSE
[system-configuration]: https://github.com/mullvad/system-configuration-rs
[system-configuration license]: https://github.com/mullvad/system-configuration-rs/blob/main/system-configuration/LICENSE-MIT
[system-configuration-sys]: https://github.com/mullvad/system-configuration-rs
[system-configuration-sys license]: https://github.com/mullvad/system-configuration-rs/blob/main/system-configuration-sys/LICENSE-MIT
[thiserror]: https://github.com/dtolnay/thiserror
[thiserror license]: https://github.com/dtolnay/thiserror/blob/master/LICENSE-MIT
[thiserror-impl]: https://github.com/dtolnay/thiserror/tree/master/impl
[thiserror-impl license]: https://github.com/dtolnay/thiserror/blob/master/LICENSE-MIT
[time]: https://github.com/time-rs/time
[time license]: https://github.com/time-rs/time/blob/main/LICENSE-MIT
[time-core]: https://github.com/time-rs/time
[time-core license]: https://github.com/time-rs/time/blob/main/LICENSE-MIT
[tinystr]: https://github.com/unicode-org/icu4x
[tinystr license]: https://github.com/unicode-org/icu4x/blob/main/LICENSE
[tinyvec]: https://github.com/Lokathor/tinyvec
[tinyvec license]: https://github.com/Lokathor/tinyvec/blob/main/LICENSE-MIT.md
[tinyvec_macros]: https://github.com/Soveu/tinyvec_macros
[tinyvec_macros license]: https://github.com/Soveu/tinyvec_macros/blob/master/LICENSE-MIT.md
[tokio]: https://github.com/tokio-rs/tokio
[tokio license]: https://github.com/tokio-rs/tokio/blob/master/LICENSE
[tokio-macros]: https://github.com/tokio-rs/tokio/tree/master/tokio-macros
[tokio-macros license]: https://github.com/tokio-rs/tokio/tree/master/tokio-macros/LICENSE
[tokio-rustls]: https://github.com/rustls/tokio-rustls
[tokio-rustls license]: https://github.com/rustls/tokio-rustls/blob/main/LICENSE-MIT
[tokio-tungstenite]: https://github.com/snapview/tokio-tungstenite
[tokio-tungstenite license]: https://github.com/snapview/tokio-tungstenite/blob/master/LICENSE
[tokio-util]: https://github.com/tokio-rs/tokio/tree/master/tokio-util
[tokio-util license]: https://github.com/tokio-rs/tokio/tree/master/tokio-util/LICENSE
[tower-service]: https://github.com/tower-rs/tower
[tower-service license]: https://github.com/tower-rs/tower/blob/master/LICENSE
[tracing]: https://github.com/tokio-rs/tracing
[tracing license]: https://github.com/tokio-rs/tracing/blob/master/LICENSE
[tracing-attributes]: https://github.com/tokio-rs/tracing/tree/master/tracing-attributes
[tracing-attributes license]: https://github.com/tokio-rs/tracing/blob/master/tracing-attributes/LICENSE
[tracing-core]: https://github.com/tokio-rs/tracing/tree/master/tracing-core
[tracing-core license]: https://github.com/tokio-rs/tracing/tree/master/tracing-core/LICENSE
[try-lock]: https://github.com/seanmonstar/try-lock
[try-lock license]: https://github.com/seanmonstar/try-lock/blob/master/LICENSE
[tungstenite]: https://github.com/snapview/tungstenite-rs
[tungstenite license]: https://github.com/snapview/tungstenite-rs/blob/master/LICENSE-MIT
[twox-hash]: https://github.com/shepmaster/twox-hash
[twox-hash license]: https://github.com/shepmaster/twox-hash/blob/main/LICENSE.txt
[typenum]: https://github.com/paholg/typenum
[typenum license]: https://github.com/paholg/typenum/blob/main/LICENSE-MIT
[unicase]: https://github.com/seanmonstar/unicase
[unicase license]: https://github.com/seanmonstar/unicase/blob/master/LICENSE-MIT
[unicode-bidi]: https://github.com/servo/unicode-bidi
[unicode-bidi license]: https://github.com/servo/unicode-bidi/blob/main/LICENSE-MIT
[unicode-ident]: https://github.com/dtolnay/unicode-ident
[unicode-ident license]: https://github.com/dtolnay/unicode-ident/blob/master/LICENSE-MIT
[unicode-normalization]: https://github.com/unicode-rs/unicode-normalization
[unicode-normalization license]: https://github.com/unicode-rs/unicode-normalization/blob/master/LICENSE-MIT
[unicode-width]: https://github.com/unicode-rs/unicode-width
[unicode-width license]: https://github.com/unicode-rs/unicode-width/blob/master/LICENSE-MIT
[universal-hash]: https://github.com/RustCrypto/traits/tree/master/universal-hash
[universal-hash license]: https://github.com/RustCrypto/traits/blob/master/universal-hash/LICENSE-MIT
[untrusted]: https://github.com/briansmith/untrusted
[untrusted license]: https://github.com/briansmith/untrusted/blob/main/LICENSE.txt
[url]: https://github.com/servo/rust-url
[url license]: https://github.com/servo/rust-url/blob/main/LICENSE-MIT
[utf-8]: https://github.com/SimonSapin/rust-utf8
[utf-8 license]: https://github.com/SimonSapin/rust-utf8/blob/master/LICENSE-MIT
[utf16_iter]: https://github.com/hsivonen/utf16_iter
[utf16_iter license]: https://github.com/hsivonen/utf16_iter/blob/main/LICENSE-MIT
[utf8_iter]: https://github.com/hsivonen/utf8_iter
[utf8_iter license]: https://github.com/hsivonen/utf8_iter/blob/main/LICENSE-MIT
[utf8parse]: https://github.com/alacritty/vte
[utf8parse license]: https://github.com/alacritty/vte/blob/master/LICENSE-MIT
[uuid]: https://github.com/uuid-rs/uuid
[uuid license]: https://github.com/uuid-rs/uuid/blob/main/LICENSE-MIT
[vcpkg]: https://github.com/mcgoo/vcpkg-rs
[vcpkg license]: https://github.com/mcgoo/vcpkg-rs/blob/master/LICENSE-MIT
[version_check]: https://github.com/SergioBenitez/version_check
[version_check license]: https://github.com/SergioBenitez/version_check/blob/master/LICENSE-MIT
[want]: https://github.com/seanmonstar/want
[want license]: https://github.com/seanmonstar/want/blob/master/LICENSE
[webpki]: https://github.com/briansmith/webpki
[webpki license]: https://github.com/briansmith/webpki/blob/main/LICENSE
[webpki-roots]: https://github.com/rustls/webpki-roots
[webpki-roots license]: https://github.com/rustls/webpki-roots/blob/main/webpki-roots/LICENSE
[websocket]: https://github.com/websockets-rs/rust-websocket
[websocket license]: https://github.com/websockets-rs/rust-websocket/blob/master/LICENSE
[write16]: https://github.com/hsivonen/write16
[write16 license]: https://github.com/hsivonen/write16/blob/main/LICENSE-MIT
[writeable]: https://github.com/unicode-org/icu4x
[writeable license]: https://github.com/unicode-org/icu4x/blob/main/utils/writeable/LICENSE
[which]: https://github.com/harryfei/which-rs
[which license]: https://github.com/harryfei/which-rs/blob/master/LICENSE.txt
[x509-signature]: https://github.com/paritytech/x509-signature
[x509-signature license]: https://github.com/paritytech/x509-signature/blob/master/LICENSE-MIT
[yoke]: https://github.com/unicode-org/icu4x
[yoke license]: https://github.com/unicode-org/icu4x/blob/main/utils/yoke/LICENSE
[zerocopy]: https://github.com/google/zerocopy
[zerocopy license]: https://github.com/google/zerocopy/blob/main/LICENSE-MIT
[zerofrom]: https://github.com/unicode-org/icu4x
[zerofrom license]: https://github.com/unicode-org/icu4x/blob/main/utils/zerofrom/LICENSE
[zerovec]: https://github.com/unicode-org/icu4x
[zerovec license]: https://github.com/unicode-org/icu4x/blob/main/utils/zerovec/LICENSE
