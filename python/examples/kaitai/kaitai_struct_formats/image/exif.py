from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from exif_le import ExifLe
from exif_be import ExifBe
class Exif(KaitaiStruct):
    SEQ_FIELDS = ["endianness", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['endianness']['start'] = self._io.pos()
        self.endianness = self._io.read_u2le()
        self._debug['endianness']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        _on = self.endianness
        if _on == 18761:
            self.body = ExifLe(self._io)
            self.body._read()
        elif _on == 19789:
            self.body = ExifBe(self._io)
            self.body._read()
        self._debug['body']['end'] = self._io.pos()


