from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class PsxTim(KaitaiStruct):

    class BppType(Enum):
        bpp_4 = 0
        bpp_8 = 1
        bpp_16 = 2
        bpp_24 = 3
    SEQ_FIELDS = ["magic", "flags", "clut", "img"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x10\x00\x00\x00")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._io.read_u4le()
        self._debug['flags']['end'] = self._io.pos()
        if self.has_clut:
            self._debug['clut']['start'] = self._io.pos()
            self.clut = self._root.Bitmap(self._io, self, self._root)
            self.clut._read()
            self._debug['clut']['end'] = self._io.pos()

        self._debug['img']['start'] = self._io.pos()
        self.img = self._root.Bitmap(self._io, self, self._root)
        self.img._read()
        self._debug['img']['end'] = self._io.pos()

    class Bitmap(KaitaiStruct):
        SEQ_FIELDS = ["len", "origin_x", "origin_y", "width", "height", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u4le()
            self._debug['len']['end'] = self._io.pos()
            self._debug['origin_x']['start'] = self._io.pos()
            self.origin_x = self._io.read_u2le()
            self._debug['origin_x']['end'] = self._io.pos()
            self._debug['origin_y']['start'] = self._io.pos()
            self.origin_y = self._io.read_u2le()
            self._debug['origin_y']['end'] = self._io.pos()
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u2le()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u2le()
            self._debug['height']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes((self.len - 12))
            self._debug['body']['end'] = self._io.pos()


    @property
    def has_clut(self):
        if hasattr(self, '_m_has_clut'):
            return self._m_has_clut if hasattr(self, '_m_has_clut') else None

        self._m_has_clut = (self.flags & 8) != 0
        return self._m_has_clut if hasattr(self, '_m_has_clut') else None

    @property
    def bpp(self):
        if hasattr(self, '_m_bpp'):
            return self._m_bpp if hasattr(self, '_m_bpp') else None

        self._m_bpp = (self.flags & 3)
        return self._m_bpp if hasattr(self, '_m_bpp') else None


