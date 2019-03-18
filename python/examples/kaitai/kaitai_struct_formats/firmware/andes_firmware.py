from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class AndesFirmware(KaitaiStruct):
    """Firmware image found with MediaTek MT76xx wifi chipsets."""
    SEQ_FIELDS = ["image_header", "ilm", "dlm"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['image_header']['start'] = self._io.pos()
        self._raw_image_header = self._io.read_bytes(32)
        io = KaitaiStream(BytesIO(self._raw_image_header))
        self.image_header = self._root.ImageHeader(io, self, self._root)
        self.image_header._read()
        self._debug['image_header']['end'] = self._io.pos()
        self._debug['ilm']['start'] = self._io.pos()
        self.ilm = self._io.read_bytes(self.image_header.ilm_len)
        self._debug['ilm']['end'] = self._io.pos()
        self._debug['dlm']['start'] = self._io.pos()
        self.dlm = self._io.read_bytes(self.image_header.dlm_len)
        self._debug['dlm']['end'] = self._io.pos()

    class ImageHeader(KaitaiStruct):
        SEQ_FIELDS = ["ilm_len", "dlm_len", "fw_ver", "build_ver", "extra", "build_time"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ilm_len']['start'] = self._io.pos()
            self.ilm_len = self._io.read_u4le()
            self._debug['ilm_len']['end'] = self._io.pos()
            self._debug['dlm_len']['start'] = self._io.pos()
            self.dlm_len = self._io.read_u4le()
            self._debug['dlm_len']['end'] = self._io.pos()
            self._debug['fw_ver']['start'] = self._io.pos()
            self.fw_ver = self._io.read_u2le()
            self._debug['fw_ver']['end'] = self._io.pos()
            self._debug['build_ver']['start'] = self._io.pos()
            self.build_ver = self._io.read_u2le()
            self._debug['build_ver']['end'] = self._io.pos()
            self._debug['extra']['start'] = self._io.pos()
            self.extra = self._io.read_u4le()
            self._debug['extra']['end'] = self._io.pos()
            self._debug['build_time']['start'] = self._io.pos()
            self.build_time = (self._io.read_bytes(16)).decode(u"UTF-8")
            self._debug['build_time']['end'] = self._io.pos()



