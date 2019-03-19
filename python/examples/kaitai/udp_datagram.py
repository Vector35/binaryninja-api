# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class UdpDatagram(KaitaiStruct):
    """UDP is a simple stateless transport layer (AKA OSI layer 4)
    protocol, one of the core Internet protocols. It provides source and
    destination ports, basic checksumming, but provides not guarantees
    of delivery, order of packets, or duplicate delivery.
    """
    SEQ_FIELDS = ["src_port", "dst_port", "length", "checksum", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['src_port']['start'] = self._io.pos()
        self.src_port = self._io.read_u2be()
        self._debug['src_port']['end'] = self._io.pos()
        self._debug['dst_port']['start'] = self._io.pos()
        self.dst_port = self._io.read_u2be()
        self._debug['dst_port']['end'] = self._io.pos()
        self._debug['length']['start'] = self._io.pos()
        self.length = self._io.read_u2be()
        self._debug['length']['end'] = self._io.pos()
        self._debug['checksum']['start'] = self._io.pos()
        self.checksum = self._io.read_u2be()
        self._debug['checksum']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        self.body = self._io.read_bytes_full()
        self._debug['body']['end'] = self._io.pos()


