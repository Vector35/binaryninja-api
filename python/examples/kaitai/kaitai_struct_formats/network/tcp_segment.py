from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class TcpSegment(KaitaiStruct):
    """TCP is one of the core Internet protocols on transport layer (AKA
    OSI layer 4), providing stateful connections with error checking,
    guarantees of delivery, order of segments and avoidance of duplicate
    delivery.
    """
    SEQ_FIELDS = ["src_port", "dst_port", "seq_num", "ack_num", "b12", "b13", "window_size", "checksum", "urgent_pointer", "body"]
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
        self._debug['seq_num']['start'] = self._io.pos()
        self.seq_num = self._io.read_u4be()
        self._debug['seq_num']['end'] = self._io.pos()
        self._debug['ack_num']['start'] = self._io.pos()
        self.ack_num = self._io.read_u4be()
        self._debug['ack_num']['end'] = self._io.pos()
        self._debug['b12']['start'] = self._io.pos()
        self.b12 = self._io.read_u1()
        self._debug['b12']['end'] = self._io.pos()
        self._debug['b13']['start'] = self._io.pos()
        self.b13 = self._io.read_u1()
        self._debug['b13']['end'] = self._io.pos()
        self._debug['window_size']['start'] = self._io.pos()
        self.window_size = self._io.read_u2be()
        self._debug['window_size']['end'] = self._io.pos()
        self._debug['checksum']['start'] = self._io.pos()
        self.checksum = self._io.read_u2be()
        self._debug['checksum']['end'] = self._io.pos()
        self._debug['urgent_pointer']['start'] = self._io.pos()
        self.urgent_pointer = self._io.read_u2be()
        self._debug['urgent_pointer']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        self.body = self._io.read_bytes_full()
        self._debug['body']['end'] = self._io.pos()


