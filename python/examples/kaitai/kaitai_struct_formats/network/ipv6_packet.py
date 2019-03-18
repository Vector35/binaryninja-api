from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from protocol_body import ProtocolBody
class Ipv6Packet(KaitaiStruct):
    SEQ_FIELDS = ["version", "traffic_class", "flow_label", "payload_length", "next_header_type", "hop_limit", "src_ipv6_addr", "dst_ipv6_addr", "next_header", "rest"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_bits_int(4)
        self._debug['version']['end'] = self._io.pos()
        self._debug['traffic_class']['start'] = self._io.pos()
        self.traffic_class = self._io.read_bits_int(8)
        self._debug['traffic_class']['end'] = self._io.pos()
        self._debug['flow_label']['start'] = self._io.pos()
        self.flow_label = self._io.read_bits_int(20)
        self._debug['flow_label']['end'] = self._io.pos()
        self._io.align_to_byte()
        self._debug['payload_length']['start'] = self._io.pos()
        self.payload_length = self._io.read_u2be()
        self._debug['payload_length']['end'] = self._io.pos()
        self._debug['next_header_type']['start'] = self._io.pos()
        self.next_header_type = self._io.read_u1()
        self._debug['next_header_type']['end'] = self._io.pos()
        self._debug['hop_limit']['start'] = self._io.pos()
        self.hop_limit = self._io.read_u1()
        self._debug['hop_limit']['end'] = self._io.pos()
        self._debug['src_ipv6_addr']['start'] = self._io.pos()
        self.src_ipv6_addr = self._io.read_bytes(16)
        self._debug['src_ipv6_addr']['end'] = self._io.pos()
        self._debug['dst_ipv6_addr']['start'] = self._io.pos()
        self.dst_ipv6_addr = self._io.read_bytes(16)
        self._debug['dst_ipv6_addr']['end'] = self._io.pos()
        self._debug['next_header']['start'] = self._io.pos()
        self.next_header = ProtocolBody(self.next_header_type, self._io)
        self.next_header._read()
        self._debug['next_header']['end'] = self._io.pos()
        self._debug['rest']['start'] = self._io.pos()
        self.rest = self._io.read_bytes_full()
        self._debug['rest']['end'] = self._io.pos()


