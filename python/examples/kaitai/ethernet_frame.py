# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from . import ipv4_packet
from . import ipv6_packet
class EthernetFrame(KaitaiStruct):
    """Ethernet frame is a OSI data link layer (layer 2) protocol data unit
    for Ethernet networks. In practice, many other networks and/or
    in-file dumps adopted the same format for encapsulation purposes.
    
    .. seealso::
       Source - https://ieeexplore.ieee.org/document/7428776
    """

    class EtherTypeEnum(Enum):
        ipv4 = 2048
        x_75_internet = 2049
        nbs_internet = 2050
        ecma_internet = 2051
        chaosnet = 2052
        x_25_level_3 = 2053
        arp = 2054
        ipv6 = 34525
    SEQ_FIELDS = ["dst_mac", "src_mac", "ether_type", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['dst_mac']['start'] = self._io.pos()
        self.dst_mac = self._io.read_bytes(6)
        self._debug['dst_mac']['end'] = self._io.pos()
        self._debug['src_mac']['start'] = self._io.pos()
        self.src_mac = self._io.read_bytes(6)
        self._debug['src_mac']['end'] = self._io.pos()
        self._debug['ether_type']['start'] = self._io.pos()
        self.ether_type = KaitaiStream.resolve_enum(self._root.EtherTypeEnum, self._io.read_u2be())
        self._debug['ether_type']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        _on = self.ether_type
        if _on == self._root.EtherTypeEnum.ipv4:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = ipv4_packet.Ipv4Packet(io)
            self.body._read()
        elif _on == self._root.EtherTypeEnum.ipv6:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = ipv6_packet.Ipv6Packet(io)
            self.body._read()
        else:
            self.body = self._io.read_bytes_full()
        self._debug['body']['end'] = self._io.pos()


