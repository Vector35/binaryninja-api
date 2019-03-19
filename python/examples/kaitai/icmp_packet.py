# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class IcmpPacket(KaitaiStruct):

    class IcmpTypeEnum(Enum):
        echo_reply = 0
        destination_unreachable = 3
        source_quench = 4
        redirect = 5
        echo = 8
        time_exceeded = 11
    SEQ_FIELDS = ["icmp_type", "destination_unreachable", "time_exceeded", "echo"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['icmp_type']['start'] = self._io.pos()
        self.icmp_type = KaitaiStream.resolve_enum(self._root.IcmpTypeEnum, self._io.read_u1())
        self._debug['icmp_type']['end'] = self._io.pos()
        if self.icmp_type == self._root.IcmpTypeEnum.destination_unreachable:
            self._debug['destination_unreachable']['start'] = self._io.pos()
            self.destination_unreachable = self._root.DestinationUnreachableMsg(self._io, self, self._root)
            self.destination_unreachable._read()
            self._debug['destination_unreachable']['end'] = self._io.pos()

        if self.icmp_type == self._root.IcmpTypeEnum.time_exceeded:
            self._debug['time_exceeded']['start'] = self._io.pos()
            self.time_exceeded = self._root.TimeExceededMsg(self._io, self, self._root)
            self.time_exceeded._read()
            self._debug['time_exceeded']['end'] = self._io.pos()

        if  ((self.icmp_type == self._root.IcmpTypeEnum.echo) or (self.icmp_type == self._root.IcmpTypeEnum.echo_reply)) :
            self._debug['echo']['start'] = self._io.pos()
            self.echo = self._root.EchoMsg(self._io, self, self._root)
            self.echo._read()
            self._debug['echo']['end'] = self._io.pos()


    class DestinationUnreachableMsg(KaitaiStruct):

        class DestinationUnreachableCode(Enum):
            net_unreachable = 0
            host_unreachable = 1
            protocol_unreachable = 2
            port_unreachable = 3
            fragmentation_needed_and_df_set = 4
            source_route_failed = 5
            dst_net_unkown = 6
            sdt_host_unkown = 7
            src_isolated = 8
            net_prohibited_by_admin = 9
            host_prohibited_by_admin = 10
            net_unreachable_for_tos = 11
            host_unreachable_for_tos = 12
            communication_prohibited_by_admin = 13
            host_precedence_violation = 14
            precedence_cuttoff_in_effect = 15
        SEQ_FIELDS = ["code", "checksum"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = KaitaiStream.resolve_enum(self._root.DestinationUnreachableMsg.DestinationUnreachableCode, self._io.read_u1())
            self._debug['code']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u2be()
            self._debug['checksum']['end'] = self._io.pos()


    class TimeExceededMsg(KaitaiStruct):

        class TimeExceededCode(Enum):
            time_to_live_exceeded_in_transit = 0
            fragment_reassembly_time_exceeded = 1
        SEQ_FIELDS = ["code", "checksum"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = KaitaiStream.resolve_enum(self._root.TimeExceededMsg.TimeExceededCode, self._io.read_u1())
            self._debug['code']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u2be()
            self._debug['checksum']['end'] = self._io.pos()


    class EchoMsg(KaitaiStruct):
        SEQ_FIELDS = ["code", "checksum", "identifier", "seq_num", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = self._io.ensure_fixed_contents(b"\x00")
            self._debug['code']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u2be()
            self._debug['checksum']['end'] = self._io.pos()
            self._debug['identifier']['start'] = self._io.pos()
            self.identifier = self._io.read_u2be()
            self._debug['identifier']['end'] = self._io.pos()
            self._debug['seq_num']['start'] = self._io.pos()
            self.seq_num = self._io.read_u2be()
            self._debug['seq_num']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes_full()
            self._debug['data']['end'] = self._io.pos()



