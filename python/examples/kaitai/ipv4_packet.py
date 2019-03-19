# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from protocol_body import ProtocolBody
class Ipv4Packet(KaitaiStruct):
    SEQ_FIELDS = ["b1", "b2", "total_length", "identification", "b67", "ttl", "protocol", "header_checksum", "src_ip_addr", "dst_ip_addr", "options", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['b1']['start'] = self._io.pos()
        self.b1 = self._io.read_u1()
        self._debug['b1']['end'] = self._io.pos()
        self._debug['b2']['start'] = self._io.pos()
        self.b2 = self._io.read_u1()
        self._debug['b2']['end'] = self._io.pos()
        self._debug['total_length']['start'] = self._io.pos()
        self.total_length = self._io.read_u2be()
        self._debug['total_length']['end'] = self._io.pos()
        self._debug['identification']['start'] = self._io.pos()
        self.identification = self._io.read_u2be()
        self._debug['identification']['end'] = self._io.pos()
        self._debug['b67']['start'] = self._io.pos()
        self.b67 = self._io.read_u2be()
        self._debug['b67']['end'] = self._io.pos()
        self._debug['ttl']['start'] = self._io.pos()
        self.ttl = self._io.read_u1()
        self._debug['ttl']['end'] = self._io.pos()
        self._debug['protocol']['start'] = self._io.pos()
        self.protocol = self._io.read_u1()
        self._debug['protocol']['end'] = self._io.pos()
        self._debug['header_checksum']['start'] = self._io.pos()
        self.header_checksum = self._io.read_u2be()
        self._debug['header_checksum']['end'] = self._io.pos()
        self._debug['src_ip_addr']['start'] = self._io.pos()
        self.src_ip_addr = self._io.read_bytes(4)
        self._debug['src_ip_addr']['end'] = self._io.pos()
        self._debug['dst_ip_addr']['start'] = self._io.pos()
        self.dst_ip_addr = self._io.read_bytes(4)
        self._debug['dst_ip_addr']['end'] = self._io.pos()
        self._debug['options']['start'] = self._io.pos()
        self._raw_options = self._io.read_bytes((self.ihl_bytes - 20))
        io = KaitaiStream(BytesIO(self._raw_options))
        self.options = self._root.Ipv4Options(io, self, self._root)
        self.options._read()
        self._debug['options']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        self._raw_body = self._io.read_bytes((self.total_length - self.ihl_bytes))
        io = KaitaiStream(BytesIO(self._raw_body))
        self.body = ProtocolBody(self.protocol, io)
        self.body._read()
        self._debug['body']['end'] = self._io.pos()

    class Ipv4Options(KaitaiStruct):
        SEQ_FIELDS = ["entries"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entries']['start'] = self._io.pos()
            self.entries = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['entries']:
                    self._debug['entries']['arr'] = []
                self._debug['entries']['arr'].append({'start': self._io.pos()})
                _t_entries = self._root.Ipv4Option(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Ipv4Option(KaitaiStruct):
        SEQ_FIELDS = ["b1", "len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['b1']['start'] = self._io.pos()
            self.b1 = self._io.read_u1()
            self._debug['b1']['end'] = self._io.pos()
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u1()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(((self.len - 2) if self.len > 2 else 0))
            self._debug['body']['end'] = self._io.pos()

        @property
        def copy(self):
            if hasattr(self, '_m_copy'):
                return self._m_copy if hasattr(self, '_m_copy') else None

            self._m_copy = ((self.b1 & 128) >> 7)
            return self._m_copy if hasattr(self, '_m_copy') else None

        @property
        def opt_class(self):
            if hasattr(self, '_m_opt_class'):
                return self._m_opt_class if hasattr(self, '_m_opt_class') else None

            self._m_opt_class = ((self.b1 & 96) >> 5)
            return self._m_opt_class if hasattr(self, '_m_opt_class') else None

        @property
        def number(self):
            if hasattr(self, '_m_number'):
                return self._m_number if hasattr(self, '_m_number') else None

            self._m_number = (self.b1 & 31)
            return self._m_number if hasattr(self, '_m_number') else None


    @property
    def version(self):
        if hasattr(self, '_m_version'):
            return self._m_version if hasattr(self, '_m_version') else None

        self._m_version = ((self.b1 & 240) >> 4)
        return self._m_version if hasattr(self, '_m_version') else None

    @property
    def ihl(self):
        if hasattr(self, '_m_ihl'):
            return self._m_ihl if hasattr(self, '_m_ihl') else None

        self._m_ihl = (self.b1 & 15)
        return self._m_ihl if hasattr(self, '_m_ihl') else None

    @property
    def ihl_bytes(self):
        if hasattr(self, '_m_ihl_bytes'):
            return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None

        self._m_ihl_bytes = (self.ihl * 4)
        return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None


