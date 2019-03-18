from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class DnsPacket(KaitaiStruct):
    """(No support for Auth-Name + Add-Name for simplicity)
    """

    class ClassType(Enum):
        in_class = 1
        cs = 2
        ch = 3
        hs = 4

    class TypeType(Enum):
        a = 1
        ns = 2
        md = 3
        mf = 4
        cname = 5
        soe = 6
        mb = 7
        mg = 8
        mr = 9
        null = 10
        wks = 11
        ptr = 12
        hinfo = 13
        minfo = 14
        mx = 15
        txt = 16
    SEQ_FIELDS = ["transaction_id", "flags", "qdcount", "ancount", "nscount", "arcount", "queries", "answers"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['transaction_id']['start'] = self._io.pos()
        self.transaction_id = self._io.read_u2be()
        self._debug['transaction_id']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._root.PacketFlags(self._io, self, self._root)
        self.flags._read()
        self._debug['flags']['end'] = self._io.pos()
        self._debug['qdcount']['start'] = self._io.pos()
        self.qdcount = self._io.read_u2be()
        self._debug['qdcount']['end'] = self._io.pos()
        self._debug['ancount']['start'] = self._io.pos()
        self.ancount = self._io.read_u2be()
        self._debug['ancount']['end'] = self._io.pos()
        self._debug['nscount']['start'] = self._io.pos()
        self.nscount = self._io.read_u2be()
        self._debug['nscount']['end'] = self._io.pos()
        self._debug['arcount']['start'] = self._io.pos()
        self.arcount = self._io.read_u2be()
        self._debug['arcount']['end'] = self._io.pos()
        self._debug['queries']['start'] = self._io.pos()
        self.queries = [None] * (self.qdcount)
        for i in range(self.qdcount):
            if not 'arr' in self._debug['queries']:
                self._debug['queries']['arr'] = []
            self._debug['queries']['arr'].append({'start': self._io.pos()})
            _t_queries = self._root.Query(self._io, self, self._root)
            _t_queries._read()
            self.queries[i] = _t_queries
            self._debug['queries']['arr'][i]['end'] = self._io.pos()

        self._debug['queries']['end'] = self._io.pos()
        self._debug['answers']['start'] = self._io.pos()
        self.answers = [None] * (self.ancount)
        for i in range(self.ancount):
            if not 'arr' in self._debug['answers']:
                self._debug['answers']['arr'] = []
            self._debug['answers']['arr'].append({'start': self._io.pos()})
            _t_answers = self._root.Answer(self._io, self, self._root)
            _t_answers._read()
            self.answers[i] = _t_answers
            self._debug['answers']['arr'][i]['end'] = self._io.pos()

        self._debug['answers']['end'] = self._io.pos()

    class PointerStruct(KaitaiStruct):
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_u1()
            self._debug['value']['end'] = self._io.pos()

        @property
        def contents(self):
            if hasattr(self, '_m_contents'):
                return self._m_contents if hasattr(self, '_m_contents') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.value)
            self._debug['_m_contents']['start'] = io.pos()
            self._m_contents = self._root.DomainName(io, self, self._root)
            self._m_contents._read()
            self._debug['_m_contents']['end'] = io.pos()
            io.seek(_pos)
            return self._m_contents if hasattr(self, '_m_contents') else None


    class Label(KaitaiStruct):
        SEQ_FIELDS = ["length", "pointer", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u1()
            self._debug['length']['end'] = self._io.pos()
            if self.is_pointer:
                self._debug['pointer']['start'] = self._io.pos()
                self.pointer = self._root.PointerStruct(self._io, self, self._root)
                self.pointer._read()
                self._debug['pointer']['end'] = self._io.pos()

            if not (self.is_pointer):
                self._debug['name']['start'] = self._io.pos()
                self.name = (self._io.read_bytes(self.length)).decode(u"ASCII")
                self._debug['name']['end'] = self._io.pos()


        @property
        def is_pointer(self):
            if hasattr(self, '_m_is_pointer'):
                return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None

            self._m_is_pointer = self.length == 192
            return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None


    class Query(KaitaiStruct):
        SEQ_FIELDS = ["name", "type", "query_class"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.DomainName(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.TypeType, self._io.read_u2be())
            self._debug['type']['end'] = self._io.pos()
            self._debug['query_class']['start'] = self._io.pos()
            self.query_class = KaitaiStream.resolve_enum(self._root.ClassType, self._io.read_u2be())
            self._debug['query_class']['end'] = self._io.pos()


    class DomainName(KaitaiStruct):
        SEQ_FIELDS = ["name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = []
            i = 0
            while True:
                if not 'arr' in self._debug['name']:
                    self._debug['name']['arr'] = []
                self._debug['name']['arr'].append({'start': self._io.pos()})
                _t_name = self._root.Label(self._io, self, self._root)
                _t_name._read()
                _ = _t_name
                self.name.append(_)
                self._debug['name']['arr'][len(self.name) - 1]['end'] = self._io.pos()
                if  ((_.length == 0) or (_.length == 192)) :
                    break
                i += 1
            self._debug['name']['end'] = self._io.pos()


    class Address(KaitaiStruct):
        SEQ_FIELDS = ["ip"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ip']['start'] = self._io.pos()
            self.ip = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['ip']:
                    self._debug['ip']['arr'] = []
                self._debug['ip']['arr'].append({'start': self._io.pos()})
                self.ip[i] = self._io.read_u1()
                self._debug['ip']['arr'][i]['end'] = self._io.pos()

            self._debug['ip']['end'] = self._io.pos()


    class Answer(KaitaiStruct):
        SEQ_FIELDS = ["name", "type", "answer_class", "ttl", "rdlength", "ptrdname", "address"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.DomainName(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.TypeType, self._io.read_u2be())
            self._debug['type']['end'] = self._io.pos()
            self._debug['answer_class']['start'] = self._io.pos()
            self.answer_class = KaitaiStream.resolve_enum(self._root.ClassType, self._io.read_u2be())
            self._debug['answer_class']['end'] = self._io.pos()
            self._debug['ttl']['start'] = self._io.pos()
            self.ttl = self._io.read_s4be()
            self._debug['ttl']['end'] = self._io.pos()
            self._debug['rdlength']['start'] = self._io.pos()
            self.rdlength = self._io.read_u2be()
            self._debug['rdlength']['end'] = self._io.pos()
            if self.type == self._root.TypeType.ptr:
                self._debug['ptrdname']['start'] = self._io.pos()
                self.ptrdname = self._root.DomainName(self._io, self, self._root)
                self.ptrdname._read()
                self._debug['ptrdname']['end'] = self._io.pos()

            if self.type == self._root.TypeType.a:
                self._debug['address']['start'] = self._io.pos()
                self.address = self._root.Address(self._io, self, self._root)
                self.address._read()
                self._debug['address']['end'] = self._io.pos()



    class PacketFlags(KaitaiStruct):
        SEQ_FIELDS = ["flag"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flag']['start'] = self._io.pos()
            self.flag = self._io.read_u2be()
            self._debug['flag']['end'] = self._io.pos()

        @property
        def qr(self):
            if hasattr(self, '_m_qr'):
                return self._m_qr if hasattr(self, '_m_qr') else None

            self._m_qr = ((self.flag & 32768) >> 15)
            return self._m_qr if hasattr(self, '_m_qr') else None

        @property
        def ra(self):
            if hasattr(self, '_m_ra'):
                return self._m_ra if hasattr(self, '_m_ra') else None

            self._m_ra = ((self.flag & 128) >> 7)
            return self._m_ra if hasattr(self, '_m_ra') else None

        @property
        def tc(self):
            if hasattr(self, '_m_tc'):
                return self._m_tc if hasattr(self, '_m_tc') else None

            self._m_tc = ((self.flag & 512) >> 9)
            return self._m_tc if hasattr(self, '_m_tc') else None

        @property
        def rcode(self):
            if hasattr(self, '_m_rcode'):
                return self._m_rcode if hasattr(self, '_m_rcode') else None

            self._m_rcode = ((self.flag & 15) >> 0)
            return self._m_rcode if hasattr(self, '_m_rcode') else None

        @property
        def opcode(self):
            if hasattr(self, '_m_opcode'):
                return self._m_opcode if hasattr(self, '_m_opcode') else None

            self._m_opcode = ((self.flag & 30720) >> 11)
            return self._m_opcode if hasattr(self, '_m_opcode') else None

        @property
        def aa(self):
            if hasattr(self, '_m_aa'):
                return self._m_aa if hasattr(self, '_m_aa') else None

            self._m_aa = ((self.flag & 1024) >> 10)
            return self._m_aa if hasattr(self, '_m_aa') else None

        @property
        def z(self):
            if hasattr(self, '_m_z'):
                return self._m_z if hasattr(self, '_m_z') else None

            self._m_z = ((self.flag & 64) >> 6)
            return self._m_z if hasattr(self, '_m_z') else None

        @property
        def rd(self):
            if hasattr(self, '_m_rd'):
                return self._m_rd if hasattr(self, '_m_rd') else None

            self._m_rd = ((self.flag & 256) >> 8)
            return self._m_rd if hasattr(self, '_m_rd') else None

        @property
        def cd(self):
            if hasattr(self, '_m_cd'):
                return self._m_cd if hasattr(self, '_m_cd') else None

            self._m_cd = ((self.flag & 16) >> 4)
            return self._m_cd if hasattr(self, '_m_cd') else None

        @property
        def ad(self):
            if hasattr(self, '_m_ad'):
                return self._m_ad if hasattr(self, '_m_ad') else None

            self._m_ad = ((self.flag & 32) >> 5)
            return self._m_ad if hasattr(self, '_m_ad') else None



