# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Dbf(KaitaiStruct):
    SEQ_FIELDS = ["header1", "header2", "records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header1']['start'] = self._io.pos()
        self.header1 = self._root.Header1(self._io, self, self._root)
        self.header1._read()
        self._debug['header1']['end'] = self._io.pos()
        self._debug['header2']['start'] = self._io.pos()
        self._raw_header2 = self._io.read_bytes((self.header1.len_header - 12))
        io = KaitaiStream(BytesIO(self._raw_header2))
        self.header2 = self._root.Header2(io, self, self._root)
        self.header2._read()
        self._debug['header2']['end'] = self._io.pos()
        self._debug['records']['start'] = self._io.pos()
        self.records = [None] * (self.header1.num_records)
        for i in range(self.header1.num_records):
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            self.records[i] = self._io.read_bytes(self.header1.len_record)
            self._debug['records']['arr'][i]['end'] = self._io.pos()

        self._debug['records']['end'] = self._io.pos()

    class Header2(KaitaiStruct):
        SEQ_FIELDS = ["header_dbase_3", "header_dbase_7", "fields"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if self._root.header1.dbase_level == 3:
                self._debug['header_dbase_3']['start'] = self._io.pos()
                self.header_dbase_3 = self._root.HeaderDbase3(self._io, self, self._root)
                self.header_dbase_3._read()
                self._debug['header_dbase_3']['end'] = self._io.pos()

            if self._root.header1.dbase_level == 7:
                self._debug['header_dbase_7']['start'] = self._io.pos()
                self.header_dbase_7 = self._root.HeaderDbase7(self._io, self, self._root)
                self.header_dbase_7._read()
                self._debug['header_dbase_7']['end'] = self._io.pos()

            self._debug['fields']['start'] = self._io.pos()
            self.fields = [None] * (11)
            for i in range(11):
                if not 'arr' in self._debug['fields']:
                    self._debug['fields']['arr'] = []
                self._debug['fields']['arr'].append({'start': self._io.pos()})
                _t_fields = self._root.Field(self._io, self, self._root)
                _t_fields._read()
                self.fields[i] = _t_fields
                self._debug['fields']['arr'][i]['end'] = self._io.pos()

            self._debug['fields']['end'] = self._io.pos()


    class Field(KaitaiStruct):
        SEQ_FIELDS = ["name", "datatype", "data_address", "length", "decimal_count", "reserved1", "work_area_id", "reserved2", "set_fields_flag", "reserved3"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(11)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()
            self._debug['datatype']['start'] = self._io.pos()
            self.datatype = self._io.read_u1()
            self._debug['datatype']['end'] = self._io.pos()
            self._debug['data_address']['start'] = self._io.pos()
            self.data_address = self._io.read_u4le()
            self._debug['data_address']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u1()
            self._debug['length']['end'] = self._io.pos()
            self._debug['decimal_count']['start'] = self._io.pos()
            self.decimal_count = self._io.read_u1()
            self._debug['decimal_count']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bytes(2)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['work_area_id']['start'] = self._io.pos()
            self.work_area_id = self._io.read_u1()
            self._debug['work_area_id']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bytes(2)
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['set_fields_flag']['start'] = self._io.pos()
            self.set_fields_flag = self._io.read_u1()
            self._debug['set_fields_flag']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.read_bytes(8)
            self._debug['reserved3']['end'] = self._io.pos()


    class Header1(KaitaiStruct):
        """
        .. seealso::
           - section 1.1 - http://www.dbase.com/Knowledgebase/INT/db7_file_fmt.htm
        """
        SEQ_FIELDS = ["version", "last_update_y", "last_update_m", "last_update_d", "num_records", "len_header", "len_record"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            self._debug['last_update_y']['start'] = self._io.pos()
            self.last_update_y = self._io.read_u1()
            self._debug['last_update_y']['end'] = self._io.pos()
            self._debug['last_update_m']['start'] = self._io.pos()
            self.last_update_m = self._io.read_u1()
            self._debug['last_update_m']['end'] = self._io.pos()
            self._debug['last_update_d']['start'] = self._io.pos()
            self.last_update_d = self._io.read_u1()
            self._debug['last_update_d']['end'] = self._io.pos()
            self._debug['num_records']['start'] = self._io.pos()
            self.num_records = self._io.read_u4le()
            self._debug['num_records']['end'] = self._io.pos()
            self._debug['len_header']['start'] = self._io.pos()
            self.len_header = self._io.read_u2le()
            self._debug['len_header']['end'] = self._io.pos()
            self._debug['len_record']['start'] = self._io.pos()
            self.len_record = self._io.read_u2le()
            self._debug['len_record']['end'] = self._io.pos()

        @property
        def dbase_level(self):
            if hasattr(self, '_m_dbase_level'):
                return self._m_dbase_level if hasattr(self, '_m_dbase_level') else None

            self._m_dbase_level = (self.version & 7)
            return self._m_dbase_level if hasattr(self, '_m_dbase_level') else None


    class HeaderDbase3(KaitaiStruct):
        SEQ_FIELDS = ["reserved1", "reserved2", "reserved3"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bytes(3)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bytes(13)
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.read_bytes(4)
            self._debug['reserved3']['end'] = self._io.pos()


    class HeaderDbase7(KaitaiStruct):
        SEQ_FIELDS = ["reserved1", "has_incomplete_transaction", "dbase_iv_encryption", "reserved2", "production_mdx", "language_driver_id", "reserved3", "language_driver_name", "reserved4"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.ensure_fixed_contents(b"\x00\x00")
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['has_incomplete_transaction']['start'] = self._io.pos()
            self.has_incomplete_transaction = self._io.read_u1()
            self._debug['has_incomplete_transaction']['end'] = self._io.pos()
            self._debug['dbase_iv_encryption']['start'] = self._io.pos()
            self.dbase_iv_encryption = self._io.read_u1()
            self._debug['dbase_iv_encryption']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bytes(12)
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['production_mdx']['start'] = self._io.pos()
            self.production_mdx = self._io.read_u1()
            self._debug['production_mdx']['end'] = self._io.pos()
            self._debug['language_driver_id']['start'] = self._io.pos()
            self.language_driver_id = self._io.read_u1()
            self._debug['language_driver_id']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.ensure_fixed_contents(b"\x00\x00")
            self._debug['reserved3']['end'] = self._io.pos()
            self._debug['language_driver_name']['start'] = self._io.pos()
            self.language_driver_name = self._io.read_bytes(32)
            self._debug['language_driver_name']['end'] = self._io.pos()
            self._debug['reserved4']['start'] = self._io.pos()
            self.reserved4 = self._io.read_bytes(4)
            self._debug['reserved4']['end'] = self._io.pos()



