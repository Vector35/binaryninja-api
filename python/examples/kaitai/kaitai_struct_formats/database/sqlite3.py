from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from vlq_base128_be import VlqBase128Be
class Sqlite3(KaitaiStruct):
    """SQLite3 is a popular serverless SQL engine, implemented as a library
    to be used within other applications. It keeps its databases as
    regular disk files.
    
    Every database file is segmented into pages. First page (starting at
    the very beginning) is special: it contains a file-global header
    which specifies some data relevant to proper parsing (i.e. format
    versions, size of page, etc). After the header, normal contents of
    the first page follow.
    
    Each page would be of some type, and generally, they would be
    reached via the links starting from the first page. First page type
    (`root_page`) is always "btree_page".
    
    .. seealso::
       Source - https://www.sqlite.org/fileformat.html
    """

    class Versions(Enum):
        legacy = 1
        wal = 2

    class Encodings(Enum):
        utf_8 = 1
        utf_16le = 2
        utf_16be = 3
    SEQ_FIELDS = ["magic", "len_page_mod", "write_version", "read_version", "reserved_space", "max_payload_frac", "min_payload_frac", "leaf_payload_frac", "file_change_counter", "num_pages", "first_freelist_trunk_page", "num_freelist_pages", "schema_cookie", "schema_format", "def_page_cache_size", "largest_root_page", "text_encoding", "user_version", "is_incremental_vacuum", "application_id", "reserved", "version_valid_for", "sqlite_version_number", "root_page"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['len_page_mod']['start'] = self._io.pos()
        self.len_page_mod = self._io.read_u2be()
        self._debug['len_page_mod']['end'] = self._io.pos()
        self._debug['write_version']['start'] = self._io.pos()
        self.write_version = KaitaiStream.resolve_enum(self._root.Versions, self._io.read_u1())
        self._debug['write_version']['end'] = self._io.pos()
        self._debug['read_version']['start'] = self._io.pos()
        self.read_version = KaitaiStream.resolve_enum(self._root.Versions, self._io.read_u1())
        self._debug['read_version']['end'] = self._io.pos()
        self._debug['reserved_space']['start'] = self._io.pos()
        self.reserved_space = self._io.read_u1()
        self._debug['reserved_space']['end'] = self._io.pos()
        self._debug['max_payload_frac']['start'] = self._io.pos()
        self.max_payload_frac = self._io.read_u1()
        self._debug['max_payload_frac']['end'] = self._io.pos()
        self._debug['min_payload_frac']['start'] = self._io.pos()
        self.min_payload_frac = self._io.read_u1()
        self._debug['min_payload_frac']['end'] = self._io.pos()
        self._debug['leaf_payload_frac']['start'] = self._io.pos()
        self.leaf_payload_frac = self._io.read_u1()
        self._debug['leaf_payload_frac']['end'] = self._io.pos()
        self._debug['file_change_counter']['start'] = self._io.pos()
        self.file_change_counter = self._io.read_u4be()
        self._debug['file_change_counter']['end'] = self._io.pos()
        self._debug['num_pages']['start'] = self._io.pos()
        self.num_pages = self._io.read_u4be()
        self._debug['num_pages']['end'] = self._io.pos()
        self._debug['first_freelist_trunk_page']['start'] = self._io.pos()
        self.first_freelist_trunk_page = self._io.read_u4be()
        self._debug['first_freelist_trunk_page']['end'] = self._io.pos()
        self._debug['num_freelist_pages']['start'] = self._io.pos()
        self.num_freelist_pages = self._io.read_u4be()
        self._debug['num_freelist_pages']['end'] = self._io.pos()
        self._debug['schema_cookie']['start'] = self._io.pos()
        self.schema_cookie = self._io.read_u4be()
        self._debug['schema_cookie']['end'] = self._io.pos()
        self._debug['schema_format']['start'] = self._io.pos()
        self.schema_format = self._io.read_u4be()
        self._debug['schema_format']['end'] = self._io.pos()
        self._debug['def_page_cache_size']['start'] = self._io.pos()
        self.def_page_cache_size = self._io.read_u4be()
        self._debug['def_page_cache_size']['end'] = self._io.pos()
        self._debug['largest_root_page']['start'] = self._io.pos()
        self.largest_root_page = self._io.read_u4be()
        self._debug['largest_root_page']['end'] = self._io.pos()
        self._debug['text_encoding']['start'] = self._io.pos()
        self.text_encoding = KaitaiStream.resolve_enum(self._root.Encodings, self._io.read_u4be())
        self._debug['text_encoding']['end'] = self._io.pos()
        self._debug['user_version']['start'] = self._io.pos()
        self.user_version = self._io.read_u4be()
        self._debug['user_version']['end'] = self._io.pos()
        self._debug['is_incremental_vacuum']['start'] = self._io.pos()
        self.is_incremental_vacuum = self._io.read_u4be()
        self._debug['is_incremental_vacuum']['end'] = self._io.pos()
        self._debug['application_id']['start'] = self._io.pos()
        self.application_id = self._io.read_u4be()
        self._debug['application_id']['end'] = self._io.pos()
        self._debug['reserved']['start'] = self._io.pos()
        self.reserved = self._io.read_bytes(20)
        self._debug['reserved']['end'] = self._io.pos()
        self._debug['version_valid_for']['start'] = self._io.pos()
        self.version_valid_for = self._io.read_u4be()
        self._debug['version_valid_for']['end'] = self._io.pos()
        self._debug['sqlite_version_number']['start'] = self._io.pos()
        self.sqlite_version_number = self._io.read_u4be()
        self._debug['sqlite_version_number']['end'] = self._io.pos()
        self._debug['root_page']['start'] = self._io.pos()
        self.root_page = self._root.BtreePage(self._io, self, self._root)
        self.root_page._read()
        self._debug['root_page']['end'] = self._io.pos()

    class Serial(KaitaiStruct):
        SEQ_FIELDS = ["code"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = VlqBase128Be(self._io)
            self.code._read()
            self._debug['code']['end'] = self._io.pos()

        @property
        def is_blob(self):
            if hasattr(self, '_m_is_blob'):
                return self._m_is_blob if hasattr(self, '_m_is_blob') else None

            self._m_is_blob =  ((self.code.value >= 12) and ((self.code.value % 2) == 0)) 
            return self._m_is_blob if hasattr(self, '_m_is_blob') else None

        @property
        def is_string(self):
            if hasattr(self, '_m_is_string'):
                return self._m_is_string if hasattr(self, '_m_is_string') else None

            self._m_is_string =  ((self.code.value >= 13) and ((self.code.value % 2) == 1)) 
            return self._m_is_string if hasattr(self, '_m_is_string') else None

        @property
        def len_content(self):
            if hasattr(self, '_m_len_content'):
                return self._m_len_content if hasattr(self, '_m_len_content') else None

            if self.code.value >= 12:
                self._m_len_content = (self.code.value - 12) // 2

            return self._m_len_content if hasattr(self, '_m_len_content') else None


    class BtreePage(KaitaiStruct):
        SEQ_FIELDS = ["page_type", "first_freeblock", "num_cells", "ofs_cells", "num_frag_free_bytes", "right_ptr", "cells"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['page_type']['start'] = self._io.pos()
            self.page_type = self._io.read_u1()
            self._debug['page_type']['end'] = self._io.pos()
            self._debug['first_freeblock']['start'] = self._io.pos()
            self.first_freeblock = self._io.read_u2be()
            self._debug['first_freeblock']['end'] = self._io.pos()
            self._debug['num_cells']['start'] = self._io.pos()
            self.num_cells = self._io.read_u2be()
            self._debug['num_cells']['end'] = self._io.pos()
            self._debug['ofs_cells']['start'] = self._io.pos()
            self.ofs_cells = self._io.read_u2be()
            self._debug['ofs_cells']['end'] = self._io.pos()
            self._debug['num_frag_free_bytes']['start'] = self._io.pos()
            self.num_frag_free_bytes = self._io.read_u1()
            self._debug['num_frag_free_bytes']['end'] = self._io.pos()
            if  ((self.page_type == 2) or (self.page_type == 5)) :
                self._debug['right_ptr']['start'] = self._io.pos()
                self.right_ptr = self._io.read_u4be()
                self._debug['right_ptr']['end'] = self._io.pos()

            self._debug['cells']['start'] = self._io.pos()
            self.cells = [None] * (self.num_cells)
            for i in range(self.num_cells):
                if not 'arr' in self._debug['cells']:
                    self._debug['cells']['arr'] = []
                self._debug['cells']['arr'].append({'start': self._io.pos()})
                _t_cells = self._root.RefCell(self._io, self, self._root)
                _t_cells._read()
                self.cells[i] = _t_cells
                self._debug['cells']['arr'][i]['end'] = self._io.pos()

            self._debug['cells']['end'] = self._io.pos()


    class CellIndexLeaf(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.sqlite.org/fileformat.html#b_tree_pages
        """
        SEQ_FIELDS = ["len_payload", "payload"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_payload']['start'] = self._io.pos()
            self.len_payload = VlqBase128Be(self._io)
            self.len_payload._read()
            self._debug['len_payload']['end'] = self._io.pos()
            self._debug['payload']['start'] = self._io.pos()
            self._raw_payload = self._io.read_bytes(self.len_payload.value)
            io = KaitaiStream(BytesIO(self._raw_payload))
            self.payload = self._root.CellPayload(io, self, self._root)
            self.payload._read()
            self._debug['payload']['end'] = self._io.pos()


    class Serials(KaitaiStruct):
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
                _t_entries = VlqBase128Be(self._io)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class CellTableLeaf(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.sqlite.org/fileformat.html#b_tree_pages
        """
        SEQ_FIELDS = ["len_payload", "row_id", "payload"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_payload']['start'] = self._io.pos()
            self.len_payload = VlqBase128Be(self._io)
            self.len_payload._read()
            self._debug['len_payload']['end'] = self._io.pos()
            self._debug['row_id']['start'] = self._io.pos()
            self.row_id = VlqBase128Be(self._io)
            self.row_id._read()
            self._debug['row_id']['end'] = self._io.pos()
            self._debug['payload']['start'] = self._io.pos()
            self._raw_payload = self._io.read_bytes(self.len_payload.value)
            io = KaitaiStream(BytesIO(self._raw_payload))
            self.payload = self._root.CellPayload(io, self, self._root)
            self.payload._read()
            self._debug['payload']['end'] = self._io.pos()


    class CellPayload(KaitaiStruct):
        """
        .. seealso::
           Source - https://sqlite.org/fileformat2.html#record_format
        """
        SEQ_FIELDS = ["len_header_and_len", "column_serials", "column_contents"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_header_and_len']['start'] = self._io.pos()
            self.len_header_and_len = VlqBase128Be(self._io)
            self.len_header_and_len._read()
            self._debug['len_header_and_len']['end'] = self._io.pos()
            self._debug['column_serials']['start'] = self._io.pos()
            self._raw_column_serials = self._io.read_bytes((self.len_header_and_len.value - 1))
            io = KaitaiStream(BytesIO(self._raw_column_serials))
            self.column_serials = self._root.Serials(io, self, self._root)
            self.column_serials._read()
            self._debug['column_serials']['end'] = self._io.pos()
            self._debug['column_contents']['start'] = self._io.pos()
            self.column_contents = [None] * (len(self.column_serials.entries))
            for i in range(len(self.column_serials.entries)):
                if not 'arr' in self._debug['column_contents']:
                    self._debug['column_contents']['arr'] = []
                self._debug['column_contents']['arr'].append({'start': self._io.pos()})
                _t_column_contents = self._root.ColumnContent(self.column_serials.entries[i], self._io, self, self._root)
                _t_column_contents._read()
                self.column_contents[i] = _t_column_contents
                self._debug['column_contents']['arr'][i]['end'] = self._io.pos()

            self._debug['column_contents']['end'] = self._io.pos()


    class CellTableInterior(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.sqlite.org/fileformat.html#b_tree_pages
        """
        SEQ_FIELDS = ["left_child_page", "row_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['left_child_page']['start'] = self._io.pos()
            self.left_child_page = self._io.read_u4be()
            self._debug['left_child_page']['end'] = self._io.pos()
            self._debug['row_id']['start'] = self._io.pos()
            self.row_id = VlqBase128Be(self._io)
            self.row_id._read()
            self._debug['row_id']['end'] = self._io.pos()


    class CellIndexInterior(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.sqlite.org/fileformat.html#b_tree_pages
        """
        SEQ_FIELDS = ["left_child_page", "len_payload", "payload"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['left_child_page']['start'] = self._io.pos()
            self.left_child_page = self._io.read_u4be()
            self._debug['left_child_page']['end'] = self._io.pos()
            self._debug['len_payload']['start'] = self._io.pos()
            self.len_payload = VlqBase128Be(self._io)
            self.len_payload._read()
            self._debug['len_payload']['end'] = self._io.pos()
            self._debug['payload']['start'] = self._io.pos()
            self._raw_payload = self._io.read_bytes(self.len_payload.value)
            io = KaitaiStream(BytesIO(self._raw_payload))
            self.payload = self._root.CellPayload(io, self, self._root)
            self.payload._read()
            self._debug['payload']['end'] = self._io.pos()


    class ColumnContent(KaitaiStruct):
        SEQ_FIELDS = ["as_int", "as_float", "as_blob", "as_str"]
        def __init__(self, ser, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.ser = ser
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if  ((self.serial_type.code.value >= 1) and (self.serial_type.code.value <= 6)) :
                self._debug['as_int']['start'] = self._io.pos()
                _on = self.serial_type.code.value
                if _on == 4:
                    self.as_int = self._io.read_u4be()
                elif _on == 6:
                    self.as_int = self._io.read_u8be()
                elif _on == 1:
                    self.as_int = self._io.read_u1()
                elif _on == 3:
                    self.as_int = self._io.read_bits_int(24)
                elif _on == 5:
                    self.as_int = self._io.read_bits_int(48)
                elif _on == 2:
                    self.as_int = self._io.read_u2be()
                self._debug['as_int']['end'] = self._io.pos()

            if self.serial_type.code.value == 7:
                self._debug['as_float']['start'] = self._io.pos()
                self.as_float = self._io.read_f8be()
                self._debug['as_float']['end'] = self._io.pos()

            if self.serial_type.is_blob:
                self._debug['as_blob']['start'] = self._io.pos()
                self.as_blob = self._io.read_bytes(self.serial_type.len_content)
                self._debug['as_blob']['end'] = self._io.pos()

            self._debug['as_str']['start'] = self._io.pos()
            self.as_str = (self._io.read_bytes(self.serial_type.len_content)).decode(u"UTF-8")
            self._debug['as_str']['end'] = self._io.pos()

        @property
        def serial_type(self):
            if hasattr(self, '_m_serial_type'):
                return self._m_serial_type if hasattr(self, '_m_serial_type') else None

            self._m_serial_type = self.ser
            return self._m_serial_type if hasattr(self, '_m_serial_type') else None


    class RefCell(KaitaiStruct):
        SEQ_FIELDS = ["ofs_body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ofs_body']['start'] = self._io.pos()
            self.ofs_body = self._io.read_u2be()
            self._debug['ofs_body']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_body)
            self._debug['_m_body']['start'] = self._io.pos()
            _on = self._parent.page_type
            if _on == 13:
                self._m_body = self._root.CellTableLeaf(self._io, self, self._root)
                self._m_body._read()
            elif _on == 5:
                self._m_body = self._root.CellTableInterior(self._io, self, self._root)
                self._m_body._read()
            elif _on == 10:
                self._m_body = self._root.CellIndexLeaf(self._io, self, self._root)
                self._m_body._read()
            elif _on == 2:
                self._m_body = self._root.CellIndexInterior(self._io, self, self._root)
                self._m_body._read()
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    @property
    def len_page(self):
        if hasattr(self, '_m_len_page'):
            return self._m_len_page if hasattr(self, '_m_len_page') else None

        self._m_len_page = (65536 if self.len_page_mod == 1 else self.len_page_mod)
        return self._m_len_page if hasattr(self, '_m_len_page') else None


