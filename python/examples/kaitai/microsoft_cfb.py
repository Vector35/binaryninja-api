# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MicrosoftCfb(KaitaiStruct):
    SEQ_FIELDS = ["header"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.CfbHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()

    class CfbHeader(KaitaiStruct):
        SEQ_FIELDS = ["signature", "clsid", "version_minor", "version_major", "byte_order", "sector_shift", "mini_sector_shift", "reserved1", "size_dir", "size_fat", "ofs_dir", "transaction_seq", "mini_stream_cutoff_size", "ofs_mini_fat", "size_mini_fat", "ofs_difat", "size_difat", "difat"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.ensure_fixed_contents(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
            self._debug['signature']['end'] = self._io.pos()
            self._debug['clsid']['start'] = self._io.pos()
            self.clsid = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            self._debug['clsid']['end'] = self._io.pos()
            self._debug['version_minor']['start'] = self._io.pos()
            self.version_minor = self._io.read_u2le()
            self._debug['version_minor']['end'] = self._io.pos()
            self._debug['version_major']['start'] = self._io.pos()
            self.version_major = self._io.read_u2le()
            self._debug['version_major']['end'] = self._io.pos()
            self._debug['byte_order']['start'] = self._io.pos()
            self.byte_order = self._io.ensure_fixed_contents(b"\xFE\xFF")
            self._debug['byte_order']['end'] = self._io.pos()
            self._debug['sector_shift']['start'] = self._io.pos()
            self.sector_shift = self._io.read_u2le()
            self._debug['sector_shift']['end'] = self._io.pos()
            self._debug['mini_sector_shift']['start'] = self._io.pos()
            self.mini_sector_shift = self._io.read_u2le()
            self._debug['mini_sector_shift']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bytes(6)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['size_dir']['start'] = self._io.pos()
            self.size_dir = self._io.read_s4le()
            self._debug['size_dir']['end'] = self._io.pos()
            self._debug['size_fat']['start'] = self._io.pos()
            self.size_fat = self._io.read_s4le()
            self._debug['size_fat']['end'] = self._io.pos()
            self._debug['ofs_dir']['start'] = self._io.pos()
            self.ofs_dir = self._io.read_s4le()
            self._debug['ofs_dir']['end'] = self._io.pos()
            self._debug['transaction_seq']['start'] = self._io.pos()
            self.transaction_seq = self._io.read_s4le()
            self._debug['transaction_seq']['end'] = self._io.pos()
            self._debug['mini_stream_cutoff_size']['start'] = self._io.pos()
            self.mini_stream_cutoff_size = self._io.read_s4le()
            self._debug['mini_stream_cutoff_size']['end'] = self._io.pos()
            self._debug['ofs_mini_fat']['start'] = self._io.pos()
            self.ofs_mini_fat = self._io.read_s4le()
            self._debug['ofs_mini_fat']['end'] = self._io.pos()
            self._debug['size_mini_fat']['start'] = self._io.pos()
            self.size_mini_fat = self._io.read_s4le()
            self._debug['size_mini_fat']['end'] = self._io.pos()
            self._debug['ofs_difat']['start'] = self._io.pos()
            self.ofs_difat = self._io.read_s4le()
            self._debug['ofs_difat']['end'] = self._io.pos()
            self._debug['size_difat']['start'] = self._io.pos()
            self.size_difat = self._io.read_s4le()
            self._debug['size_difat']['end'] = self._io.pos()
            self._debug['difat']['start'] = self._io.pos()
            self.difat = [None] * (109)
            for i in range(109):
                if not 'arr' in self._debug['difat']:
                    self._debug['difat']['arr'] = []
                self._debug['difat']['arr'].append({'start': self._io.pos()})
                self.difat[i] = self._io.read_s4le()
                self._debug['difat']['arr'][i]['end'] = self._io.pos()

            self._debug['difat']['end'] = self._io.pos()


    class FatEntries(KaitaiStruct):
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
                self.entries.append(self._io.read_s4le())
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class DirEntry(KaitaiStruct):

        class ObjType(Enum):
            unknown = 0
            storage = 1
            stream = 2
            root_storage = 5

        class RbColor(Enum):
            red = 0
            black = 1
        SEQ_FIELDS = ["name", "name_len", "object_type", "color_flag", "left_sibling_id", "right_sibling_id", "child_id", "clsid", "state", "time_create", "time_mod", "ofs", "size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(64)).decode(u"UTF-16LE")
            self._debug['name']['end'] = self._io.pos()
            self._debug['name_len']['start'] = self._io.pos()
            self.name_len = self._io.read_u2le()
            self._debug['name_len']['end'] = self._io.pos()
            self._debug['object_type']['start'] = self._io.pos()
            self.object_type = KaitaiStream.resolve_enum(self._root.DirEntry.ObjType, self._io.read_u1())
            self._debug['object_type']['end'] = self._io.pos()
            self._debug['color_flag']['start'] = self._io.pos()
            self.color_flag = KaitaiStream.resolve_enum(self._root.DirEntry.RbColor, self._io.read_u1())
            self._debug['color_flag']['end'] = self._io.pos()
            self._debug['left_sibling_id']['start'] = self._io.pos()
            self.left_sibling_id = self._io.read_s4le()
            self._debug['left_sibling_id']['end'] = self._io.pos()
            self._debug['right_sibling_id']['start'] = self._io.pos()
            self.right_sibling_id = self._io.read_s4le()
            self._debug['right_sibling_id']['end'] = self._io.pos()
            self._debug['child_id']['start'] = self._io.pos()
            self.child_id = self._io.read_s4le()
            self._debug['child_id']['end'] = self._io.pos()
            self._debug['clsid']['start'] = self._io.pos()
            self.clsid = self._io.read_bytes(16)
            self._debug['clsid']['end'] = self._io.pos()
            self._debug['state']['start'] = self._io.pos()
            self.state = self._io.read_u4le()
            self._debug['state']['end'] = self._io.pos()
            self._debug['time_create']['start'] = self._io.pos()
            self.time_create = self._io.read_u8le()
            self._debug['time_create']['end'] = self._io.pos()
            self._debug['time_mod']['start'] = self._io.pos()
            self.time_mod = self._io.read_u8le()
            self._debug['time_mod']['end'] = self._io.pos()
            self._debug['ofs']['start'] = self._io.pos()
            self.ofs = self._io.read_s4le()
            self._debug['ofs']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u8le()
            self._debug['size']['end'] = self._io.pos()

        @property
        def mini_stream(self):
            if hasattr(self, '_m_mini_stream'):
                return self._m_mini_stream if hasattr(self, '_m_mini_stream') else None

            if self.object_type == self._root.DirEntry.ObjType.root_storage:
                io = self._root._io
                _pos = io.pos()
                io.seek(((self.ofs + 1) * self._root.sector_size))
                self._debug['_m_mini_stream']['start'] = io.pos()
                self._m_mini_stream = io.read_bytes(self.size)
                self._debug['_m_mini_stream']['end'] = io.pos()
                io.seek(_pos)

            return self._m_mini_stream if hasattr(self, '_m_mini_stream') else None

        @property
        def child(self):
            if hasattr(self, '_m_child'):
                return self._m_child if hasattr(self, '_m_child') else None

            if self.child_id != -1:
                io = self._root._io
                _pos = io.pos()
                io.seek((((self._root.header.ofs_dir + 1) * self._root.sector_size) + (self.child_id * 128)))
                self._debug['_m_child']['start'] = io.pos()
                self._m_child = self._root.DirEntry(io, self, self._root)
                self._m_child._read()
                self._debug['_m_child']['end'] = io.pos()
                io.seek(_pos)

            return self._m_child if hasattr(self, '_m_child') else None

        @property
        def left_sibling(self):
            if hasattr(self, '_m_left_sibling'):
                return self._m_left_sibling if hasattr(self, '_m_left_sibling') else None

            if self.left_sibling_id != -1:
                io = self._root._io
                _pos = io.pos()
                io.seek((((self._root.header.ofs_dir + 1) * self._root.sector_size) + (self.left_sibling_id * 128)))
                self._debug['_m_left_sibling']['start'] = io.pos()
                self._m_left_sibling = self._root.DirEntry(io, self, self._root)
                self._m_left_sibling._read()
                self._debug['_m_left_sibling']['end'] = io.pos()
                io.seek(_pos)

            return self._m_left_sibling if hasattr(self, '_m_left_sibling') else None

        @property
        def right_sibling(self):
            if hasattr(self, '_m_right_sibling'):
                return self._m_right_sibling if hasattr(self, '_m_right_sibling') else None

            if self.right_sibling_id != -1:
                io = self._root._io
                _pos = io.pos()
                io.seek((((self._root.header.ofs_dir + 1) * self._root.sector_size) + (self.right_sibling_id * 128)))
                self._debug['_m_right_sibling']['start'] = io.pos()
                self._m_right_sibling = self._root.DirEntry(io, self, self._root)
                self._m_right_sibling._read()
                self._debug['_m_right_sibling']['end'] = io.pos()
                io.seek(_pos)

            return self._m_right_sibling if hasattr(self, '_m_right_sibling') else None


    @property
    def sector_size(self):
        if hasattr(self, '_m_sector_size'):
            return self._m_sector_size if hasattr(self, '_m_sector_size') else None

        self._m_sector_size = (1 << self.header.sector_shift)
        return self._m_sector_size if hasattr(self, '_m_sector_size') else None

    @property
    def fat(self):
        if hasattr(self, '_m_fat'):
            return self._m_fat if hasattr(self, '_m_fat') else None

        _pos = self._io.pos()
        self._io.seek(self.sector_size)
        self._debug['_m_fat']['start'] = self._io.pos()
        self._raw__m_fat = self._io.read_bytes((self.header.size_fat * self.sector_size))
        io = KaitaiStream(BytesIO(self._raw__m_fat))
        self._m_fat = self._root.FatEntries(io, self, self._root)
        self._m_fat._read()
        self._debug['_m_fat']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_fat if hasattr(self, '_m_fat') else None

    @property
    def dir(self):
        if hasattr(self, '_m_dir'):
            return self._m_dir if hasattr(self, '_m_dir') else None

        _pos = self._io.pos()
        self._io.seek(((self.header.ofs_dir + 1) * self.sector_size))
        self._debug['_m_dir']['start'] = self._io.pos()
        self._m_dir = self._root.DirEntry(self._io, self, self._root)
        self._m_dir._read()
        self._debug['_m_dir']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_dir if hasattr(self, '_m_dir') else None


