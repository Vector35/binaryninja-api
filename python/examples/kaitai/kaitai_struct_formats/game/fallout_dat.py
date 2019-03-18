from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class FalloutDat(KaitaiStruct):

    class Compression(Enum):
        none = 32
        lzss = 64
    SEQ_FIELDS = ["folder_count", "unknown1", "unknown2", "timestamp", "folder_names", "folders"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['folder_count']['start'] = self._io.pos()
        self.folder_count = self._io.read_u4be()
        self._debug['folder_count']['end'] = self._io.pos()
        self._debug['unknown1']['start'] = self._io.pos()
        self.unknown1 = self._io.read_u4be()
        self._debug['unknown1']['end'] = self._io.pos()
        self._debug['unknown2']['start'] = self._io.pos()
        self.unknown2 = self._io.read_u4be()
        self._debug['unknown2']['end'] = self._io.pos()
        self._debug['timestamp']['start'] = self._io.pos()
        self.timestamp = self._io.read_u4be()
        self._debug['timestamp']['end'] = self._io.pos()
        self._debug['folder_names']['start'] = self._io.pos()
        self.folder_names = [None] * (self.folder_count)
        for i in range(self.folder_count):
            if not 'arr' in self._debug['folder_names']:
                self._debug['folder_names']['arr'] = []
            self._debug['folder_names']['arr'].append({'start': self._io.pos()})
            _t_folder_names = self._root.Pstr(self._io, self, self._root)
            _t_folder_names._read()
            self.folder_names[i] = _t_folder_names
            self._debug['folder_names']['arr'][i]['end'] = self._io.pos()

        self._debug['folder_names']['end'] = self._io.pos()
        self._debug['folders']['start'] = self._io.pos()
        self.folders = [None] * (self.folder_count)
        for i in range(self.folder_count):
            if not 'arr' in self._debug['folders']:
                self._debug['folders']['arr'] = []
            self._debug['folders']['arr'].append({'start': self._io.pos()})
            _t_folders = self._root.Folder(self._io, self, self._root)
            _t_folders._read()
            self.folders[i] = _t_folders
            self._debug['folders']['arr'][i]['end'] = self._io.pos()

        self._debug['folders']['end'] = self._io.pos()

    class Pstr(KaitaiStruct):
        SEQ_FIELDS = ["size", "str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u1()
            self._debug['size']['end'] = self._io.pos()
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes(self.size)).decode(u"ASCII")
            self._debug['str']['end'] = self._io.pos()


    class Folder(KaitaiStruct):
        SEQ_FIELDS = ["file_count", "unknown", "flags", "timestamp", "files"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['file_count']['start'] = self._io.pos()
            self.file_count = self._io.read_u4be()
            self._debug['file_count']['end'] = self._io.pos()
            self._debug['unknown']['start'] = self._io.pos()
            self.unknown = self._io.read_u4be()
            self._debug['unknown']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4be()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_u4be()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['files']['start'] = self._io.pos()
            self.files = [None] * (self.file_count)
            for i in range(self.file_count):
                if not 'arr' in self._debug['files']:
                    self._debug['files']['arr'] = []
                self._debug['files']['arr'].append({'start': self._io.pos()})
                _t_files = self._root.File(self._io, self, self._root)
                _t_files._read()
                self.files[i] = _t_files
                self._debug['files']['arr'][i]['end'] = self._io.pos()

            self._debug['files']['end'] = self._io.pos()


    class File(KaitaiStruct):
        SEQ_FIELDS = ["name", "flags", "offset", "size_unpacked", "size_packed"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.Pstr(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = KaitaiStream.resolve_enum(self._root.Compression, self._io.read_u4be())
            self._debug['flags']['end'] = self._io.pos()
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4be()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['size_unpacked']['start'] = self._io.pos()
            self.size_unpacked = self._io.read_u4be()
            self._debug['size_unpacked']['end'] = self._io.pos()
            self._debug['size_packed']['start'] = self._io.pos()
            self.size_packed = self._io.read_u4be()
            self._debug['size_packed']['end'] = self._io.pos()

        @property
        def contents(self):
            if hasattr(self, '_m_contents'):
                return self._m_contents if hasattr(self, '_m_contents') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_contents']['start'] = io.pos()
            self._m_contents = io.read_bytes((self.size_unpacked if self.flags == self._root.Compression.none else self.size_packed))
            self._debug['_m_contents']['end'] = io.pos()
            io.seek(_pos)
            return self._m_contents if hasattr(self, '_m_contents') else None



