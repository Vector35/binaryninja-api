# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class NtMdtPal(KaitaiStruct):
    """It is a color scheme for visualising SPM scans."""
    SEQ_FIELDS = ["signature", "count", "meta", "something2", "tables"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['signature']['start'] = self._io.pos()
        self.signature = self._io.ensure_fixed_contents(b"\x4E\x54\x2D\x4D\x44\x54\x20\x50\x61\x6C\x65\x74\x74\x65\x20\x46\x69\x6C\x65\x20\x20\x31\x2E\x30\x30\x21")
        self._debug['signature']['end'] = self._io.pos()
        self._debug['count']['start'] = self._io.pos()
        self.count = self._io.read_u4be()
        self._debug['count']['end'] = self._io.pos()
        self._debug['meta']['start'] = self._io.pos()
        self.meta = [None] * (self.count)
        for i in range(self.count):
            if not 'arr' in self._debug['meta']:
                self._debug['meta']['arr'] = []
            self._debug['meta']['arr'].append({'start': self._io.pos()})
            _t_meta = self._root.Meta(self._io, self, self._root)
            _t_meta._read()
            self.meta[i] = _t_meta
            self._debug['meta']['arr'][i]['end'] = self._io.pos()

        self._debug['meta']['end'] = self._io.pos()
        self._debug['something2']['start'] = self._io.pos()
        self.something2 = self._io.read_bytes(1)
        self._debug['something2']['end'] = self._io.pos()
        self._debug['tables']['start'] = self._io.pos()
        self.tables = [None] * (self.count)
        for i in range(self.count):
            if not 'arr' in self._debug['tables']:
                self._debug['tables']['arr'] = []
            self._debug['tables']['arr'].append({'start': self._io.pos()})
            _t_tables = self._root.ColTable(i, self._io, self, self._root)
            _t_tables._read()
            self.tables[i] = _t_tables
            self._debug['tables']['arr'][i]['end'] = self._io.pos()

        self._debug['tables']['end'] = self._io.pos()

    class Meta(KaitaiStruct):
        SEQ_FIELDS = ["unkn00", "unkn01", "unkn02", "unkn03", "colors_count", "unkn10", "unkn11", "unkn12", "name_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['unkn00']['start'] = self._io.pos()
            self.unkn00 = self._io.read_bytes(3)
            self._debug['unkn00']['end'] = self._io.pos()
            self._debug['unkn01']['start'] = self._io.pos()
            self.unkn01 = self._io.read_bytes(2)
            self._debug['unkn01']['end'] = self._io.pos()
            self._debug['unkn02']['start'] = self._io.pos()
            self.unkn02 = self._io.read_bytes(1)
            self._debug['unkn02']['end'] = self._io.pos()
            self._debug['unkn03']['start'] = self._io.pos()
            self.unkn03 = self._io.read_bytes(1)
            self._debug['unkn03']['end'] = self._io.pos()
            self._debug['colors_count']['start'] = self._io.pos()
            self.colors_count = self._io.read_u2le()
            self._debug['colors_count']['end'] = self._io.pos()
            self._debug['unkn10']['start'] = self._io.pos()
            self.unkn10 = self._io.read_bytes(2)
            self._debug['unkn10']['end'] = self._io.pos()
            self._debug['unkn11']['start'] = self._io.pos()
            self.unkn11 = self._io.read_bytes(1)
            self._debug['unkn11']['end'] = self._io.pos()
            self._debug['unkn12']['start'] = self._io.pos()
            self.unkn12 = self._io.read_bytes(2)
            self._debug['unkn12']['end'] = self._io.pos()
            self._debug['name_size']['start'] = self._io.pos()
            self.name_size = self._io.read_u2be()
            self._debug['name_size']['end'] = self._io.pos()


    class Color(KaitaiStruct):
        SEQ_FIELDS = ["red", "unkn", "blue", "green"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['red']['start'] = self._io.pos()
            self.red = self._io.read_u1()
            self._debug['red']['end'] = self._io.pos()
            self._debug['unkn']['start'] = self._io.pos()
            self.unkn = self._io.read_u1()
            self._debug['unkn']['end'] = self._io.pos()
            self._debug['blue']['start'] = self._io.pos()
            self.blue = self._io.read_u1()
            self._debug['blue']['end'] = self._io.pos()
            self._debug['green']['start'] = self._io.pos()
            self.green = self._io.read_u1()
            self._debug['green']['end'] = self._io.pos()


    class ColTable(KaitaiStruct):
        SEQ_FIELDS = ["size1", "unkn", "title", "unkn1", "colors"]
        def __init__(self, index, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.index = index
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size1']['start'] = self._io.pos()
            self.size1 = self._io.read_u1()
            self._debug['size1']['end'] = self._io.pos()
            self._debug['unkn']['start'] = self._io.pos()
            self.unkn = self._io.read_u1()
            self._debug['unkn']['end'] = self._io.pos()
            self._debug['title']['start'] = self._io.pos()
            self.title = (self._io.read_bytes(self._root.meta[self.index].name_size)).decode(u"UTF-16")
            self._debug['title']['end'] = self._io.pos()
            self._debug['unkn1']['start'] = self._io.pos()
            self.unkn1 = self._io.read_u2be()
            self._debug['unkn1']['end'] = self._io.pos()
            self._debug['colors']['start'] = self._io.pos()
            self.colors = [None] * ((self._root.meta[self.index].colors_count - 1))
            for i in range((self._root.meta[self.index].colors_count - 1)):
                if not 'arr' in self._debug['colors']:
                    self._debug['colors']['arr'] = []
                self._debug['colors']['arr'].append({'start': self._io.pos()})
                _t_colors = self._root.Color(self._io, self, self._root)
                _t_colors._read()
                self.colors[i] = _t_colors
                self._debug['colors']['arr'][i]['end'] = self._io.pos()

            self._debug['colors']['end'] = self._io.pos()



