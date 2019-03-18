from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class QuakePak(KaitaiStruct):
    """
    .. seealso::
       Source - https://quakewiki.org/wiki/.pak#Format_specification
    """
    SEQ_FIELDS = ["magic", "ofs_index", "len_index"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x50\x41\x43\x4B")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['ofs_index']['start'] = self._io.pos()
        self.ofs_index = self._io.read_u4le()
        self._debug['ofs_index']['end'] = self._io.pos()
        self._debug['len_index']['start'] = self._io.pos()
        self.len_index = self._io.read_u4le()
        self._debug['len_index']['end'] = self._io.pos()

    class IndexStruct(KaitaiStruct):
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
                _t_entries = self._root.IndexEntry(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class IndexEntry(KaitaiStruct):
        SEQ_FIELDS = ["name", "ofs", "size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (KaitaiStream.bytes_terminate(KaitaiStream.bytes_strip_right(self._io.read_bytes(56), 0), 0, False)).decode(u"UTF-8")
            self._debug['name']['end'] = self._io.pos()
            self._debug['ofs']['start'] = self._io.pos()
            self.ofs = self._io.read_u4le()
            self._debug['ofs']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs)
            self._debug['_m_body']['start'] = io.pos()
            self._m_body = io.read_bytes(self.size)
            self._debug['_m_body']['end'] = io.pos()
            io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    @property
    def index(self):
        if hasattr(self, '_m_index'):
            return self._m_index if hasattr(self, '_m_index') else None

        _pos = self._io.pos()
        self._io.seek(self.ofs_index)
        self._debug['_m_index']['start'] = self._io.pos()
        self._raw__m_index = self._io.read_bytes(self.len_index)
        io = KaitaiStream(BytesIO(self._raw__m_index))
        self._m_index = self._root.IndexStruct(io, self, self._root)
        self._m_index._read()
        self._debug['_m_index']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_index if hasattr(self, '_m_index') else None


