# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class HeroesOfMightAndMagicAgg(KaitaiStruct):
    """
    .. seealso::
       Source - http://rewiki.regengedanken.de/wiki/.AGG_(Heroes_of_Might_and_Magic)
    """
    SEQ_FIELDS = ["num_files", "entries"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['num_files']['start'] = self._io.pos()
        self.num_files = self._io.read_u2le()
        self._debug['num_files']['end'] = self._io.pos()
        self._debug['entries']['start'] = self._io.pos()
        self.entries = [None] * (self.num_files)
        for i in range(self.num_files):
            if not 'arr' in self._debug['entries']:
                self._debug['entries']['arr'] = []
            self._debug['entries']['arr'].append({'start': self._io.pos()})
            _t_entries = self._root.Entry(self._io, self, self._root)
            _t_entries._read()
            self.entries[i] = _t_entries
            self._debug['entries']['arr'][i]['end'] = self._io.pos()

        self._debug['entries']['end'] = self._io.pos()

    class Entry(KaitaiStruct):
        SEQ_FIELDS = ["hash", "offset", "size", "size2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['hash']['start'] = self._io.pos()
            self.hash = self._io.read_u2le()
            self._debug['hash']['end'] = self._io.pos()
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4le()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['size2']['start'] = self._io.pos()
            self.size2 = self._io.read_u4le()
            self._debug['size2']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek(self.offset)
            self._debug['_m_body']['start'] = self._io.pos()
            self._m_body = self._io.read_bytes(self.size)
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class Filename(KaitaiStruct):
        SEQ_FIELDS = ["str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
            self._debug['str']['end'] = self._io.pos()


    @property
    def filenames(self):
        if hasattr(self, '_m_filenames'):
            return self._m_filenames if hasattr(self, '_m_filenames') else None

        _pos = self._io.pos()
        self._io.seek((self.entries[-1].offset + self.entries[-1].size))
        self._debug['_m_filenames']['start'] = self._io.pos()
        self._raw__m_filenames = [None] * (self.num_files)
        self._m_filenames = [None] * (self.num_files)
        for i in range(self.num_files):
            if not 'arr' in self._debug['_m_filenames']:
                self._debug['_m_filenames']['arr'] = []
            self._debug['_m_filenames']['arr'].append({'start': self._io.pos()})
            self._raw__m_filenames[i] = self._io.read_bytes(15)
            io = KaitaiStream(BytesIO(self._raw__m_filenames[i]))
            _t__m_filenames = self._root.Filename(io, self, self._root)
            _t__m_filenames._read()
            self._m_filenames[i] = _t__m_filenames
            self._debug['_m_filenames']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_filenames']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_filenames if hasattr(self, '_m_filenames') else None


