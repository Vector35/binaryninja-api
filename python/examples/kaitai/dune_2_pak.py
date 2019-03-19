# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Dune2Pak(KaitaiStruct):
    SEQ_FIELDS = ["dir"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['dir']['start'] = self._io.pos()
        self._raw_dir = self._io.read_bytes(self.dir_size)
        io = KaitaiStream(BytesIO(self._raw_dir))
        self.dir = self._root.Files(io, self, self._root)
        self.dir._read()
        self._debug['dir']['end'] = self._io.pos()

    class Files(KaitaiStruct):
        SEQ_FIELDS = ["files"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['files']['start'] = self._io.pos()
            self.files = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['files']:
                    self._debug['files']['arr'] = []
                self._debug['files']['arr'].append({'start': self._io.pos()})
                _t_files = self._root.File(i, self._io, self, self._root)
                _t_files._read()
                self.files.append(_t_files)
                self._debug['files']['arr'][len(self.files) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['files']['end'] = self._io.pos()


    class File(KaitaiStruct):
        SEQ_FIELDS = ["ofs", "file_name"]
        def __init__(self, idx, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.idx = idx
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ofs']['start'] = self._io.pos()
            self.ofs = self._io.read_u4le()
            self._debug['ofs']['end'] = self._io.pos()
            if self.ofs != 0:
                self._debug['file_name']['start'] = self._io.pos()
                self.file_name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
                self._debug['file_name']['end'] = self._io.pos()


        @property
        def next_ofs0(self):
            if hasattr(self, '_m_next_ofs0'):
                return self._m_next_ofs0 if hasattr(self, '_m_next_ofs0') else None

            if self.ofs != 0:
                self._m_next_ofs0 = self._root.dir.files[(self.idx + 1)].ofs

            return self._m_next_ofs0 if hasattr(self, '_m_next_ofs0') else None

        @property
        def next_ofs(self):
            if hasattr(self, '_m_next_ofs'):
                return self._m_next_ofs if hasattr(self, '_m_next_ofs') else None

            if self.ofs != 0:
                self._m_next_ofs = (self._root._io.size() if self.next_ofs0 == 0 else self.next_ofs0)

            return self._m_next_ofs if hasattr(self, '_m_next_ofs') else None

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            if self.ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs)
                self._debug['_m_body']['start'] = io.pos()
                self._m_body = io.read_bytes((self.next_ofs - self.ofs))
                self._debug['_m_body']['end'] = io.pos()
                io.seek(_pos)

            return self._m_body if hasattr(self, '_m_body') else None


    @property
    def dir_size(self):
        if hasattr(self, '_m_dir_size'):
            return self._m_dir_size if hasattr(self, '_m_dir_size') else None

        _pos = self._io.pos()
        self._io.seek(0)
        self._debug['_m_dir_size']['start'] = self._io.pos()
        self._m_dir_size = self._io.read_u4le()
        self._debug['_m_dir_size']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_dir_size if hasattr(self, '_m_dir_size') else None


