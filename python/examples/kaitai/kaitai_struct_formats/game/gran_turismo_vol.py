from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class GranTurismoVol(KaitaiStruct):
    SEQ_FIELDS = ["magic", "num_files", "num_entries", "reserved", "offsets"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x47\x54\x46\x53\x00\x00\x00\x00")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['num_files']['start'] = self._io.pos()
        self.num_files = self._io.read_u2le()
        self._debug['num_files']['end'] = self._io.pos()
        self._debug['num_entries']['start'] = self._io.pos()
        self.num_entries = self._io.read_u2le()
        self._debug['num_entries']['end'] = self._io.pos()
        self._debug['reserved']['start'] = self._io.pos()
        self.reserved = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
        self._debug['reserved']['end'] = self._io.pos()
        self._debug['offsets']['start'] = self._io.pos()
        self.offsets = [None] * (self.num_files)
        for i in range(self.num_files):
            if not 'arr' in self._debug['offsets']:
                self._debug['offsets']['arr'] = []
            self._debug['offsets']['arr'].append({'start': self._io.pos()})
            self.offsets[i] = self._io.read_u4le()
            self._debug['offsets']['arr'][i]['end'] = self._io.pos()

        self._debug['offsets']['end'] = self._io.pos()

    class FileInfo(KaitaiStruct):
        SEQ_FIELDS = ["timestamp", "offset_idx", "flags", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_u4le()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['offset_idx']['start'] = self._io.pos()
            self.offset_idx = self._io.read_u2le()
            self._debug['offset_idx']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u1()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (KaitaiStream.bytes_terminate(KaitaiStream.bytes_strip_right(self._io.read_bytes(25), 0), 0, False)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()

        @property
        def size(self):
            if hasattr(self, '_m_size'):
                return self._m_size if hasattr(self, '_m_size') else None

            self._m_size = ((self._root.offsets[(self.offset_idx + 1)] & 4294965248) - self._root.offsets[self.offset_idx])
            return self._m_size if hasattr(self, '_m_size') else None

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            if not (self.is_dir):
                _pos = self._io.pos()
                self._io.seek((self._root.offsets[self.offset_idx] & 4294965248))
                self._debug['_m_body']['start'] = self._io.pos()
                self._m_body = self._io.read_bytes(self.size)
                self._debug['_m_body']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_body if hasattr(self, '_m_body') else None

        @property
        def is_dir(self):
            if hasattr(self, '_m_is_dir'):
                return self._m_is_dir if hasattr(self, '_m_is_dir') else None

            self._m_is_dir = (self.flags & 1) != 0
            return self._m_is_dir if hasattr(self, '_m_is_dir') else None

        @property
        def is_last_entry(self):
            if hasattr(self, '_m_is_last_entry'):
                return self._m_is_last_entry if hasattr(self, '_m_is_last_entry') else None

            self._m_is_last_entry = (self.flags & 128) != 0
            return self._m_is_last_entry if hasattr(self, '_m_is_last_entry') else None


    @property
    def ofs_dir(self):
        if hasattr(self, '_m_ofs_dir'):
            return self._m_ofs_dir if hasattr(self, '_m_ofs_dir') else None

        self._m_ofs_dir = self.offsets[1]
        return self._m_ofs_dir if hasattr(self, '_m_ofs_dir') else None

    @property
    def files(self):
        if hasattr(self, '_m_files'):
            return self._m_files if hasattr(self, '_m_files') else None

        _pos = self._io.pos()
        self._io.seek((self.ofs_dir & 4294965248))
        self._debug['_m_files']['start'] = self._io.pos()
        self._m_files = [None] * (self._root.num_entries)
        for i in range(self._root.num_entries):
            if not 'arr' in self._debug['_m_files']:
                self._debug['_m_files']['arr'] = []
            self._debug['_m_files']['arr'].append({'start': self._io.pos()})
            _t__m_files = self._root.FileInfo(self._io, self, self._root)
            _t__m_files._read()
            self._m_files[i] = _t__m_files
            self._debug['_m_files']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_files']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_files if hasattr(self, '_m_files') else None


