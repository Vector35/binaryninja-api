# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class SaintsRow2VppPc(KaitaiStruct):
    SEQ_FIELDS = ["magic", "pad1", "num_files", "container_size", "len_offsets", "len_filenames", "len_extensions", "smth5", "smth6", "smth7", "smth8", "smth9"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\xCE\x0A\x89\x51\x04")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['pad1']['start'] = self._io.pos()
        self.pad1 = self._io.read_bytes(335)
        self._debug['pad1']['end'] = self._io.pos()
        self._debug['num_files']['start'] = self._io.pos()
        self.num_files = self._io.read_s4le()
        self._debug['num_files']['end'] = self._io.pos()
        self._debug['container_size']['start'] = self._io.pos()
        self.container_size = self._io.read_s4le()
        self._debug['container_size']['end'] = self._io.pos()
        self._debug['len_offsets']['start'] = self._io.pos()
        self.len_offsets = self._io.read_s4le()
        self._debug['len_offsets']['end'] = self._io.pos()
        self._debug['len_filenames']['start'] = self._io.pos()
        self.len_filenames = self._io.read_s4le()
        self._debug['len_filenames']['end'] = self._io.pos()
        self._debug['len_extensions']['start'] = self._io.pos()
        self.len_extensions = self._io.read_s4le()
        self._debug['len_extensions']['end'] = self._io.pos()
        self._debug['smth5']['start'] = self._io.pos()
        self.smth5 = self._io.read_s4le()
        self._debug['smth5']['end'] = self._io.pos()
        self._debug['smth6']['start'] = self._io.pos()
        self.smth6 = self._io.read_s4le()
        self._debug['smth6']['end'] = self._io.pos()
        self._debug['smth7']['start'] = self._io.pos()
        self.smth7 = self._io.read_s4le()
        self._debug['smth7']['end'] = self._io.pos()
        self._debug['smth8']['start'] = self._io.pos()
        self.smth8 = self._io.read_s4le()
        self._debug['smth8']['end'] = self._io.pos()
        self._debug['smth9']['start'] = self._io.pos()
        self.smth9 = self._io.read_s4le()
        self._debug['smth9']['end'] = self._io.pos()

    class Offsets(KaitaiStruct):
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
                _t_entries = self._root.Offsets.Offset(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()

        class Offset(KaitaiStruct):
            SEQ_FIELDS = ["name_ofs", "ext_ofs", "smth2", "ofs_body", "len_body", "always_minus_1", "always_zero"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['name_ofs']['start'] = self._io.pos()
                self.name_ofs = self._io.read_u4le()
                self._debug['name_ofs']['end'] = self._io.pos()
                self._debug['ext_ofs']['start'] = self._io.pos()
                self.ext_ofs = self._io.read_u4le()
                self._debug['ext_ofs']['end'] = self._io.pos()
                self._debug['smth2']['start'] = self._io.pos()
                self.smth2 = self._io.read_s4le()
                self._debug['smth2']['end'] = self._io.pos()
                self._debug['ofs_body']['start'] = self._io.pos()
                self.ofs_body = self._io.read_s4le()
                self._debug['ofs_body']['end'] = self._io.pos()
                self._debug['len_body']['start'] = self._io.pos()
                self.len_body = self._io.read_s4le()
                self._debug['len_body']['end'] = self._io.pos()
                self._debug['always_minus_1']['start'] = self._io.pos()
                self.always_minus_1 = self._io.read_s4le()
                self._debug['always_minus_1']['end'] = self._io.pos()
                self._debug['always_zero']['start'] = self._io.pos()
                self.always_zero = self._io.read_s4le()
                self._debug['always_zero']['end'] = self._io.pos()

            @property
            def filename(self):
                if hasattr(self, '_m_filename'):
                    return self._m_filename if hasattr(self, '_m_filename') else None

                io = self._root.filenames._io
                _pos = io.pos()
                io.seek(self.name_ofs)
                self._debug['_m_filename']['start'] = io.pos()
                self._m_filename = (io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
                self._debug['_m_filename']['end'] = io.pos()
                io.seek(_pos)
                return self._m_filename if hasattr(self, '_m_filename') else None

            @property
            def ext(self):
                if hasattr(self, '_m_ext'):
                    return self._m_ext if hasattr(self, '_m_ext') else None

                io = self._root.extensions._io
                _pos = io.pos()
                io.seek(self.ext_ofs)
                self._debug['_m_ext']['start'] = io.pos()
                self._m_ext = (io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
                self._debug['_m_ext']['end'] = io.pos()
                io.seek(_pos)
                return self._m_ext if hasattr(self, '_m_ext') else None

            @property
            def body(self):
                if hasattr(self, '_m_body'):
                    return self._m_body if hasattr(self, '_m_body') else None

                io = self._root._io
                _pos = io.pos()
                io.seek((self._root.data_start + self.ofs_body))
                self._debug['_m_body']['start'] = io.pos()
                self._m_body = io.read_bytes(self.len_body)
                self._debug['_m_body']['end'] = io.pos()
                io.seek(_pos)
                return self._m_body if hasattr(self, '_m_body') else None



    class Strings(KaitaiStruct):
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
                self.entries.append((self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8"))
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    @property
    def filenames(self):
        if hasattr(self, '_m_filenames'):
            return self._m_filenames if hasattr(self, '_m_filenames') else None

        _pos = self._io.pos()
        self._io.seek(self.ofs_filenames)
        self._debug['_m_filenames']['start'] = self._io.pos()
        self._raw__m_filenames = self._io.read_bytes(self.len_filenames)
        io = KaitaiStream(BytesIO(self._raw__m_filenames))
        self._m_filenames = self._root.Strings(io, self, self._root)
        self._m_filenames._read()
        self._debug['_m_filenames']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_filenames if hasattr(self, '_m_filenames') else None

    @property
    def ofs_extensions(self):
        if hasattr(self, '_m_ofs_extensions'):
            return self._m_ofs_extensions if hasattr(self, '_m_ofs_extensions') else None

        self._m_ofs_extensions = (((self.ofs_filenames + self.len_filenames) & 4294965248) + 2048)
        return self._m_ofs_extensions if hasattr(self, '_m_ofs_extensions') else None

    @property
    def files(self):
        if hasattr(self, '_m_files'):
            return self._m_files if hasattr(self, '_m_files') else None

        _pos = self._io.pos()
        self._io.seek(2048)
        self._debug['_m_files']['start'] = self._io.pos()
        self._raw__m_files = self._io.read_bytes(self.len_offsets)
        io = KaitaiStream(BytesIO(self._raw__m_files))
        self._m_files = self._root.Offsets(io, self, self._root)
        self._m_files._read()
        self._debug['_m_files']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_files if hasattr(self, '_m_files') else None

    @property
    def data_start(self):
        if hasattr(self, '_m_data_start'):
            return self._m_data_start if hasattr(self, '_m_data_start') else None

        self._m_data_start = (((self.ofs_extensions + self.len_extensions) & 4294965248) + 2048)
        return self._m_data_start if hasattr(self, '_m_data_start') else None

    @property
    def extensions(self):
        if hasattr(self, '_m_extensions'):
            return self._m_extensions if hasattr(self, '_m_extensions') else None

        _pos = self._io.pos()
        self._io.seek(self.ofs_extensions)
        self._debug['_m_extensions']['start'] = self._io.pos()
        self._raw__m_extensions = self._io.read_bytes(self.len_extensions)
        io = KaitaiStream(BytesIO(self._raw__m_extensions))
        self._m_extensions = self._root.Strings(io, self, self._root)
        self._m_extensions._read()
        self._debug['_m_extensions']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_extensions if hasattr(self, '_m_extensions') else None

    @property
    def ofs_filenames(self):
        if hasattr(self, '_m_ofs_filenames'):
            return self._m_ofs_filenames if hasattr(self, '_m_ofs_filenames') else None

        self._m_ofs_filenames = (((2048 + self.len_offsets) & 4294965248) + 2048)
        return self._m_ofs_filenames if hasattr(self, '_m_ofs_filenames') else None


