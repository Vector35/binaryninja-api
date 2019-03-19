# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class DosMz(KaitaiStruct):
    """DOS MZ file format is a traditional format for executables in MS-DOS
    environment. Many modern formats (i.e. Windows PE) still maintain
    compatibility stub with this format.
    
    As opposed to .com file format (which basically sports one 64K code
    segment of raw CPU instructions), DOS MZ .exe file format allowed
    more flexible memory management, loading of larger programs and
    added support for relocations.
    """
    SEQ_FIELDS = ["hdr", "mz_header2", "relocations", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['hdr']['start'] = self._io.pos()
        self.hdr = self._root.MzHeader(self._io, self, self._root)
        self.hdr._read()
        self._debug['hdr']['end'] = self._io.pos()
        self._debug['mz_header2']['start'] = self._io.pos()
        self.mz_header2 = self._io.read_bytes((self.hdr.ofs_relocations - 28))
        self._debug['mz_header2']['end'] = self._io.pos()
        self._debug['relocations']['start'] = self._io.pos()
        self.relocations = [None] * (self.hdr.num_relocations)
        for i in range(self.hdr.num_relocations):
            if not 'arr' in self._debug['relocations']:
                self._debug['relocations']['arr'] = []
            self._debug['relocations']['arr'].append({'start': self._io.pos()})
            _t_relocations = self._root.Relocation(self._io, self, self._root)
            _t_relocations._read()
            self.relocations[i] = _t_relocations
            self._debug['relocations']['arr'][i]['end'] = self._io.pos()

        self._debug['relocations']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        self.body = self._io.read_bytes_full()
        self._debug['body']['end'] = self._io.pos()

    class MzHeader(KaitaiStruct):
        SEQ_FIELDS = ["magic", "last_page_extra_bytes", "num_pages", "num_relocations", "header_size", "min_allocation", "max_allocation", "initial_ss", "initial_sp", "checksum", "initial_ip", "initial_cs", "ofs_relocations", "overlay_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.read_bytes(2)
            self._debug['magic']['end'] = self._io.pos()
            self._debug['last_page_extra_bytes']['start'] = self._io.pos()
            self.last_page_extra_bytes = self._io.read_u2le()
            self._debug['last_page_extra_bytes']['end'] = self._io.pos()
            self._debug['num_pages']['start'] = self._io.pos()
            self.num_pages = self._io.read_u2le()
            self._debug['num_pages']['end'] = self._io.pos()
            self._debug['num_relocations']['start'] = self._io.pos()
            self.num_relocations = self._io.read_u2le()
            self._debug['num_relocations']['end'] = self._io.pos()
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u2le()
            self._debug['header_size']['end'] = self._io.pos()
            self._debug['min_allocation']['start'] = self._io.pos()
            self.min_allocation = self._io.read_u2le()
            self._debug['min_allocation']['end'] = self._io.pos()
            self._debug['max_allocation']['start'] = self._io.pos()
            self.max_allocation = self._io.read_u2le()
            self._debug['max_allocation']['end'] = self._io.pos()
            self._debug['initial_ss']['start'] = self._io.pos()
            self.initial_ss = self._io.read_u2le()
            self._debug['initial_ss']['end'] = self._io.pos()
            self._debug['initial_sp']['start'] = self._io.pos()
            self.initial_sp = self._io.read_u2le()
            self._debug['initial_sp']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u2le()
            self._debug['checksum']['end'] = self._io.pos()
            self._debug['initial_ip']['start'] = self._io.pos()
            self.initial_ip = self._io.read_u2le()
            self._debug['initial_ip']['end'] = self._io.pos()
            self._debug['initial_cs']['start'] = self._io.pos()
            self.initial_cs = self._io.read_u2le()
            self._debug['initial_cs']['end'] = self._io.pos()
            self._debug['ofs_relocations']['start'] = self._io.pos()
            self.ofs_relocations = self._io.read_u2le()
            self._debug['ofs_relocations']['end'] = self._io.pos()
            self._debug['overlay_id']['start'] = self._io.pos()
            self.overlay_id = self._io.read_u2le()
            self._debug['overlay_id']['end'] = self._io.pos()


    class Relocation(KaitaiStruct):
        SEQ_FIELDS = ["ofs", "seg"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ofs']['start'] = self._io.pos()
            self.ofs = self._io.read_u2le()
            self._debug['ofs']['end'] = self._io.pos()
            self._debug['seg']['start'] = self._io.pos()
            self.seg = self._io.read_u2le()
            self._debug['seg']['end'] = self._io.pos()



