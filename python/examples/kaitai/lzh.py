# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Lzh(KaitaiStruct):
    """LHA (LHarc, LZH) is a file format used by a popular freeware
    eponymous archiver, created in 1988 by Haruyasu Yoshizaki. Over the
    years, many ports and implementations were developed, sporting many
    extensions to original 1988 LZH.
    
    File format is pretty simple and essentially consists of a stream of
    records.
    """
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
            _t_entries = self._root.Record(self._io, self, self._root)
            _t_entries._read()
            self.entries.append(_t_entries)
            self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['entries']['end'] = self._io.pos()

    class Record(KaitaiStruct):
        SEQ_FIELDS = ["header_len", "file_record"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header_len']['start'] = self._io.pos()
            self.header_len = self._io.read_u1()
            self._debug['header_len']['end'] = self._io.pos()
            if self.header_len > 0:
                self._debug['file_record']['start'] = self._io.pos()
                self.file_record = self._root.FileRecord(self._io, self, self._root)
                self.file_record._read()
                self._debug['file_record']['end'] = self._io.pos()



    class FileRecord(KaitaiStruct):
        SEQ_FIELDS = ["header", "file_uncompr_crc16", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self._raw_header = self._io.read_bytes((self._parent.header_len - 1))
            io = KaitaiStream(BytesIO(self._raw_header))
            self.header = self._root.Header(io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            if self.header.header1.lha_level == 0:
                self._debug['file_uncompr_crc16']['start'] = self._io.pos()
                self.file_uncompr_crc16 = self._io.read_u2le()
                self._debug['file_uncompr_crc16']['end'] = self._io.pos()

            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.header.header1.file_size_compr)
            self._debug['body']['end'] = self._io.pos()


    class Header(KaitaiStruct):
        SEQ_FIELDS = ["header1", "filename_len", "filename", "file_uncompr_crc16", "os", "ext_header_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header1']['start'] = self._io.pos()
            self.header1 = self._root.Header1(self._io, self, self._root)
            self.header1._read()
            self._debug['header1']['end'] = self._io.pos()
            if self.header1.lha_level == 0:
                self._debug['filename_len']['start'] = self._io.pos()
                self.filename_len = self._io.read_u1()
                self._debug['filename_len']['end'] = self._io.pos()

            if self.header1.lha_level == 0:
                self._debug['filename']['start'] = self._io.pos()
                self.filename = (self._io.read_bytes(self.filename_len)).decode(u"ASCII")
                self._debug['filename']['end'] = self._io.pos()

            if self.header1.lha_level == 2:
                self._debug['file_uncompr_crc16']['start'] = self._io.pos()
                self.file_uncompr_crc16 = self._io.read_u2le()
                self._debug['file_uncompr_crc16']['end'] = self._io.pos()

            if self.header1.lha_level == 2:
                self._debug['os']['start'] = self._io.pos()
                self.os = self._io.read_u1()
                self._debug['os']['end'] = self._io.pos()

            if self.header1.lha_level == 2:
                self._debug['ext_header_size']['start'] = self._io.pos()
                self.ext_header_size = self._io.read_u2le()
                self._debug['ext_header_size']['end'] = self._io.pos()



    class Header1(KaitaiStruct):
        SEQ_FIELDS = ["header_checksum", "method_id", "file_size_compr", "file_size_uncompr", "file_timestamp", "attr", "lha_level"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header_checksum']['start'] = self._io.pos()
            self.header_checksum = self._io.read_u1()
            self._debug['header_checksum']['end'] = self._io.pos()
            self._debug['method_id']['start'] = self._io.pos()
            self.method_id = (self._io.read_bytes(5)).decode(u"ASCII")
            self._debug['method_id']['end'] = self._io.pos()
            self._debug['file_size_compr']['start'] = self._io.pos()
            self.file_size_compr = self._io.read_u4le()
            self._debug['file_size_compr']['end'] = self._io.pos()
            self._debug['file_size_uncompr']['start'] = self._io.pos()
            self.file_size_uncompr = self._io.read_u4le()
            self._debug['file_size_uncompr']['end'] = self._io.pos()
            self._debug['file_timestamp']['start'] = self._io.pos()
            self.file_timestamp = self._io.read_u4le()
            self._debug['file_timestamp']['end'] = self._io.pos()
            self._debug['attr']['start'] = self._io.pos()
            self.attr = self._io.read_u1()
            self._debug['attr']['end'] = self._io.pos()
            self._debug['lha_level']['start'] = self._io.pos()
            self.lha_level = self._io.read_u1()
            self._debug['lha_level']['end'] = self._io.pos()



