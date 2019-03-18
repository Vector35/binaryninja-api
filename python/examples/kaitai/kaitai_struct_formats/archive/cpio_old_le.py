from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class CpioOldLe(KaitaiStruct):
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
            _t_files = self._root.File(self._io, self, self._root)
            _t_files._read()
            self.files.append(_t_files)
            self._debug['files']['arr'][len(self.files) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['files']['end'] = self._io.pos()

    class File(KaitaiStruct):
        SEQ_FIELDS = ["header", "path_name", "string_terminator", "path_name_padding", "file_data", "file_data_padding", "end_of_file_padding"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self.header = self._root.FileHeader(self._io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            self._debug['path_name']['start'] = self._io.pos()
            self.path_name = self._io.read_bytes((self.header.path_name_size - 1))
            self._debug['path_name']['end'] = self._io.pos()
            self._debug['string_terminator']['start'] = self._io.pos()
            self.string_terminator = self._io.ensure_fixed_contents(b"\x00")
            self._debug['string_terminator']['end'] = self._io.pos()
            if (self.header.path_name_size % 2) == 1:
                self._debug['path_name_padding']['start'] = self._io.pos()
                self.path_name_padding = self._io.ensure_fixed_contents(b"\x00")
                self._debug['path_name_padding']['end'] = self._io.pos()

            self._debug['file_data']['start'] = self._io.pos()
            self.file_data = self._io.read_bytes(self.header.file_size.value)
            self._debug['file_data']['end'] = self._io.pos()
            if (self.header.file_size.value % 2) == 1:
                self._debug['file_data_padding']['start'] = self._io.pos()
                self.file_data_padding = self._io.ensure_fixed_contents(b"\x00")
                self._debug['file_data_padding']['end'] = self._io.pos()

            if  ((self.path_name == b"\x54\x52\x41\x49\x4C\x45\x52\x21\x21\x21") and (self.header.file_size.value == 0)) :
                self._debug['end_of_file_padding']['start'] = self._io.pos()
                self.end_of_file_padding = self._io.read_bytes_full()
                self._debug['end_of_file_padding']['end'] = self._io.pos()



    class FileHeader(KaitaiStruct):
        SEQ_FIELDS = ["magic", "device_number", "inode_number", "mode", "user_id", "group_id", "number_of_links", "r_device_number", "modification_time", "path_name_size", "file_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\xC7\x71")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['device_number']['start'] = self._io.pos()
            self.device_number = self._io.read_u2le()
            self._debug['device_number']['end'] = self._io.pos()
            self._debug['inode_number']['start'] = self._io.pos()
            self.inode_number = self._io.read_u2le()
            self._debug['inode_number']['end'] = self._io.pos()
            self._debug['mode']['start'] = self._io.pos()
            self.mode = self._io.read_u2le()
            self._debug['mode']['end'] = self._io.pos()
            self._debug['user_id']['start'] = self._io.pos()
            self.user_id = self._io.read_u2le()
            self._debug['user_id']['end'] = self._io.pos()
            self._debug['group_id']['start'] = self._io.pos()
            self.group_id = self._io.read_u2le()
            self._debug['group_id']['end'] = self._io.pos()
            self._debug['number_of_links']['start'] = self._io.pos()
            self.number_of_links = self._io.read_u2le()
            self._debug['number_of_links']['end'] = self._io.pos()
            self._debug['r_device_number']['start'] = self._io.pos()
            self.r_device_number = self._io.read_u2le()
            self._debug['r_device_number']['end'] = self._io.pos()
            self._debug['modification_time']['start'] = self._io.pos()
            self.modification_time = self._root.FourByteUnsignedInteger(self._io, self, self._root)
            self.modification_time._read()
            self._debug['modification_time']['end'] = self._io.pos()
            self._debug['path_name_size']['start'] = self._io.pos()
            self.path_name_size = self._io.read_u2le()
            self._debug['path_name_size']['end'] = self._io.pos()
            self._debug['file_size']['start'] = self._io.pos()
            self.file_size = self._root.FourByteUnsignedInteger(self._io, self, self._root)
            self.file_size._read()
            self._debug['file_size']['end'] = self._io.pos()


    class FourByteUnsignedInteger(KaitaiStruct):
        SEQ_FIELDS = ["most_significant_bits", "least_significant_bits"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['most_significant_bits']['start'] = self._io.pos()
            self.most_significant_bits = self._io.read_u2le()
            self._debug['most_significant_bits']['end'] = self._io.pos()
            self._debug['least_significant_bits']['start'] = self._io.pos()
            self.least_significant_bits = self._io.read_u2le()
            self._debug['least_significant_bits']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = (self.least_significant_bits + (self.most_significant_bits << 16))
            return self._m_value if hasattr(self, '_m_value') else None



