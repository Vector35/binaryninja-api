from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class VmwareVmdk(KaitaiStruct):
    """
    .. seealso::
       Source - https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#41-file-header
    """

    class CompressionMethods(Enum):
        none = 0
        deflate = 1
    SEQ_FIELDS = ["magic", "version", "flags", "size_max", "size_grain", "start_descriptor", "size_descriptor", "num_grain_table_entries", "start_secondary_grain", "start_primary_grain", "size_metadata", "is_dirty", "stuff", "compression_method"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x4B\x44\x4D\x56")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_s4le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._root.HeaderFlags(self._io, self, self._root)
        self.flags._read()
        self._debug['flags']['end'] = self._io.pos()
        self._debug['size_max']['start'] = self._io.pos()
        self.size_max = self._io.read_s8le()
        self._debug['size_max']['end'] = self._io.pos()
        self._debug['size_grain']['start'] = self._io.pos()
        self.size_grain = self._io.read_s8le()
        self._debug['size_grain']['end'] = self._io.pos()
        self._debug['start_descriptor']['start'] = self._io.pos()
        self.start_descriptor = self._io.read_s8le()
        self._debug['start_descriptor']['end'] = self._io.pos()
        self._debug['size_descriptor']['start'] = self._io.pos()
        self.size_descriptor = self._io.read_s8le()
        self._debug['size_descriptor']['end'] = self._io.pos()
        self._debug['num_grain_table_entries']['start'] = self._io.pos()
        self.num_grain_table_entries = self._io.read_s4le()
        self._debug['num_grain_table_entries']['end'] = self._io.pos()
        self._debug['start_secondary_grain']['start'] = self._io.pos()
        self.start_secondary_grain = self._io.read_s8le()
        self._debug['start_secondary_grain']['end'] = self._io.pos()
        self._debug['start_primary_grain']['start'] = self._io.pos()
        self.start_primary_grain = self._io.read_s8le()
        self._debug['start_primary_grain']['end'] = self._io.pos()
        self._debug['size_metadata']['start'] = self._io.pos()
        self.size_metadata = self._io.read_s8le()
        self._debug['size_metadata']['end'] = self._io.pos()
        self._debug['is_dirty']['start'] = self._io.pos()
        self.is_dirty = self._io.read_u1()
        self._debug['is_dirty']['end'] = self._io.pos()
        self._debug['stuff']['start'] = self._io.pos()
        self.stuff = self._io.read_bytes(4)
        self._debug['stuff']['end'] = self._io.pos()
        self._debug['compression_method']['start'] = self._io.pos()
        self.compression_method = KaitaiStream.resolve_enum(self._root.CompressionMethods, self._io.read_u2le())
        self._debug['compression_method']['end'] = self._io.pos()

    class HeaderFlags(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#411-flags
        """
        SEQ_FIELDS = ["reserved1", "zeroed_grain_table_entry", "use_secondary_grain_dir", "valid_new_line_detection_test", "reserved2", "reserved3", "has_metadata", "has_compressed_grain", "reserved4"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(5)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['zeroed_grain_table_entry']['start'] = self._io.pos()
            self.zeroed_grain_table_entry = self._io.read_bits_int(1) != 0
            self._debug['zeroed_grain_table_entry']['end'] = self._io.pos()
            self._debug['use_secondary_grain_dir']['start'] = self._io.pos()
            self.use_secondary_grain_dir = self._io.read_bits_int(1) != 0
            self._debug['use_secondary_grain_dir']['end'] = self._io.pos()
            self._debug['valid_new_line_detection_test']['start'] = self._io.pos()
            self.valid_new_line_detection_test = self._io.read_bits_int(1) != 0
            self._debug['valid_new_line_detection_test']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_u1()
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.read_bits_int(6)
            self._debug['reserved3']['end'] = self._io.pos()
            self._debug['has_metadata']['start'] = self._io.pos()
            self.has_metadata = self._io.read_bits_int(1) != 0
            self._debug['has_metadata']['end'] = self._io.pos()
            self._debug['has_compressed_grain']['start'] = self._io.pos()
            self.has_compressed_grain = self._io.read_bits_int(1) != 0
            self._debug['has_compressed_grain']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['reserved4']['start'] = self._io.pos()
            self.reserved4 = self._io.read_u1()
            self._debug['reserved4']['end'] = self._io.pos()


    @property
    def len_sector(self):
        if hasattr(self, '_m_len_sector'):
            return self._m_len_sector if hasattr(self, '_m_len_sector') else None

        self._m_len_sector = 512
        return self._m_len_sector if hasattr(self, '_m_len_sector') else None

    @property
    def descriptor(self):
        if hasattr(self, '_m_descriptor'):
            return self._m_descriptor if hasattr(self, '_m_descriptor') else None

        _pos = self._io.pos()
        self._io.seek((self.start_descriptor * self._root.len_sector))
        self._debug['_m_descriptor']['start'] = self._io.pos()
        self._m_descriptor = self._io.read_bytes((self.size_descriptor * self._root.len_sector))
        self._debug['_m_descriptor']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_descriptor if hasattr(self, '_m_descriptor') else None

    @property
    def grain_primary(self):
        if hasattr(self, '_m_grain_primary'):
            return self._m_grain_primary if hasattr(self, '_m_grain_primary') else None

        _pos = self._io.pos()
        self._io.seek((self.start_primary_grain * self._root.len_sector))
        self._debug['_m_grain_primary']['start'] = self._io.pos()
        self._m_grain_primary = self._io.read_bytes((self.size_grain * self._root.len_sector))
        self._debug['_m_grain_primary']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_grain_primary if hasattr(self, '_m_grain_primary') else None

    @property
    def grain_secondary(self):
        if hasattr(self, '_m_grain_secondary'):
            return self._m_grain_secondary if hasattr(self, '_m_grain_secondary') else None

        _pos = self._io.pos()
        self._io.seek((self.start_secondary_grain * self._root.len_sector))
        self._debug['_m_grain_secondary']['start'] = self._io.pos()
        self._m_grain_secondary = self._io.read_bytes((self.size_grain * self._root.len_sector))
        self._debug['_m_grain_secondary']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_grain_secondary if hasattr(self, '_m_grain_secondary') else None


