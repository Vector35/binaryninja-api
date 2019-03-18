from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Iso9660(KaitaiStruct):
    """ISO9660 is standard filesystem used on read-only optical discs
    (mostly CD-ROM). The standard was based on earlier High Sierra
    Format (HSF), proposed for CD-ROMs in 1985, and, after several
    revisions, it was accepted as ISO9960:1998.
    
    The format emphasizes portability (thus having pretty minimal
    features and very conservative file names standards) and sequential
    access (which favors disc devices with relatively slow rotation
    speed).
    """
    SEQ_FIELDS = []
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        pass

    class VolDescPrimary(KaitaiStruct):
        """
        .. seealso::
           Source - http://wiki.osdev.org/ISO_9660#The_Primary_Volume_Descriptor
        """
        SEQ_FIELDS = ["unused1", "system_id", "volume_id", "unused2", "vol_space_size", "unused3", "vol_set_size", "vol_seq_num", "logical_block_size", "path_table_size", "lba_path_table_le", "lba_opt_path_table_le", "lba_path_table_be", "lba_opt_path_table_be", "root_dir", "vol_set_id", "publisher_id", "data_preparer_id", "application_id", "copyright_file_id", "abstract_file_id", "bibliographic_file_id", "vol_create_datetime", "vol_mod_datetime", "vol_expire_datetime", "vol_effective_datetime", "file_structure_version", "unused4", "application_area"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['unused1']['start'] = self._io.pos()
            self.unused1 = self._io.ensure_fixed_contents(b"\x00")
            self._debug['unused1']['end'] = self._io.pos()
            self._debug['system_id']['start'] = self._io.pos()
            self.system_id = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['system_id']['end'] = self._io.pos()
            self._debug['volume_id']['start'] = self._io.pos()
            self.volume_id = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['volume_id']['end'] = self._io.pos()
            self._debug['unused2']['start'] = self._io.pos()
            self.unused2 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            self._debug['unused2']['end'] = self._io.pos()
            self._debug['vol_space_size']['start'] = self._io.pos()
            self.vol_space_size = self._root.U4bi(self._io, self, self._root)
            self.vol_space_size._read()
            self._debug['vol_space_size']['end'] = self._io.pos()
            self._debug['unused3']['start'] = self._io.pos()
            self.unused3 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            self._debug['unused3']['end'] = self._io.pos()
            self._debug['vol_set_size']['start'] = self._io.pos()
            self.vol_set_size = self._root.U2bi(self._io, self, self._root)
            self.vol_set_size._read()
            self._debug['vol_set_size']['end'] = self._io.pos()
            self._debug['vol_seq_num']['start'] = self._io.pos()
            self.vol_seq_num = self._root.U2bi(self._io, self, self._root)
            self.vol_seq_num._read()
            self._debug['vol_seq_num']['end'] = self._io.pos()
            self._debug['logical_block_size']['start'] = self._io.pos()
            self.logical_block_size = self._root.U2bi(self._io, self, self._root)
            self.logical_block_size._read()
            self._debug['logical_block_size']['end'] = self._io.pos()
            self._debug['path_table_size']['start'] = self._io.pos()
            self.path_table_size = self._root.U4bi(self._io, self, self._root)
            self.path_table_size._read()
            self._debug['path_table_size']['end'] = self._io.pos()
            self._debug['lba_path_table_le']['start'] = self._io.pos()
            self.lba_path_table_le = self._io.read_u4le()
            self._debug['lba_path_table_le']['end'] = self._io.pos()
            self._debug['lba_opt_path_table_le']['start'] = self._io.pos()
            self.lba_opt_path_table_le = self._io.read_u4le()
            self._debug['lba_opt_path_table_le']['end'] = self._io.pos()
            self._debug['lba_path_table_be']['start'] = self._io.pos()
            self.lba_path_table_be = self._io.read_u4be()
            self._debug['lba_path_table_be']['end'] = self._io.pos()
            self._debug['lba_opt_path_table_be']['start'] = self._io.pos()
            self.lba_opt_path_table_be = self._io.read_u4be()
            self._debug['lba_opt_path_table_be']['end'] = self._io.pos()
            self._debug['root_dir']['start'] = self._io.pos()
            self._raw_root_dir = self._io.read_bytes(34)
            io = KaitaiStream(BytesIO(self._raw_root_dir))
            self.root_dir = self._root.DirEntry(io, self, self._root)
            self.root_dir._read()
            self._debug['root_dir']['end'] = self._io.pos()
            self._debug['vol_set_id']['start'] = self._io.pos()
            self.vol_set_id = (self._io.read_bytes(128)).decode(u"UTF-8")
            self._debug['vol_set_id']['end'] = self._io.pos()
            self._debug['publisher_id']['start'] = self._io.pos()
            self.publisher_id = (self._io.read_bytes(128)).decode(u"UTF-8")
            self._debug['publisher_id']['end'] = self._io.pos()
            self._debug['data_preparer_id']['start'] = self._io.pos()
            self.data_preparer_id = (self._io.read_bytes(128)).decode(u"UTF-8")
            self._debug['data_preparer_id']['end'] = self._io.pos()
            self._debug['application_id']['start'] = self._io.pos()
            self.application_id = (self._io.read_bytes(128)).decode(u"UTF-8")
            self._debug['application_id']['end'] = self._io.pos()
            self._debug['copyright_file_id']['start'] = self._io.pos()
            self.copyright_file_id = (self._io.read_bytes(38)).decode(u"UTF-8")
            self._debug['copyright_file_id']['end'] = self._io.pos()
            self._debug['abstract_file_id']['start'] = self._io.pos()
            self.abstract_file_id = (self._io.read_bytes(36)).decode(u"UTF-8")
            self._debug['abstract_file_id']['end'] = self._io.pos()
            self._debug['bibliographic_file_id']['start'] = self._io.pos()
            self.bibliographic_file_id = (self._io.read_bytes(37)).decode(u"UTF-8")
            self._debug['bibliographic_file_id']['end'] = self._io.pos()
            self._debug['vol_create_datetime']['start'] = self._io.pos()
            self.vol_create_datetime = self._root.DecDatetime(self._io, self, self._root)
            self.vol_create_datetime._read()
            self._debug['vol_create_datetime']['end'] = self._io.pos()
            self._debug['vol_mod_datetime']['start'] = self._io.pos()
            self.vol_mod_datetime = self._root.DecDatetime(self._io, self, self._root)
            self.vol_mod_datetime._read()
            self._debug['vol_mod_datetime']['end'] = self._io.pos()
            self._debug['vol_expire_datetime']['start'] = self._io.pos()
            self.vol_expire_datetime = self._root.DecDatetime(self._io, self, self._root)
            self.vol_expire_datetime._read()
            self._debug['vol_expire_datetime']['end'] = self._io.pos()
            self._debug['vol_effective_datetime']['start'] = self._io.pos()
            self.vol_effective_datetime = self._root.DecDatetime(self._io, self, self._root)
            self.vol_effective_datetime._read()
            self._debug['vol_effective_datetime']['end'] = self._io.pos()
            self._debug['file_structure_version']['start'] = self._io.pos()
            self.file_structure_version = self._io.read_u1()
            self._debug['file_structure_version']['end'] = self._io.pos()
            self._debug['unused4']['start'] = self._io.pos()
            self.unused4 = self._io.read_u1()
            self._debug['unused4']['end'] = self._io.pos()
            self._debug['application_area']['start'] = self._io.pos()
            self.application_area = self._io.read_bytes(512)
            self._debug['application_area']['end'] = self._io.pos()

        @property
        def path_table(self):
            if hasattr(self, '_m_path_table'):
                return self._m_path_table if hasattr(self, '_m_path_table') else None

            _pos = self._io.pos()
            self._io.seek((self.lba_path_table_le * self._root.sector_size))
            self._debug['_m_path_table']['start'] = self._io.pos()
            self._raw__m_path_table = self._io.read_bytes(self.path_table_size.le)
            io = KaitaiStream(BytesIO(self._raw__m_path_table))
            self._m_path_table = self._root.PathTableLe(io, self, self._root)
            self._m_path_table._read()
            self._debug['_m_path_table']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_path_table if hasattr(self, '_m_path_table') else None


    class VolDescBootRecord(KaitaiStruct):
        SEQ_FIELDS = ["boot_system_id", "boot_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['boot_system_id']['start'] = self._io.pos()
            self.boot_system_id = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['boot_system_id']['end'] = self._io.pos()
            self._debug['boot_id']['start'] = self._io.pos()
            self.boot_id = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['boot_id']['end'] = self._io.pos()


    class Datetime(KaitaiStruct):
        SEQ_FIELDS = ["year", "month", "day", "hour", "minute", "sec", "timezone"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['year']['start'] = self._io.pos()
            self.year = self._io.read_u1()
            self._debug['year']['end'] = self._io.pos()
            self._debug['month']['start'] = self._io.pos()
            self.month = self._io.read_u1()
            self._debug['month']['end'] = self._io.pos()
            self._debug['day']['start'] = self._io.pos()
            self.day = self._io.read_u1()
            self._debug['day']['end'] = self._io.pos()
            self._debug['hour']['start'] = self._io.pos()
            self.hour = self._io.read_u1()
            self._debug['hour']['end'] = self._io.pos()
            self._debug['minute']['start'] = self._io.pos()
            self.minute = self._io.read_u1()
            self._debug['minute']['end'] = self._io.pos()
            self._debug['sec']['start'] = self._io.pos()
            self.sec = self._io.read_u1()
            self._debug['sec']['end'] = self._io.pos()
            self._debug['timezone']['start'] = self._io.pos()
            self.timezone = self._io.read_u1()
            self._debug['timezone']['end'] = self._io.pos()


    class DirEntry(KaitaiStruct):
        SEQ_FIELDS = ["len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u1()
            self._debug['len']['end'] = self._io.pos()
            if self.len > 0:
                self._debug['body']['start'] = self._io.pos()
                self._raw_body = self._io.read_bytes((self.len - 1))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DirEntryBody(io, self, self._root)
                self.body._read()
                self._debug['body']['end'] = self._io.pos()



    class VolDesc(KaitaiStruct):
        SEQ_FIELDS = ["type", "magic", "version", "vol_desc_boot_record", "vol_desc_primary"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u1()
            self._debug['type']['end'] = self._io.pos()
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x43\x44\x30\x30\x31")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            if self.type == 0:
                self._debug['vol_desc_boot_record']['start'] = self._io.pos()
                self.vol_desc_boot_record = self._root.VolDescBootRecord(self._io, self, self._root)
                self.vol_desc_boot_record._read()
                self._debug['vol_desc_boot_record']['end'] = self._io.pos()

            if self.type == 1:
                self._debug['vol_desc_primary']['start'] = self._io.pos()
                self.vol_desc_primary = self._root.VolDescPrimary(self._io, self, self._root)
                self.vol_desc_primary._read()
                self._debug['vol_desc_primary']['end'] = self._io.pos()



    class PathTableEntryLe(KaitaiStruct):
        SEQ_FIELDS = ["len_dir_name", "len_ext_attr_rec", "lba_extent", "parent_dir_idx", "dir_name", "padding"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_dir_name']['start'] = self._io.pos()
            self.len_dir_name = self._io.read_u1()
            self._debug['len_dir_name']['end'] = self._io.pos()
            self._debug['len_ext_attr_rec']['start'] = self._io.pos()
            self.len_ext_attr_rec = self._io.read_u1()
            self._debug['len_ext_attr_rec']['end'] = self._io.pos()
            self._debug['lba_extent']['start'] = self._io.pos()
            self.lba_extent = self._io.read_u4le()
            self._debug['lba_extent']['end'] = self._io.pos()
            self._debug['parent_dir_idx']['start'] = self._io.pos()
            self.parent_dir_idx = self._io.read_u2le()
            self._debug['parent_dir_idx']['end'] = self._io.pos()
            self._debug['dir_name']['start'] = self._io.pos()
            self.dir_name = (self._io.read_bytes(self.len_dir_name)).decode(u"UTF-8")
            self._debug['dir_name']['end'] = self._io.pos()
            if (self.len_dir_name % 2) == 1:
                self._debug['padding']['start'] = self._io.pos()
                self.padding = self._io.read_u1()
                self._debug['padding']['end'] = self._io.pos()



    class DirEntries(KaitaiStruct):
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
            while True:
                if not 'arr' in self._debug['entries']:
                    self._debug['entries']['arr'] = []
                self._debug['entries']['arr'].append({'start': self._io.pos()})
                _t_entries = self._root.DirEntry(self._io, self, self._root)
                _t_entries._read()
                _ = _t_entries
                self.entries.append(_)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                if _.len == 0:
                    break
                i += 1
            self._debug['entries']['end'] = self._io.pos()


    class U4bi(KaitaiStruct):
        SEQ_FIELDS = ["le", "be"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['le']['start'] = self._io.pos()
            self.le = self._io.read_u4le()
            self._debug['le']['end'] = self._io.pos()
            self._debug['be']['start'] = self._io.pos()
            self.be = self._io.read_u4be()
            self._debug['be']['end'] = self._io.pos()


    class U2bi(KaitaiStruct):
        SEQ_FIELDS = ["le", "be"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['le']['start'] = self._io.pos()
            self.le = self._io.read_u2le()
            self._debug['le']['end'] = self._io.pos()
            self._debug['be']['start'] = self._io.pos()
            self.be = self._io.read_u2be()
            self._debug['be']['end'] = self._io.pos()


    class PathTableLe(KaitaiStruct):
        """
        .. seealso::
           Source - http://wiki.osdev.org/ISO_9660#The_Path_Table
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
                _t_entries = self._root.PathTableEntryLe(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class DecDatetime(KaitaiStruct):
        """
        .. seealso::
           Source - http://wiki.osdev.org/ISO_9660#Date.2Ftime_format
        """
        SEQ_FIELDS = ["year", "month", "day", "hour", "minute", "sec", "sec_hundreds", "timezone"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['year']['start'] = self._io.pos()
            self.year = (self._io.read_bytes(4)).decode(u"ASCII")
            self._debug['year']['end'] = self._io.pos()
            self._debug['month']['start'] = self._io.pos()
            self.month = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['month']['end'] = self._io.pos()
            self._debug['day']['start'] = self._io.pos()
            self.day = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['day']['end'] = self._io.pos()
            self._debug['hour']['start'] = self._io.pos()
            self.hour = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['hour']['end'] = self._io.pos()
            self._debug['minute']['start'] = self._io.pos()
            self.minute = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['minute']['end'] = self._io.pos()
            self._debug['sec']['start'] = self._io.pos()
            self.sec = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['sec']['end'] = self._io.pos()
            self._debug['sec_hundreds']['start'] = self._io.pos()
            self.sec_hundreds = (self._io.read_bytes(2)).decode(u"ASCII")
            self._debug['sec_hundreds']['end'] = self._io.pos()
            self._debug['timezone']['start'] = self._io.pos()
            self.timezone = self._io.read_u1()
            self._debug['timezone']['end'] = self._io.pos()


    class DirEntryBody(KaitaiStruct):
        SEQ_FIELDS = ["len_ext_attr_rec", "lba_extent", "size_extent", "datetime", "file_flags", "file_unit_size", "interleave_gap_size", "vol_seq_num", "len_file_name", "file_name", "padding", "rest"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_ext_attr_rec']['start'] = self._io.pos()
            self.len_ext_attr_rec = self._io.read_u1()
            self._debug['len_ext_attr_rec']['end'] = self._io.pos()
            self._debug['lba_extent']['start'] = self._io.pos()
            self.lba_extent = self._root.U4bi(self._io, self, self._root)
            self.lba_extent._read()
            self._debug['lba_extent']['end'] = self._io.pos()
            self._debug['size_extent']['start'] = self._io.pos()
            self.size_extent = self._root.U4bi(self._io, self, self._root)
            self.size_extent._read()
            self._debug['size_extent']['end'] = self._io.pos()
            self._debug['datetime']['start'] = self._io.pos()
            self.datetime = self._root.Datetime(self._io, self, self._root)
            self.datetime._read()
            self._debug['datetime']['end'] = self._io.pos()
            self._debug['file_flags']['start'] = self._io.pos()
            self.file_flags = self._io.read_u1()
            self._debug['file_flags']['end'] = self._io.pos()
            self._debug['file_unit_size']['start'] = self._io.pos()
            self.file_unit_size = self._io.read_u1()
            self._debug['file_unit_size']['end'] = self._io.pos()
            self._debug['interleave_gap_size']['start'] = self._io.pos()
            self.interleave_gap_size = self._io.read_u1()
            self._debug['interleave_gap_size']['end'] = self._io.pos()
            self._debug['vol_seq_num']['start'] = self._io.pos()
            self.vol_seq_num = self._root.U2bi(self._io, self, self._root)
            self.vol_seq_num._read()
            self._debug['vol_seq_num']['end'] = self._io.pos()
            self._debug['len_file_name']['start'] = self._io.pos()
            self.len_file_name = self._io.read_u1()
            self._debug['len_file_name']['end'] = self._io.pos()
            self._debug['file_name']['start'] = self._io.pos()
            self.file_name = (self._io.read_bytes(self.len_file_name)).decode(u"UTF-8")
            self._debug['file_name']['end'] = self._io.pos()
            if (self.len_file_name % 2) == 0:
                self._debug['padding']['start'] = self._io.pos()
                self.padding = self._io.read_u1()
                self._debug['padding']['end'] = self._io.pos()

            self._debug['rest']['start'] = self._io.pos()
            self.rest = self._io.read_bytes_full()
            self._debug['rest']['end'] = self._io.pos()

        @property
        def extent_as_dir(self):
            if hasattr(self, '_m_extent_as_dir'):
                return self._m_extent_as_dir if hasattr(self, '_m_extent_as_dir') else None

            if (self.file_flags & 2) != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek((self.lba_extent.le * self._root.sector_size))
                self._debug['_m_extent_as_dir']['start'] = io.pos()
                self._raw__m_extent_as_dir = io.read_bytes(self.size_extent.le)
                io = KaitaiStream(BytesIO(self._raw__m_extent_as_dir))
                self._m_extent_as_dir = self._root.DirEntries(io, self, self._root)
                self._m_extent_as_dir._read()
                self._debug['_m_extent_as_dir']['end'] = io.pos()
                io.seek(_pos)

            return self._m_extent_as_dir if hasattr(self, '_m_extent_as_dir') else None

        @property
        def extent_as_file(self):
            if hasattr(self, '_m_extent_as_file'):
                return self._m_extent_as_file if hasattr(self, '_m_extent_as_file') else None

            if (self.file_flags & 2) == 0:
                io = self._root._io
                _pos = io.pos()
                io.seek((self.lba_extent.le * self._root.sector_size))
                self._debug['_m_extent_as_file']['start'] = io.pos()
                self._m_extent_as_file = io.read_bytes(self.size_extent.le)
                self._debug['_m_extent_as_file']['end'] = io.pos()
                io.seek(_pos)

            return self._m_extent_as_file if hasattr(self, '_m_extent_as_file') else None


    @property
    def sector_size(self):
        if hasattr(self, '_m_sector_size'):
            return self._m_sector_size if hasattr(self, '_m_sector_size') else None

        self._m_sector_size = 2048
        return self._m_sector_size if hasattr(self, '_m_sector_size') else None

    @property
    def primary_vol_desc(self):
        if hasattr(self, '_m_primary_vol_desc'):
            return self._m_primary_vol_desc if hasattr(self, '_m_primary_vol_desc') else None

        _pos = self._io.pos()
        self._io.seek((16 * self.sector_size))
        self._debug['_m_primary_vol_desc']['start'] = self._io.pos()
        self._m_primary_vol_desc = self._root.VolDesc(self._io, self, self._root)
        self._m_primary_vol_desc._read()
        self._debug['_m_primary_vol_desc']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_primary_vol_desc if hasattr(self, '_m_primary_vol_desc') else None


