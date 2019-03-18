from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Vfat(KaitaiStruct):
    SEQ_FIELDS = ["boot_sector"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['boot_sector']['start'] = self._io.pos()
        self.boot_sector = self._root.BootSector(self._io, self, self._root)
        self.boot_sector._read()
        self._debug['boot_sector']['end'] = self._io.pos()

    class ExtBiosParamBlockFat32(KaitaiStruct):
        """Extended BIOS Parameter Block for FAT32."""
        SEQ_FIELDS = ["ls_per_fat", "has_active_fat", "reserved1", "active_fat_id", "reserved2", "fat_version", "root_dir_start_clus", "ls_fs_info", "boot_sectors_copy_start_ls", "reserved3", "phys_drive_num", "reserved4", "ext_boot_sign", "volume_id", "partition_volume_label", "fs_type_str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ls_per_fat']['start'] = self._io.pos()
            self.ls_per_fat = self._io.read_u4le()
            self._debug['ls_per_fat']['end'] = self._io.pos()
            self._debug['has_active_fat']['start'] = self._io.pos()
            self.has_active_fat = self._io.read_bits_int(1) != 0
            self._debug['has_active_fat']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(3)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['active_fat_id']['start'] = self._io.pos()
            self.active_fat_id = self._io.read_bits_int(4)
            self._debug['active_fat_id']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.ensure_fixed_contents(b"\x00")
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['fat_version']['start'] = self._io.pos()
            self.fat_version = self._io.read_u2le()
            self._debug['fat_version']['end'] = self._io.pos()
            self._debug['root_dir_start_clus']['start'] = self._io.pos()
            self.root_dir_start_clus = self._io.read_u4le()
            self._debug['root_dir_start_clus']['end'] = self._io.pos()
            self._debug['ls_fs_info']['start'] = self._io.pos()
            self.ls_fs_info = self._io.read_u2le()
            self._debug['ls_fs_info']['end'] = self._io.pos()
            self._debug['boot_sectors_copy_start_ls']['start'] = self._io.pos()
            self.boot_sectors_copy_start_ls = self._io.read_u2le()
            self._debug['boot_sectors_copy_start_ls']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.read_bytes(12)
            self._debug['reserved3']['end'] = self._io.pos()
            self._debug['phys_drive_num']['start'] = self._io.pos()
            self.phys_drive_num = self._io.read_u1()
            self._debug['phys_drive_num']['end'] = self._io.pos()
            self._debug['reserved4']['start'] = self._io.pos()
            self.reserved4 = self._io.read_u1()
            self._debug['reserved4']['end'] = self._io.pos()
            self._debug['ext_boot_sign']['start'] = self._io.pos()
            self.ext_boot_sign = self._io.read_u1()
            self._debug['ext_boot_sign']['end'] = self._io.pos()
            self._debug['volume_id']['start'] = self._io.pos()
            self.volume_id = self._io.read_bytes(4)
            self._debug['volume_id']['end'] = self._io.pos()
            self._debug['partition_volume_label']['start'] = self._io.pos()
            self.partition_volume_label = (KaitaiStream.bytes_strip_right(self._io.read_bytes(11), 32)).decode(u"ASCII")
            self._debug['partition_volume_label']['end'] = self._io.pos()
            self._debug['fs_type_str']['start'] = self._io.pos()
            self.fs_type_str = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 32)).decode(u"ASCII")
            self._debug['fs_type_str']['end'] = self._io.pos()


    class BootSector(KaitaiStruct):
        SEQ_FIELDS = ["jmp_instruction", "oem_name", "bpb", "ebpb_fat16", "ebpb_fat32"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['jmp_instruction']['start'] = self._io.pos()
            self.jmp_instruction = self._io.read_bytes(3)
            self._debug['jmp_instruction']['end'] = self._io.pos()
            self._debug['oem_name']['start'] = self._io.pos()
            self.oem_name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 32)).decode(u"ASCII")
            self._debug['oem_name']['end'] = self._io.pos()
            self._debug['bpb']['start'] = self._io.pos()
            self.bpb = self._root.BiosParamBlock(self._io, self, self._root)
            self.bpb._read()
            self._debug['bpb']['end'] = self._io.pos()
            if not (self.is_fat32):
                self._debug['ebpb_fat16']['start'] = self._io.pos()
                self.ebpb_fat16 = self._root.ExtBiosParamBlockFat16(self._io, self, self._root)
                self.ebpb_fat16._read()
                self._debug['ebpb_fat16']['end'] = self._io.pos()

            if self.is_fat32:
                self._debug['ebpb_fat32']['start'] = self._io.pos()
                self.ebpb_fat32 = self._root.ExtBiosParamBlockFat32(self._io, self, self._root)
                self.ebpb_fat32._read()
                self._debug['ebpb_fat32']['end'] = self._io.pos()


        @property
        def pos_fats(self):
            """Offset of FATs in bytes from start of filesystem."""
            if hasattr(self, '_m_pos_fats'):
                return self._m_pos_fats if hasattr(self, '_m_pos_fats') else None

            self._m_pos_fats = (self.bpb.bytes_per_ls * self.bpb.num_reserved_ls)
            return self._m_pos_fats if hasattr(self, '_m_pos_fats') else None

        @property
        def ls_per_fat(self):
            if hasattr(self, '_m_ls_per_fat'):
                return self._m_ls_per_fat if hasattr(self, '_m_ls_per_fat') else None

            self._m_ls_per_fat = (self.ebpb_fat32.ls_per_fat if self.is_fat32 else self.bpb.ls_per_fat)
            return self._m_ls_per_fat if hasattr(self, '_m_ls_per_fat') else None

        @property
        def ls_per_root_dir(self):
            """Size of root directory in logical sectors.
            
            .. seealso::
               FAT: General Overview of On-Disk Format, section "FAT Data Structure"
            """
            if hasattr(self, '_m_ls_per_root_dir'):
                return self._m_ls_per_root_dir if hasattr(self, '_m_ls_per_root_dir') else None

            self._m_ls_per_root_dir = (((self.bpb.max_root_dir_rec * 32) + self.bpb.bytes_per_ls) - 1) // self.bpb.bytes_per_ls
            return self._m_ls_per_root_dir if hasattr(self, '_m_ls_per_root_dir') else None

        @property
        def is_fat32(self):
            """Determines if filesystem is FAT32 (true) or FAT12/16 (false)
            by analyzing some preliminary conditions in BPB. Used to
            determine whether we should parse post-BPB data as
            `ext_bios_param_block_fat16` or `ext_bios_param_block_fat32`.
            """
            if hasattr(self, '_m_is_fat32'):
                return self._m_is_fat32 if hasattr(self, '_m_is_fat32') else None

            self._m_is_fat32 = self.bpb.max_root_dir_rec == 0
            return self._m_is_fat32 if hasattr(self, '_m_is_fat32') else None

        @property
        def size_fat(self):
            """Size of one FAT in bytes."""
            if hasattr(self, '_m_size_fat'):
                return self._m_size_fat if hasattr(self, '_m_size_fat') else None

            self._m_size_fat = (self.bpb.bytes_per_ls * self.ls_per_fat)
            return self._m_size_fat if hasattr(self, '_m_size_fat') else None

        @property
        def pos_root_dir(self):
            """Offset of root directory in bytes from start of filesystem."""
            if hasattr(self, '_m_pos_root_dir'):
                return self._m_pos_root_dir if hasattr(self, '_m_pos_root_dir') else None

            self._m_pos_root_dir = (self.bpb.bytes_per_ls * (self.bpb.num_reserved_ls + (self.ls_per_fat * self.bpb.num_fats)))
            return self._m_pos_root_dir if hasattr(self, '_m_pos_root_dir') else None

        @property
        def size_root_dir(self):
            """Size of root directory in bytes."""
            if hasattr(self, '_m_size_root_dir'):
                return self._m_size_root_dir if hasattr(self, '_m_size_root_dir') else None

            self._m_size_root_dir = (self.ls_per_root_dir * self.bpb.bytes_per_ls)
            return self._m_size_root_dir if hasattr(self, '_m_size_root_dir') else None


    class BiosParamBlock(KaitaiStruct):
        SEQ_FIELDS = ["bytes_per_ls", "ls_per_clus", "num_reserved_ls", "num_fats", "max_root_dir_rec", "total_ls_2", "media_code", "ls_per_fat", "ps_per_track", "num_heads", "num_hidden_sectors", "total_ls_4"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bytes_per_ls']['start'] = self._io.pos()
            self.bytes_per_ls = self._io.read_u2le()
            self._debug['bytes_per_ls']['end'] = self._io.pos()
            self._debug['ls_per_clus']['start'] = self._io.pos()
            self.ls_per_clus = self._io.read_u1()
            self._debug['ls_per_clus']['end'] = self._io.pos()
            self._debug['num_reserved_ls']['start'] = self._io.pos()
            self.num_reserved_ls = self._io.read_u2le()
            self._debug['num_reserved_ls']['end'] = self._io.pos()
            self._debug['num_fats']['start'] = self._io.pos()
            self.num_fats = self._io.read_u1()
            self._debug['num_fats']['end'] = self._io.pos()
            self._debug['max_root_dir_rec']['start'] = self._io.pos()
            self.max_root_dir_rec = self._io.read_u2le()
            self._debug['max_root_dir_rec']['end'] = self._io.pos()
            self._debug['total_ls_2']['start'] = self._io.pos()
            self.total_ls_2 = self._io.read_u2le()
            self._debug['total_ls_2']['end'] = self._io.pos()
            self._debug['media_code']['start'] = self._io.pos()
            self.media_code = self._io.read_u1()
            self._debug['media_code']['end'] = self._io.pos()
            self._debug['ls_per_fat']['start'] = self._io.pos()
            self.ls_per_fat = self._io.read_u2le()
            self._debug['ls_per_fat']['end'] = self._io.pos()
            self._debug['ps_per_track']['start'] = self._io.pos()
            self.ps_per_track = self._io.read_u2le()
            self._debug['ps_per_track']['end'] = self._io.pos()
            self._debug['num_heads']['start'] = self._io.pos()
            self.num_heads = self._io.read_u2le()
            self._debug['num_heads']['end'] = self._io.pos()
            self._debug['num_hidden_sectors']['start'] = self._io.pos()
            self.num_hidden_sectors = self._io.read_u4le()
            self._debug['num_hidden_sectors']['end'] = self._io.pos()
            self._debug['total_ls_4']['start'] = self._io.pos()
            self.total_ls_4 = self._io.read_u4le()
            self._debug['total_ls_4']['end'] = self._io.pos()


    class RootDirectoryRec(KaitaiStruct):
        SEQ_FIELDS = ["file_name", "attribute", "reserved", "time", "date", "start_clus", "file_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['file_name']['start'] = self._io.pos()
            self.file_name = self._io.read_bytes(11)
            self._debug['file_name']['end'] = self._io.pos()
            self._debug['attribute']['start'] = self._io.pos()
            self.attribute = self._io.read_u1()
            self._debug['attribute']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(10)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['time']['start'] = self._io.pos()
            self.time = self._io.read_u2le()
            self._debug['time']['end'] = self._io.pos()
            self._debug['date']['start'] = self._io.pos()
            self.date = self._io.read_u2le()
            self._debug['date']['end'] = self._io.pos()
            self._debug['start_clus']['start'] = self._io.pos()
            self.start_clus = self._io.read_u2le()
            self._debug['start_clus']['end'] = self._io.pos()
            self._debug['file_size']['start'] = self._io.pos()
            self.file_size = self._io.read_u4le()
            self._debug['file_size']['end'] = self._io.pos()


    class RootDirectory(KaitaiStruct):
        SEQ_FIELDS = ["records"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['records']['start'] = self._io.pos()
            self.records = [None] * (self._root.boot_sector.bpb.max_root_dir_rec)
            for i in range(self._root.boot_sector.bpb.max_root_dir_rec):
                if not 'arr' in self._debug['records']:
                    self._debug['records']['arr'] = []
                self._debug['records']['arr'].append({'start': self._io.pos()})
                _t_records = self._root.RootDirectoryRec(self._io, self, self._root)
                _t_records._read()
                self.records[i] = _t_records
                self._debug['records']['arr'][i]['end'] = self._io.pos()

            self._debug['records']['end'] = self._io.pos()


    class ExtBiosParamBlockFat16(KaitaiStruct):
        """Extended BIOS Parameter Block (DOS 4.0+, OS/2 1.0+). Used only
        for FAT12 and FAT16.
        """
        SEQ_FIELDS = ["phys_drive_num", "reserved1", "ext_boot_sign", "volume_id", "partition_volume_label", "fs_type_str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['phys_drive_num']['start'] = self._io.pos()
            self.phys_drive_num = self._io.read_u1()
            self._debug['phys_drive_num']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_u1()
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['ext_boot_sign']['start'] = self._io.pos()
            self.ext_boot_sign = self._io.read_u1()
            self._debug['ext_boot_sign']['end'] = self._io.pos()
            self._debug['volume_id']['start'] = self._io.pos()
            self.volume_id = self._io.read_bytes(4)
            self._debug['volume_id']['end'] = self._io.pos()
            self._debug['partition_volume_label']['start'] = self._io.pos()
            self.partition_volume_label = (KaitaiStream.bytes_strip_right(self._io.read_bytes(11), 32)).decode(u"ASCII")
            self._debug['partition_volume_label']['end'] = self._io.pos()
            self._debug['fs_type_str']['start'] = self._io.pos()
            self.fs_type_str = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 32)).decode(u"ASCII")
            self._debug['fs_type_str']['end'] = self._io.pos()


    @property
    def fats(self):
        if hasattr(self, '_m_fats'):
            return self._m_fats if hasattr(self, '_m_fats') else None

        _pos = self._io.pos()
        self._io.seek(self.boot_sector.pos_fats)
        self._debug['_m_fats']['start'] = self._io.pos()
        self._m_fats = [None] * (self.boot_sector.bpb.num_fats)
        for i in range(self.boot_sector.bpb.num_fats):
            if not 'arr' in self._debug['_m_fats']:
                self._debug['_m_fats']['arr'] = []
            self._debug['_m_fats']['arr'].append({'start': self._io.pos()})
            self._m_fats[i] = self._io.read_bytes(self.boot_sector.size_fat)
            self._debug['_m_fats']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_fats']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_fats if hasattr(self, '_m_fats') else None

    @property
    def root_dir(self):
        if hasattr(self, '_m_root_dir'):
            return self._m_root_dir if hasattr(self, '_m_root_dir') else None

        _pos = self._io.pos()
        self._io.seek(self.boot_sector.pos_root_dir)
        self._debug['_m_root_dir']['start'] = self._io.pos()
        self._raw__m_root_dir = self._io.read_bytes(self.boot_sector.size_root_dir)
        io = KaitaiStream(BytesIO(self._raw__m_root_dir))
        self._m_root_dir = self._root.RootDirectory(io, self, self._root)
        self._m_root_dir._read()
        self._debug['_m_root_dir']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_root_dir if hasattr(self, '_m_root_dir') else None


