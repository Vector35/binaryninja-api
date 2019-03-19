# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Ext2(KaitaiStruct):
    SEQ_FIELDS = []
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        pass

    class SuperBlockStruct(KaitaiStruct):

        class StateEnum(Enum):
            valid_fs = 1
            error_fs = 2

        class ErrorsEnum(Enum):
            act_continue = 1
            act_ro = 2
            act_panic = 3
        SEQ_FIELDS = ["inodes_count", "blocks_count", "r_blocks_count", "free_blocks_count", "free_inodes_count", "first_data_block", "log_block_size", "log_frag_size", "blocks_per_group", "frags_per_group", "inodes_per_group", "mtime", "wtime", "mnt_count", "max_mnt_count", "magic", "state", "errors", "minor_rev_level", "lastcheck", "checkinterval", "creator_os", "rev_level", "def_resuid", "def_resgid", "first_ino", "inode_size", "block_group_nr", "feature_compat", "feature_incompat", "feature_ro_compat", "uuid", "volume_name", "last_mounted", "algo_bitmap", "prealloc_blocks", "prealloc_dir_blocks", "padding1", "journal_uuid", "journal_inum", "journal_dev", "last_orphan", "hash_seed", "def_hash_version"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['inodes_count']['start'] = self._io.pos()
            self.inodes_count = self._io.read_u4le()
            self._debug['inodes_count']['end'] = self._io.pos()
            self._debug['blocks_count']['start'] = self._io.pos()
            self.blocks_count = self._io.read_u4le()
            self._debug['blocks_count']['end'] = self._io.pos()
            self._debug['r_blocks_count']['start'] = self._io.pos()
            self.r_blocks_count = self._io.read_u4le()
            self._debug['r_blocks_count']['end'] = self._io.pos()
            self._debug['free_blocks_count']['start'] = self._io.pos()
            self.free_blocks_count = self._io.read_u4le()
            self._debug['free_blocks_count']['end'] = self._io.pos()
            self._debug['free_inodes_count']['start'] = self._io.pos()
            self.free_inodes_count = self._io.read_u4le()
            self._debug['free_inodes_count']['end'] = self._io.pos()
            self._debug['first_data_block']['start'] = self._io.pos()
            self.first_data_block = self._io.read_u4le()
            self._debug['first_data_block']['end'] = self._io.pos()
            self._debug['log_block_size']['start'] = self._io.pos()
            self.log_block_size = self._io.read_u4le()
            self._debug['log_block_size']['end'] = self._io.pos()
            self._debug['log_frag_size']['start'] = self._io.pos()
            self.log_frag_size = self._io.read_u4le()
            self._debug['log_frag_size']['end'] = self._io.pos()
            self._debug['blocks_per_group']['start'] = self._io.pos()
            self.blocks_per_group = self._io.read_u4le()
            self._debug['blocks_per_group']['end'] = self._io.pos()
            self._debug['frags_per_group']['start'] = self._io.pos()
            self.frags_per_group = self._io.read_u4le()
            self._debug['frags_per_group']['end'] = self._io.pos()
            self._debug['inodes_per_group']['start'] = self._io.pos()
            self.inodes_per_group = self._io.read_u4le()
            self._debug['inodes_per_group']['end'] = self._io.pos()
            self._debug['mtime']['start'] = self._io.pos()
            self.mtime = self._io.read_u4le()
            self._debug['mtime']['end'] = self._io.pos()
            self._debug['wtime']['start'] = self._io.pos()
            self.wtime = self._io.read_u4le()
            self._debug['wtime']['end'] = self._io.pos()
            self._debug['mnt_count']['start'] = self._io.pos()
            self.mnt_count = self._io.read_u2le()
            self._debug['mnt_count']['end'] = self._io.pos()
            self._debug['max_mnt_count']['start'] = self._io.pos()
            self.max_mnt_count = self._io.read_u2le()
            self._debug['max_mnt_count']['end'] = self._io.pos()
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x53\xEF")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['state']['start'] = self._io.pos()
            self.state = KaitaiStream.resolve_enum(self._root.SuperBlockStruct.StateEnum, self._io.read_u2le())
            self._debug['state']['end'] = self._io.pos()
            self._debug['errors']['start'] = self._io.pos()
            self.errors = KaitaiStream.resolve_enum(self._root.SuperBlockStruct.ErrorsEnum, self._io.read_u2le())
            self._debug['errors']['end'] = self._io.pos()
            self._debug['minor_rev_level']['start'] = self._io.pos()
            self.minor_rev_level = self._io.read_u2le()
            self._debug['minor_rev_level']['end'] = self._io.pos()
            self._debug['lastcheck']['start'] = self._io.pos()
            self.lastcheck = self._io.read_u4le()
            self._debug['lastcheck']['end'] = self._io.pos()
            self._debug['checkinterval']['start'] = self._io.pos()
            self.checkinterval = self._io.read_u4le()
            self._debug['checkinterval']['end'] = self._io.pos()
            self._debug['creator_os']['start'] = self._io.pos()
            self.creator_os = self._io.read_u4le()
            self._debug['creator_os']['end'] = self._io.pos()
            self._debug['rev_level']['start'] = self._io.pos()
            self.rev_level = self._io.read_u4le()
            self._debug['rev_level']['end'] = self._io.pos()
            self._debug['def_resuid']['start'] = self._io.pos()
            self.def_resuid = self._io.read_u2le()
            self._debug['def_resuid']['end'] = self._io.pos()
            self._debug['def_resgid']['start'] = self._io.pos()
            self.def_resgid = self._io.read_u2le()
            self._debug['def_resgid']['end'] = self._io.pos()
            self._debug['first_ino']['start'] = self._io.pos()
            self.first_ino = self._io.read_u4le()
            self._debug['first_ino']['end'] = self._io.pos()
            self._debug['inode_size']['start'] = self._io.pos()
            self.inode_size = self._io.read_u2le()
            self._debug['inode_size']['end'] = self._io.pos()
            self._debug['block_group_nr']['start'] = self._io.pos()
            self.block_group_nr = self._io.read_u2le()
            self._debug['block_group_nr']['end'] = self._io.pos()
            self._debug['feature_compat']['start'] = self._io.pos()
            self.feature_compat = self._io.read_u4le()
            self._debug['feature_compat']['end'] = self._io.pos()
            self._debug['feature_incompat']['start'] = self._io.pos()
            self.feature_incompat = self._io.read_u4le()
            self._debug['feature_incompat']['end'] = self._io.pos()
            self._debug['feature_ro_compat']['start'] = self._io.pos()
            self.feature_ro_compat = self._io.read_u4le()
            self._debug['feature_ro_compat']['end'] = self._io.pos()
            self._debug['uuid']['start'] = self._io.pos()
            self.uuid = self._io.read_bytes(16)
            self._debug['uuid']['end'] = self._io.pos()
            self._debug['volume_name']['start'] = self._io.pos()
            self.volume_name = self._io.read_bytes(16)
            self._debug['volume_name']['end'] = self._io.pos()
            self._debug['last_mounted']['start'] = self._io.pos()
            self.last_mounted = self._io.read_bytes(64)
            self._debug['last_mounted']['end'] = self._io.pos()
            self._debug['algo_bitmap']['start'] = self._io.pos()
            self.algo_bitmap = self._io.read_u4le()
            self._debug['algo_bitmap']['end'] = self._io.pos()
            self._debug['prealloc_blocks']['start'] = self._io.pos()
            self.prealloc_blocks = self._io.read_u1()
            self._debug['prealloc_blocks']['end'] = self._io.pos()
            self._debug['prealloc_dir_blocks']['start'] = self._io.pos()
            self.prealloc_dir_blocks = self._io.read_u1()
            self._debug['prealloc_dir_blocks']['end'] = self._io.pos()
            self._debug['padding1']['start'] = self._io.pos()
            self.padding1 = self._io.read_bytes(2)
            self._debug['padding1']['end'] = self._io.pos()
            self._debug['journal_uuid']['start'] = self._io.pos()
            self.journal_uuid = self._io.read_bytes(16)
            self._debug['journal_uuid']['end'] = self._io.pos()
            self._debug['journal_inum']['start'] = self._io.pos()
            self.journal_inum = self._io.read_u4le()
            self._debug['journal_inum']['end'] = self._io.pos()
            self._debug['journal_dev']['start'] = self._io.pos()
            self.journal_dev = self._io.read_u4le()
            self._debug['journal_dev']['end'] = self._io.pos()
            self._debug['last_orphan']['start'] = self._io.pos()
            self.last_orphan = self._io.read_u4le()
            self._debug['last_orphan']['end'] = self._io.pos()
            self._debug['hash_seed']['start'] = self._io.pos()
            self.hash_seed = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['hash_seed']:
                    self._debug['hash_seed']['arr'] = []
                self._debug['hash_seed']['arr'].append({'start': self._io.pos()})
                self.hash_seed[i] = self._io.read_u4le()
                self._debug['hash_seed']['arr'][i]['end'] = self._io.pos()

            self._debug['hash_seed']['end'] = self._io.pos()
            self._debug['def_hash_version']['start'] = self._io.pos()
            self.def_hash_version = self._io.read_u1()
            self._debug['def_hash_version']['end'] = self._io.pos()

        @property
        def block_size(self):
            if hasattr(self, '_m_block_size'):
                return self._m_block_size if hasattr(self, '_m_block_size') else None

            self._m_block_size = (1024 << self.log_block_size)
            return self._m_block_size if hasattr(self, '_m_block_size') else None

        @property
        def block_group_count(self):
            if hasattr(self, '_m_block_group_count'):
                return self._m_block_group_count if hasattr(self, '_m_block_group_count') else None

            self._m_block_group_count = self.blocks_count // self.blocks_per_group
            return self._m_block_group_count if hasattr(self, '_m_block_group_count') else None


    class DirEntry(KaitaiStruct):

        class FileTypeEnum(Enum):
            unknown = 0
            reg_file = 1
            dir = 2
            chrdev = 3
            blkdev = 4
            fifo = 5
            sock = 6
            symlink = 7
        SEQ_FIELDS = ["inode_ptr", "rec_len", "name_len", "file_type", "name", "padding"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['inode_ptr']['start'] = self._io.pos()
            self.inode_ptr = self._io.read_u4le()
            self._debug['inode_ptr']['end'] = self._io.pos()
            self._debug['rec_len']['start'] = self._io.pos()
            self.rec_len = self._io.read_u2le()
            self._debug['rec_len']['end'] = self._io.pos()
            self._debug['name_len']['start'] = self._io.pos()
            self.name_len = self._io.read_u1()
            self._debug['name_len']['end'] = self._io.pos()
            self._debug['file_type']['start'] = self._io.pos()
            self.file_type = KaitaiStream.resolve_enum(self._root.DirEntry.FileTypeEnum, self._io.read_u1())
            self._debug['file_type']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(self.name_len)).decode(u"UTF-8")
            self._debug['name']['end'] = self._io.pos()
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_bytes(((self.rec_len - self.name_len) - 8))
            self._debug['padding']['end'] = self._io.pos()

        @property
        def inode(self):
            if hasattr(self, '_m_inode'):
                return self._m_inode if hasattr(self, '_m_inode') else None

            self._m_inode = self._root.bg1.block_groups[(self.inode_ptr - 1) // self._root.bg1.super_block.inodes_per_group].inodes[((self.inode_ptr - 1) % self._root.bg1.super_block.inodes_per_group)]
            return self._m_inode if hasattr(self, '_m_inode') else None


    class Inode(KaitaiStruct):
        SEQ_FIELDS = ["mode", "uid", "size", "atime", "ctime", "mtime", "dtime", "gid", "links_count", "blocks", "flags", "osd1", "block", "generation", "file_acl", "dir_acl", "faddr", "osd2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['mode']['start'] = self._io.pos()
            self.mode = self._io.read_u2le()
            self._debug['mode']['end'] = self._io.pos()
            self._debug['uid']['start'] = self._io.pos()
            self.uid = self._io.read_u2le()
            self._debug['uid']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['atime']['start'] = self._io.pos()
            self.atime = self._io.read_u4le()
            self._debug['atime']['end'] = self._io.pos()
            self._debug['ctime']['start'] = self._io.pos()
            self.ctime = self._io.read_u4le()
            self._debug['ctime']['end'] = self._io.pos()
            self._debug['mtime']['start'] = self._io.pos()
            self.mtime = self._io.read_u4le()
            self._debug['mtime']['end'] = self._io.pos()
            self._debug['dtime']['start'] = self._io.pos()
            self.dtime = self._io.read_u4le()
            self._debug['dtime']['end'] = self._io.pos()
            self._debug['gid']['start'] = self._io.pos()
            self.gid = self._io.read_u2le()
            self._debug['gid']['end'] = self._io.pos()
            self._debug['links_count']['start'] = self._io.pos()
            self.links_count = self._io.read_u2le()
            self._debug['links_count']['end'] = self._io.pos()
            self._debug['blocks']['start'] = self._io.pos()
            self.blocks = self._io.read_u4le()
            self._debug['blocks']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['osd1']['start'] = self._io.pos()
            self.osd1 = self._io.read_u4le()
            self._debug['osd1']['end'] = self._io.pos()
            self._debug['block']['start'] = self._io.pos()
            self.block = [None] * (15)
            for i in range(15):
                if not 'arr' in self._debug['block']:
                    self._debug['block']['arr'] = []
                self._debug['block']['arr'].append({'start': self._io.pos()})
                _t_block = self._root.BlockPtr(self._io, self, self._root)
                _t_block._read()
                self.block[i] = _t_block
                self._debug['block']['arr'][i]['end'] = self._io.pos()

            self._debug['block']['end'] = self._io.pos()
            self._debug['generation']['start'] = self._io.pos()
            self.generation = self._io.read_u4le()
            self._debug['generation']['end'] = self._io.pos()
            self._debug['file_acl']['start'] = self._io.pos()
            self.file_acl = self._io.read_u4le()
            self._debug['file_acl']['end'] = self._io.pos()
            self._debug['dir_acl']['start'] = self._io.pos()
            self.dir_acl = self._io.read_u4le()
            self._debug['dir_acl']['end'] = self._io.pos()
            self._debug['faddr']['start'] = self._io.pos()
            self.faddr = self._io.read_u4le()
            self._debug['faddr']['end'] = self._io.pos()
            self._debug['osd2']['start'] = self._io.pos()
            self.osd2 = self._io.read_bytes(12)
            self._debug['osd2']['end'] = self._io.pos()

        @property
        def as_dir(self):
            if hasattr(self, '_m_as_dir'):
                return self._m_as_dir if hasattr(self, '_m_as_dir') else None

            io = self.block[0].body._io
            _pos = io.pos()
            io.seek(0)
            self._debug['_m_as_dir']['start'] = io.pos()
            self._m_as_dir = self._root.Dir(io, self, self._root)
            self._m_as_dir._read()
            self._debug['_m_as_dir']['end'] = io.pos()
            io.seek(_pos)
            return self._m_as_dir if hasattr(self, '_m_as_dir') else None


    class BlockPtr(KaitaiStruct):
        SEQ_FIELDS = ["ptr"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ptr']['start'] = self._io.pos()
            self.ptr = self._io.read_u4le()
            self._debug['ptr']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek((self.ptr * self._root.bg1.super_block.block_size))
            self._debug['_m_body']['start'] = self._io.pos()
            self._raw__m_body = self._io.read_bytes(self._root.bg1.super_block.block_size)
            io = KaitaiStream(BytesIO(self._raw__m_body))
            self._m_body = self._root.RawBlock(io, self, self._root)
            self._m_body._read()
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class Dir(KaitaiStruct):
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
                _t_entries = self._root.DirEntry(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class BlockGroup(KaitaiStruct):
        SEQ_FIELDS = ["super_block", "block_groups"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['super_block']['start'] = self._io.pos()
            self._raw_super_block = self._io.read_bytes(1024)
            io = KaitaiStream(BytesIO(self._raw_super_block))
            self.super_block = self._root.SuperBlockStruct(io, self, self._root)
            self.super_block._read()
            self._debug['super_block']['end'] = self._io.pos()
            self._debug['block_groups']['start'] = self._io.pos()
            self.block_groups = [None] * (self.super_block.block_group_count)
            for i in range(self.super_block.block_group_count):
                if not 'arr' in self._debug['block_groups']:
                    self._debug['block_groups']['arr'] = []
                self._debug['block_groups']['arr'].append({'start': self._io.pos()})
                _t_block_groups = self._root.Bgd(self._io, self, self._root)
                _t_block_groups._read()
                self.block_groups[i] = _t_block_groups
                self._debug['block_groups']['arr'][i]['end'] = self._io.pos()

            self._debug['block_groups']['end'] = self._io.pos()


    class Bgd(KaitaiStruct):
        SEQ_FIELDS = ["block_bitmap_block", "inode_bitmap_block", "inode_table_block", "free_blocks_count", "free_inodes_count", "used_dirs_count", "pad_reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['block_bitmap_block']['start'] = self._io.pos()
            self.block_bitmap_block = self._io.read_u4le()
            self._debug['block_bitmap_block']['end'] = self._io.pos()
            self._debug['inode_bitmap_block']['start'] = self._io.pos()
            self.inode_bitmap_block = self._io.read_u4le()
            self._debug['inode_bitmap_block']['end'] = self._io.pos()
            self._debug['inode_table_block']['start'] = self._io.pos()
            self.inode_table_block = self._io.read_u4le()
            self._debug['inode_table_block']['end'] = self._io.pos()
            self._debug['free_blocks_count']['start'] = self._io.pos()
            self.free_blocks_count = self._io.read_u2le()
            self._debug['free_blocks_count']['end'] = self._io.pos()
            self._debug['free_inodes_count']['start'] = self._io.pos()
            self.free_inodes_count = self._io.read_u2le()
            self._debug['free_inodes_count']['end'] = self._io.pos()
            self._debug['used_dirs_count']['start'] = self._io.pos()
            self.used_dirs_count = self._io.read_u2le()
            self._debug['used_dirs_count']['end'] = self._io.pos()
            self._debug['pad_reserved']['start'] = self._io.pos()
            self.pad_reserved = self._io.read_bytes((2 + 12))
            self._debug['pad_reserved']['end'] = self._io.pos()

        @property
        def block_bitmap(self):
            if hasattr(self, '_m_block_bitmap'):
                return self._m_block_bitmap if hasattr(self, '_m_block_bitmap') else None

            _pos = self._io.pos()
            self._io.seek((self.block_bitmap_block * self._root.bg1.super_block.block_size))
            self._debug['_m_block_bitmap']['start'] = self._io.pos()
            self._m_block_bitmap = self._io.read_bytes(1024)
            self._debug['_m_block_bitmap']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_block_bitmap if hasattr(self, '_m_block_bitmap') else None

        @property
        def inode_bitmap(self):
            if hasattr(self, '_m_inode_bitmap'):
                return self._m_inode_bitmap if hasattr(self, '_m_inode_bitmap') else None

            _pos = self._io.pos()
            self._io.seek((self.inode_bitmap_block * self._root.bg1.super_block.block_size))
            self._debug['_m_inode_bitmap']['start'] = self._io.pos()
            self._m_inode_bitmap = self._io.read_bytes(1024)
            self._debug['_m_inode_bitmap']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_inode_bitmap if hasattr(self, '_m_inode_bitmap') else None

        @property
        def inodes(self):
            if hasattr(self, '_m_inodes'):
                return self._m_inodes if hasattr(self, '_m_inodes') else None

            _pos = self._io.pos()
            self._io.seek((self.inode_table_block * self._root.bg1.super_block.block_size))
            self._debug['_m_inodes']['start'] = self._io.pos()
            self._m_inodes = [None] * (self._root.bg1.super_block.inodes_per_group)
            for i in range(self._root.bg1.super_block.inodes_per_group):
                if not 'arr' in self._debug['_m_inodes']:
                    self._debug['_m_inodes']['arr'] = []
                self._debug['_m_inodes']['arr'].append({'start': self._io.pos()})
                _t__m_inodes = self._root.Inode(self._io, self, self._root)
                _t__m_inodes._read()
                self._m_inodes[i] = _t__m_inodes
                self._debug['_m_inodes']['arr'][i]['end'] = self._io.pos()

            self._debug['_m_inodes']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_inodes if hasattr(self, '_m_inodes') else None


    class RawBlock(KaitaiStruct):
        SEQ_FIELDS = ["body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self._root.bg1.super_block.block_size)
            self._debug['body']['end'] = self._io.pos()


    @property
    def bg1(self):
        if hasattr(self, '_m_bg1'):
            return self._m_bg1 if hasattr(self, '_m_bg1') else None

        _pos = self._io.pos()
        self._io.seek(1024)
        self._debug['_m_bg1']['start'] = self._io.pos()
        self._m_bg1 = self._root.BlockGroup(self._io, self, self._root)
        self._m_bg1._read()
        self._debug['_m_bg1']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_bg1 if hasattr(self, '_m_bg1') else None

    @property
    def root_dir(self):
        if hasattr(self, '_m_root_dir'):
            return self._m_root_dir if hasattr(self, '_m_root_dir') else None

        self._m_root_dir = self.bg1.block_groups[0].inodes[1].as_dir
        return self._m_root_dir if hasattr(self, '_m_root_dir') else None


