from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Cramfs(KaitaiStruct):
    SEQ_FIELDS = ["super_block"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['super_block']['start'] = self._io.pos()
        self.super_block = self._root.SuperBlockStruct(self._io, self, self._root)
        self.super_block._read()
        self._debug['super_block']['end'] = self._io.pos()

    class SuperBlockStruct(KaitaiStruct):
        SEQ_FIELDS = ["magic", "size", "flags", "future", "signature", "fsid", "name", "root"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x45\x3D\xCD\x28")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['future']['start'] = self._io.pos()
            self.future = self._io.read_u4le()
            self._debug['future']['end'] = self._io.pos()
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.ensure_fixed_contents(b"\x43\x6F\x6D\x70\x72\x65\x73\x73\x65\x64\x20\x52\x4F\x4D\x46\x53")
            self._debug['signature']['end'] = self._io.pos()
            self._debug['fsid']['start'] = self._io.pos()
            self.fsid = self._root.Info(self._io, self, self._root)
            self.fsid._read()
            self._debug['fsid']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(16)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()
            self._debug['root']['start'] = self._io.pos()
            self.root = self._root.Inode(self._io, self, self._root)
            self.root._read()
            self._debug['root']['end'] = self._io.pos()

        @property
        def flag_fsid_v2(self):
            if hasattr(self, '_m_flag_fsid_v2'):
                return self._m_flag_fsid_v2 if hasattr(self, '_m_flag_fsid_v2') else None

            self._m_flag_fsid_v2 = ((self.flags >> 0) & 1)
            return self._m_flag_fsid_v2 if hasattr(self, '_m_flag_fsid_v2') else None

        @property
        def flag_holes(self):
            if hasattr(self, '_m_flag_holes'):
                return self._m_flag_holes if hasattr(self, '_m_flag_holes') else None

            self._m_flag_holes = ((self.flags >> 8) & 1)
            return self._m_flag_holes if hasattr(self, '_m_flag_holes') else None

        @property
        def flag_wrong_signature(self):
            if hasattr(self, '_m_flag_wrong_signature'):
                return self._m_flag_wrong_signature if hasattr(self, '_m_flag_wrong_signature') else None

            self._m_flag_wrong_signature = ((self.flags >> 9) & 1)
            return self._m_flag_wrong_signature if hasattr(self, '_m_flag_wrong_signature') else None

        @property
        def flag_sorted_dirs(self):
            if hasattr(self, '_m_flag_sorted_dirs'):
                return self._m_flag_sorted_dirs if hasattr(self, '_m_flag_sorted_dirs') else None

            self._m_flag_sorted_dirs = ((self.flags >> 1) & 1)
            return self._m_flag_sorted_dirs if hasattr(self, '_m_flag_sorted_dirs') else None

        @property
        def flag_shifted_root_offset(self):
            if hasattr(self, '_m_flag_shifted_root_offset'):
                return self._m_flag_shifted_root_offset if hasattr(self, '_m_flag_shifted_root_offset') else None

            self._m_flag_shifted_root_offset = ((self.flags >> 10) & 1)
            return self._m_flag_shifted_root_offset if hasattr(self, '_m_flag_shifted_root_offset') else None


    class ChunkedDataInode(KaitaiStruct):
        SEQ_FIELDS = ["block_end_index", "raw_blocks"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['block_end_index']['start'] = self._io.pos()
            self.block_end_index = [None] * (((self._parent.size + self._root.page_size) - 1) // self._root.page_size)
            for i in range(((self._parent.size + self._root.page_size) - 1) // self._root.page_size):
                if not 'arr' in self._debug['block_end_index']:
                    self._debug['block_end_index']['arr'] = []
                self._debug['block_end_index']['arr'].append({'start': self._io.pos()})
                self.block_end_index[i] = self._io.read_u4le()
                self._debug['block_end_index']['arr'][i]['end'] = self._io.pos()

            self._debug['block_end_index']['end'] = self._io.pos()
            self._debug['raw_blocks']['start'] = self._io.pos()
            self.raw_blocks = self._io.read_bytes_full()
            self._debug['raw_blocks']['end'] = self._io.pos()


    class Inode(KaitaiStruct):

        class FileType(Enum):
            fifo = 1
            chrdev = 2
            dir = 4
            blkdev = 6
            reg_file = 8
            symlink = 10
            socket = 12
        SEQ_FIELDS = ["mode", "uid", "size_gid", "namelen_offset", "name"]
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
            self._debug['size_gid']['start'] = self._io.pos()
            self.size_gid = self._io.read_u4le()
            self._debug['size_gid']['end'] = self._io.pos()
            self._debug['namelen_offset']['start'] = self._io.pos()
            self.namelen_offset = self._io.read_u4le()
            self._debug['namelen_offset']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(self.namelen)).decode(u"utf-8")
            self._debug['name']['end'] = self._io.pos()

        @property
        def attr(self):
            if hasattr(self, '_m_attr'):
                return self._m_attr if hasattr(self, '_m_attr') else None

            self._m_attr = ((self.mode >> 9) & 7)
            return self._m_attr if hasattr(self, '_m_attr') else None

        @property
        def as_reg_file(self):
            if hasattr(self, '_m_as_reg_file'):
                return self._m_as_reg_file if hasattr(self, '_m_as_reg_file') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_as_reg_file']['start'] = io.pos()
            self._m_as_reg_file = self._root.ChunkedDataInode(io, self, self._root)
            self._m_as_reg_file._read()
            self._debug['_m_as_reg_file']['end'] = io.pos()
            io.seek(_pos)
            return self._m_as_reg_file if hasattr(self, '_m_as_reg_file') else None

        @property
        def perm_u(self):
            if hasattr(self, '_m_perm_u'):
                return self._m_perm_u if hasattr(self, '_m_perm_u') else None

            self._m_perm_u = ((self.mode >> 6) & 7)
            return self._m_perm_u if hasattr(self, '_m_perm_u') else None

        @property
        def as_symlink(self):
            if hasattr(self, '_m_as_symlink'):
                return self._m_as_symlink if hasattr(self, '_m_as_symlink') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_as_symlink']['start'] = io.pos()
            self._m_as_symlink = self._root.ChunkedDataInode(io, self, self._root)
            self._m_as_symlink._read()
            self._debug['_m_as_symlink']['end'] = io.pos()
            io.seek(_pos)
            return self._m_as_symlink if hasattr(self, '_m_as_symlink') else None

        @property
        def perm_o(self):
            if hasattr(self, '_m_perm_o'):
                return self._m_perm_o if hasattr(self, '_m_perm_o') else None

            self._m_perm_o = (self.mode & 7)
            return self._m_perm_o if hasattr(self, '_m_perm_o') else None

        @property
        def size(self):
            if hasattr(self, '_m_size'):
                return self._m_size if hasattr(self, '_m_size') else None

            self._m_size = (self.size_gid & 16777215)
            return self._m_size if hasattr(self, '_m_size') else None

        @property
        def gid(self):
            if hasattr(self, '_m_gid'):
                return self._m_gid if hasattr(self, '_m_gid') else None

            self._m_gid = (self.size_gid >> 24)
            return self._m_gid if hasattr(self, '_m_gid') else None

        @property
        def perm_g(self):
            if hasattr(self, '_m_perm_g'):
                return self._m_perm_g if hasattr(self, '_m_perm_g') else None

            self._m_perm_g = ((self.mode >> 3) & 7)
            return self._m_perm_g if hasattr(self, '_m_perm_g') else None

        @property
        def namelen(self):
            if hasattr(self, '_m_namelen'):
                return self._m_namelen if hasattr(self, '_m_namelen') else None

            self._m_namelen = ((self.namelen_offset & 63) << 2)
            return self._m_namelen if hasattr(self, '_m_namelen') else None

        @property
        def as_dir(self):
            if hasattr(self, '_m_as_dir'):
                return self._m_as_dir if hasattr(self, '_m_as_dir') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_as_dir']['start'] = io.pos()
            self._raw__m_as_dir = io.read_bytes(self.size)
            io = KaitaiStream(BytesIO(self._raw__m_as_dir))
            self._m_as_dir = self._root.DirInode(io, self, self._root)
            self._m_as_dir._read()
            self._debug['_m_as_dir']['end'] = io.pos()
            io.seek(_pos)
            return self._m_as_dir if hasattr(self, '_m_as_dir') else None

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type if hasattr(self, '_m_type') else None

            self._m_type = KaitaiStream.resolve_enum(self._root.Inode.FileType, ((self.mode >> 12) & 15))
            return self._m_type if hasattr(self, '_m_type') else None

        @property
        def offset(self):
            if hasattr(self, '_m_offset'):
                return self._m_offset if hasattr(self, '_m_offset') else None

            self._m_offset = (((self.namelen_offset >> 6) & 67108863) << 2)
            return self._m_offset if hasattr(self, '_m_offset') else None


    class DirInode(KaitaiStruct):
        SEQ_FIELDS = ["children"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if self._io.size() > 0:
                self._debug['children']['start'] = self._io.pos()
                self.children = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['children']:
                        self._debug['children']['arr'] = []
                    self._debug['children']['arr'].append({'start': self._io.pos()})
                    _t_children = self._root.Inode(self._io, self, self._root)
                    _t_children._read()
                    self.children.append(_t_children)
                    self._debug['children']['arr'][len(self.children) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['children']['end'] = self._io.pos()



    class Info(KaitaiStruct):
        SEQ_FIELDS = ["crc", "edition", "blocks", "files"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['crc']['start'] = self._io.pos()
            self.crc = self._io.read_u4le()
            self._debug['crc']['end'] = self._io.pos()
            self._debug['edition']['start'] = self._io.pos()
            self.edition = self._io.read_u4le()
            self._debug['edition']['end'] = self._io.pos()
            self._debug['blocks']['start'] = self._io.pos()
            self.blocks = self._io.read_u4le()
            self._debug['blocks']['end'] = self._io.pos()
            self._debug['files']['start'] = self._io.pos()
            self.files = self._io.read_u4le()
            self._debug['files']['end'] = self._io.pos()


    @property
    def page_size(self):
        if hasattr(self, '_m_page_size'):
            return self._m_page_size if hasattr(self, '_m_page_size') else None

        self._m_page_size = 4096
        return self._m_page_size if hasattr(self, '_m_page_size') else None


