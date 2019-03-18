from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Vdi(KaitaiStruct):
    """A native VirtualBox file format
    Images for testing can be downloaded from
     * https://www.osboxes.org/virtualbox-images/
     * https://virtualboxes.org/images/
     * https://virtualboximages.com/
    or you can convert images of other formats.
    
    .. seealso::
       Source - https://github.com/qemu/qemu/blob/master/block/vdi.c
    """

    class ImageType(Enum):
        dynamic = 1
        static = 2
        undo = 3
        diff = 4
    SEQ_FIELDS = ["header"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.Header(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()

    class Header(KaitaiStruct):
        SEQ_FIELDS = ["text", "signature", "version", "header_size_optional", "header_main"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['text']['start'] = self._io.pos()
            self.text = (self._io.read_bytes(64)).decode(u"utf-8")
            self._debug['text']['end'] = self._io.pos()
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.ensure_fixed_contents(b"\x7F\x10\xDA\xBE")
            self._debug['signature']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Header.Version(self._io, self, self._root)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            if self.subheader_size_is_dynamic:
                self._debug['header_size_optional']['start'] = self._io.pos()
                self.header_size_optional = self._io.read_u4le()
                self._debug['header_size_optional']['end'] = self._io.pos()

            self._debug['header_main']['start'] = self._io.pos()
            self._raw_header_main = self._io.read_bytes(self.header_size)
            io = KaitaiStream(BytesIO(self._raw_header_main))
            self.header_main = self._root.Header.HeaderMain(io, self, self._root)
            self.header_main._read()
            self._debug['header_main']['end'] = self._io.pos()

        class Uuid(KaitaiStruct):
            SEQ_FIELDS = ["uuid"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['uuid']['start'] = self._io.pos()
                self.uuid = self._io.read_bytes(16)
                self._debug['uuid']['end'] = self._io.pos()


        class Version(KaitaiStruct):
            SEQ_FIELDS = ["major", "minor"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['major']['start'] = self._io.pos()
                self.major = self._io.read_u2le()
                self._debug['major']['end'] = self._io.pos()
                self._debug['minor']['start'] = self._io.pos()
                self.minor = self._io.read_u2le()
                self._debug['minor']['end'] = self._io.pos()


        class HeaderMain(KaitaiStruct):
            SEQ_FIELDS = ["image_type", "image_flags", "description", "blocks_map_offset", "offset_data", "geometry", "reserved1", "disk_size", "block_data_size", "block_metadata_size", "blocks_in_image", "blocks_allocated", "uuid_image", "uuid_last_snap", "uuid_link", "uuid_parent", "lchc_geometry"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['image_type']['start'] = self._io.pos()
                self.image_type = KaitaiStream.resolve_enum(self._root.ImageType, self._io.read_u4le())
                self._debug['image_type']['end'] = self._io.pos()
                self._debug['image_flags']['start'] = self._io.pos()
                self.image_flags = self._root.Header.HeaderMain.Flags(self._io, self, self._root)
                self.image_flags._read()
                self._debug['image_flags']['end'] = self._io.pos()
                self._debug['description']['start'] = self._io.pos()
                self.description = (self._io.read_bytes(256)).decode(u"utf-8")
                self._debug['description']['end'] = self._io.pos()
                if self._parent.version.major >= 1:
                    self._debug['blocks_map_offset']['start'] = self._io.pos()
                    self.blocks_map_offset = self._io.read_u4le()
                    self._debug['blocks_map_offset']['end'] = self._io.pos()

                if self._parent.version.major >= 1:
                    self._debug['offset_data']['start'] = self._io.pos()
                    self.offset_data = self._io.read_u4le()
                    self._debug['offset_data']['end'] = self._io.pos()

                self._debug['geometry']['start'] = self._io.pos()
                self.geometry = self._root.Header.HeaderMain.Geometry(self._io, self, self._root)
                self.geometry._read()
                self._debug['geometry']['end'] = self._io.pos()
                if self._parent.version.major >= 1:
                    self._debug['reserved1']['start'] = self._io.pos()
                    self.reserved1 = self._io.read_u4le()
                    self._debug['reserved1']['end'] = self._io.pos()

                self._debug['disk_size']['start'] = self._io.pos()
                self.disk_size = self._io.read_u8le()
                self._debug['disk_size']['end'] = self._io.pos()
                self._debug['block_data_size']['start'] = self._io.pos()
                self.block_data_size = self._io.read_u4le()
                self._debug['block_data_size']['end'] = self._io.pos()
                if self._parent.version.major >= 1:
                    self._debug['block_metadata_size']['start'] = self._io.pos()
                    self.block_metadata_size = self._io.read_u4le()
                    self._debug['block_metadata_size']['end'] = self._io.pos()

                self._debug['blocks_in_image']['start'] = self._io.pos()
                self.blocks_in_image = self._io.read_u4le()
                self._debug['blocks_in_image']['end'] = self._io.pos()
                self._debug['blocks_allocated']['start'] = self._io.pos()
                self.blocks_allocated = self._io.read_u4le()
                self._debug['blocks_allocated']['end'] = self._io.pos()
                self._debug['uuid_image']['start'] = self._io.pos()
                self.uuid_image = self._root.Header.Uuid(self._io, self, self._root)
                self.uuid_image._read()
                self._debug['uuid_image']['end'] = self._io.pos()
                self._debug['uuid_last_snap']['start'] = self._io.pos()
                self.uuid_last_snap = self._root.Header.Uuid(self._io, self, self._root)
                self.uuid_last_snap._read()
                self._debug['uuid_last_snap']['end'] = self._io.pos()
                self._debug['uuid_link']['start'] = self._io.pos()
                self.uuid_link = self._root.Header.Uuid(self._io, self, self._root)
                self.uuid_link._read()
                self._debug['uuid_link']['end'] = self._io.pos()
                if self._parent.version.major >= 1:
                    self._debug['uuid_parent']['start'] = self._io.pos()
                    self.uuid_parent = self._root.Header.Uuid(self._io, self, self._root)
                    self.uuid_parent._read()
                    self._debug['uuid_parent']['end'] = self._io.pos()

                if  ((self._parent.version.major >= 1) and ((self._io.pos() + 16) <= self._io.size())) :
                    self._debug['lchc_geometry']['start'] = self._io.pos()
                    self.lchc_geometry = self._root.Header.HeaderMain.Geometry(self._io, self, self._root)
                    self.lchc_geometry._read()
                    self._debug['lchc_geometry']['end'] = self._io.pos()


            class Geometry(KaitaiStruct):
                SEQ_FIELDS = ["cylinders", "heads", "sectors", "sector_size"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['cylinders']['start'] = self._io.pos()
                    self.cylinders = self._io.read_u4le()
                    self._debug['cylinders']['end'] = self._io.pos()
                    self._debug['heads']['start'] = self._io.pos()
                    self.heads = self._io.read_u4le()
                    self._debug['heads']['end'] = self._io.pos()
                    self._debug['sectors']['start'] = self._io.pos()
                    self.sectors = self._io.read_u4le()
                    self._debug['sectors']['end'] = self._io.pos()
                    self._debug['sector_size']['start'] = self._io.pos()
                    self.sector_size = self._io.read_u4le()
                    self._debug['sector_size']['end'] = self._io.pos()


            class Flags(KaitaiStruct):
                SEQ_FIELDS = ["reserved0", "zero_expand", "reserved1", "diff", "fixed", "reserved2"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['reserved0']['start'] = self._io.pos()
                    self.reserved0 = self._io.read_bits_int(15)
                    self._debug['reserved0']['end'] = self._io.pos()
                    self._debug['zero_expand']['start'] = self._io.pos()
                    self.zero_expand = self._io.read_bits_int(1) != 0
                    self._debug['zero_expand']['end'] = self._io.pos()
                    self._debug['reserved1']['start'] = self._io.pos()
                    self.reserved1 = self._io.read_bits_int(6)
                    self._debug['reserved1']['end'] = self._io.pos()
                    self._debug['diff']['start'] = self._io.pos()
                    self.diff = self._io.read_bits_int(1) != 0
                    self._debug['diff']['end'] = self._io.pos()
                    self._debug['fixed']['start'] = self._io.pos()
                    self.fixed = self._io.read_bits_int(1) != 0
                    self._debug['fixed']['end'] = self._io.pos()
                    self._debug['reserved2']['start'] = self._io.pos()
                    self.reserved2 = self._io.read_bits_int(8)
                    self._debug['reserved2']['end'] = self._io.pos()



        @property
        def header_size(self):
            if hasattr(self, '_m_header_size'):
                return self._m_header_size if hasattr(self, '_m_header_size') else None

            self._m_header_size = (self.header_size_optional if self.subheader_size_is_dynamic else 336)
            return self._m_header_size if hasattr(self, '_m_header_size') else None

        @property
        def blocks_map_offset(self):
            if hasattr(self, '_m_blocks_map_offset'):
                return self._m_blocks_map_offset if hasattr(self, '_m_blocks_map_offset') else None

            self._m_blocks_map_offset = self.header_main.blocks_map_offset
            return self._m_blocks_map_offset if hasattr(self, '_m_blocks_map_offset') else None

        @property
        def subheader_size_is_dynamic(self):
            if hasattr(self, '_m_subheader_size_is_dynamic'):
                return self._m_subheader_size_is_dynamic if hasattr(self, '_m_subheader_size_is_dynamic') else None

            self._m_subheader_size_is_dynamic = self.version.major >= 1
            return self._m_subheader_size_is_dynamic if hasattr(self, '_m_subheader_size_is_dynamic') else None

        @property
        def blocks_offset(self):
            if hasattr(self, '_m_blocks_offset'):
                return self._m_blocks_offset if hasattr(self, '_m_blocks_offset') else None

            self._m_blocks_offset = self.header_main.offset_data
            return self._m_blocks_offset if hasattr(self, '_m_blocks_offset') else None

        @property
        def block_size(self):
            if hasattr(self, '_m_block_size'):
                return self._m_block_size if hasattr(self, '_m_block_size') else None

            self._m_block_size = (self.header_main.block_metadata_size + self.header_main.block_data_size)
            return self._m_block_size if hasattr(self, '_m_block_size') else None

        @property
        def blocks_map_size(self):
            if hasattr(self, '_m_blocks_map_size'):
                return self._m_blocks_map_size if hasattr(self, '_m_blocks_map_size') else None

            self._m_blocks_map_size = ((((self.header_main.blocks_in_image * 4) + self.header_main.geometry.sector_size) - 1) // self.header_main.geometry.sector_size * self.header_main.geometry.sector_size)
            return self._m_blocks_map_size if hasattr(self, '_m_blocks_map_size') else None


    class BlocksMap(KaitaiStruct):
        SEQ_FIELDS = ["index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['index']['start'] = self._io.pos()
            self.index = [None] * (self._root.header.header_main.blocks_in_image)
            for i in range(self._root.header.header_main.blocks_in_image):
                if not 'arr' in self._debug['index']:
                    self._debug['index']['arr'] = []
                self._debug['index']['arr'].append({'start': self._io.pos()})
                _t_index = self._root.BlocksMap.BlockIndex(self._io, self, self._root)
                _t_index._read()
                self.index[i] = _t_index
                self._debug['index']['arr'][i]['end'] = self._io.pos()

            self._debug['index']['end'] = self._io.pos()

        class BlockIndex(KaitaiStruct):
            SEQ_FIELDS = ["index"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['index']['start'] = self._io.pos()
                self.index = self._io.read_u4le()
                self._debug['index']['end'] = self._io.pos()

            @property
            def is_allocated(self):
                if hasattr(self, '_m_is_allocated'):
                    return self._m_is_allocated if hasattr(self, '_m_is_allocated') else None

                self._m_is_allocated = self.index < self._root.block_discarded
                return self._m_is_allocated if hasattr(self, '_m_is_allocated') else None

            @property
            def block(self):
                if hasattr(self, '_m_block'):
                    return self._m_block if hasattr(self, '_m_block') else None

                if self.is_allocated:
                    self._m_block = self._root.disk.blocks[self.index]

                return self._m_block if hasattr(self, '_m_block') else None



    class Disk(KaitaiStruct):
        SEQ_FIELDS = ["blocks"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['blocks']['start'] = self._io.pos()
            self.blocks = [None] * (self._root.header.header_main.blocks_in_image)
            for i in range(self._root.header.header_main.blocks_in_image):
                if not 'arr' in self._debug['blocks']:
                    self._debug['blocks']['arr'] = []
                self._debug['blocks']['arr'].append({'start': self._io.pos()})
                _t_blocks = self._root.Disk.Block(self._io, self, self._root)
                _t_blocks._read()
                self.blocks[i] = _t_blocks
                self._debug['blocks']['arr'][i]['end'] = self._io.pos()

            self._debug['blocks']['end'] = self._io.pos()

        class Block(KaitaiStruct):
            SEQ_FIELDS = ["metadata", "data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['metadata']['start'] = self._io.pos()
                self.metadata = self._io.read_bytes(self._root.header.header_main.block_metadata_size)
                self._debug['metadata']['end'] = self._io.pos()
                self._debug['data']['start'] = self._io.pos()
                self._raw_data = []
                self.data = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['data']:
                        self._debug['data']['arr'] = []
                    self._debug['data']['arr'].append({'start': self._io.pos()})
                    self._raw_data.append(self._io.read_bytes(self._root.header.header_main.block_data_size))
                    io = KaitaiStream(BytesIO(self._raw_data[-1]))
                    _t_data = self._root.Disk.Block.Sector(io, self, self._root)
                    _t_data._read()
                    self.data.append(_t_data)
                    self._debug['data']['arr'][len(self.data) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['data']['end'] = self._io.pos()

            class Sector(KaitaiStruct):
                SEQ_FIELDS = ["data"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._io.read_bytes(self._root.header.header_main.geometry.sector_size)
                    self._debug['data']['end'] = self._io.pos()




    @property
    def block_discarded(self):
        if hasattr(self, '_m_block_discarded'):
            return self._m_block_discarded if hasattr(self, '_m_block_discarded') else None

        self._m_block_discarded = 4294967294
        return self._m_block_discarded if hasattr(self, '_m_block_discarded') else None

    @property
    def block_unallocated(self):
        if hasattr(self, '_m_block_unallocated'):
            return self._m_block_unallocated if hasattr(self, '_m_block_unallocated') else None

        self._m_block_unallocated = 4294967295
        return self._m_block_unallocated if hasattr(self, '_m_block_unallocated') else None

    @property
    def blocks_map(self):
        """block_index = offset_in_virtual_disk / block_size actual_data_offset = blocks_map[block_index]*block_size+metadata_size+offset_in_block
        The blocks_map will take up blocks_in_image_max * sizeof(uint32_t) bytes; since the blocks_map is read and written in a single operation, its size needs to be limited to INT_MAX; furthermore, when opening an image, the blocks_map size is rounded up to be aligned on BDRV_SECTOR_SIZE. Therefore this should satisfy the following: blocks_in_image_max * sizeof(uint32_t) + BDRV_SECTOR_SIZE == INT_MAX + 1 (INT_MAX + 1 is the first value not representable as an int) This guarantees that any value below or equal to the constant will, when multiplied by sizeof(uint32_t) and rounded up to a BDRV_SECTOR_SIZE boundary, still be below or equal to INT_MAX.
        """
        if hasattr(self, '_m_blocks_map'):
            return self._m_blocks_map if hasattr(self, '_m_blocks_map') else None

        _pos = self._io.pos()
        self._io.seek(self.header.blocks_map_offset)
        self._debug['_m_blocks_map']['start'] = self._io.pos()
        self._raw__m_blocks_map = self._io.read_bytes(self.header.blocks_map_size)
        io = KaitaiStream(BytesIO(self._raw__m_blocks_map))
        self._m_blocks_map = self._root.BlocksMap(io, self, self._root)
        self._m_blocks_map._read()
        self._debug['_m_blocks_map']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_blocks_map if hasattr(self, '_m_blocks_map') else None

    @property
    def disk(self):
        if hasattr(self, '_m_disk'):
            return self._m_disk if hasattr(self, '_m_disk') else None

        _pos = self._io.pos()
        self._io.seek(self.header.blocks_offset)
        self._debug['_m_disk']['start'] = self._io.pos()
        self._m_disk = self._root.Disk(self._io, self, self._root)
        self._m_disk._read()
        self._debug['_m_disk']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_disk if hasattr(self, '_m_disk') else None


