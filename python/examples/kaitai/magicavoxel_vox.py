# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MagicavoxelVox(KaitaiStruct):
    """
    .. seealso::
       Format Description - https://github.com/ephtracy/voxel-model/blob/master/MagicaVoxel-file-format-vox.txt
    """

    class ChunkType(Enum):
        main = 1296124238
        matt = 1296127060
        pack = 1346454347
        rgba = 1380401729
        size = 1397316165
        xyzi = 1482250825

    class MaterialType(Enum):
        diffuse = 0
        metal = 1
        glass = 2
        emissive = 3

    class PropertyBitsType(Enum):
        plastic = 1
        roughness = 2
        specular = 4
        ior = 8
        attenuation = 16
        power = 32
        glow = 64
        is_total_power = 128
    SEQ_FIELDS = ["magic", "version", "main"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x56\x4F\x58\x20")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u4le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['main']['start'] = self._io.pos()
        self.main = self._root.Chunk(self._io, self, self._root)
        self.main._read()
        self._debug['main']['end'] = self._io.pos()

    class Chunk(KaitaiStruct):
        SEQ_FIELDS = ["chunk_id", "num_bytes_of_chunk_content", "num_bytes_of_children_chunks", "chunk_content", "children_chunks"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chunk_id']['start'] = self._io.pos()
            self.chunk_id = KaitaiStream.resolve_enum(self._root.ChunkType, self._io.read_u4be())
            self._debug['chunk_id']['end'] = self._io.pos()
            self._debug['num_bytes_of_chunk_content']['start'] = self._io.pos()
            self.num_bytes_of_chunk_content = self._io.read_u4le()
            self._debug['num_bytes_of_chunk_content']['end'] = self._io.pos()
            self._debug['num_bytes_of_children_chunks']['start'] = self._io.pos()
            self.num_bytes_of_children_chunks = self._io.read_u4le()
            self._debug['num_bytes_of_children_chunks']['end'] = self._io.pos()
            if self.num_bytes_of_chunk_content != 0:
                self._debug['chunk_content']['start'] = self._io.pos()
                _on = self.chunk_id
                if _on == self._root.ChunkType.size:
                    self._raw_chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                    io = KaitaiStream(BytesIO(self._raw_chunk_content))
                    self.chunk_content = self._root.Size(io, self, self._root)
                    self.chunk_content._read()
                elif _on == self._root.ChunkType.matt:
                    self._raw_chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                    io = KaitaiStream(BytesIO(self._raw_chunk_content))
                    self.chunk_content = self._root.Matt(io, self, self._root)
                    self.chunk_content._read()
                elif _on == self._root.ChunkType.rgba:
                    self._raw_chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                    io = KaitaiStream(BytesIO(self._raw_chunk_content))
                    self.chunk_content = self._root.Rgba(io, self, self._root)
                    self.chunk_content._read()
                elif _on == self._root.ChunkType.xyzi:
                    self._raw_chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                    io = KaitaiStream(BytesIO(self._raw_chunk_content))
                    self.chunk_content = self._root.Xyzi(io, self, self._root)
                    self.chunk_content._read()
                elif _on == self._root.ChunkType.pack:
                    self._raw_chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                    io = KaitaiStream(BytesIO(self._raw_chunk_content))
                    self.chunk_content = self._root.Pack(io, self, self._root)
                    self.chunk_content._read()
                else:
                    self.chunk_content = self._io.read_bytes(self.num_bytes_of_chunk_content)
                self._debug['chunk_content']['end'] = self._io.pos()

            if self.num_bytes_of_children_chunks != 0:
                self._debug['children_chunks']['start'] = self._io.pos()
                self.children_chunks = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['children_chunks']:
                        self._debug['children_chunks']['arr'] = []
                    self._debug['children_chunks']['arr'].append({'start': self._io.pos()})
                    _t_children_chunks = self._root.Chunk(self._io, self, self._root)
                    _t_children_chunks._read()
                    self.children_chunks.append(_t_children_chunks)
                    self._debug['children_chunks']['arr'][len(self.children_chunks) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['children_chunks']['end'] = self._io.pos()



    class Size(KaitaiStruct):
        SEQ_FIELDS = ["size_x", "size_y", "size_z"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size_x']['start'] = self._io.pos()
            self.size_x = self._io.read_u4le()
            self._debug['size_x']['end'] = self._io.pos()
            self._debug['size_y']['start'] = self._io.pos()
            self.size_y = self._io.read_u4le()
            self._debug['size_y']['end'] = self._io.pos()
            self._debug['size_z']['start'] = self._io.pos()
            self.size_z = self._io.read_u4le()
            self._debug['size_z']['end'] = self._io.pos()


    class Rgba(KaitaiStruct):
        SEQ_FIELDS = ["colors"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['colors']['start'] = self._io.pos()
            self.colors = [None] * (256)
            for i in range(256):
                if not 'arr' in self._debug['colors']:
                    self._debug['colors']['arr'] = []
                self._debug['colors']['arr'].append({'start': self._io.pos()})
                _t_colors = self._root.Color(self._io, self, self._root)
                _t_colors._read()
                self.colors[i] = _t_colors
                self._debug['colors']['arr'][i]['end'] = self._io.pos()

            self._debug['colors']['end'] = self._io.pos()


    class Pack(KaitaiStruct):
        SEQ_FIELDS = ["num_models"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_models']['start'] = self._io.pos()
            self.num_models = self._io.read_u4le()
            self._debug['num_models']['end'] = self._io.pos()


    class Matt(KaitaiStruct):
        SEQ_FIELDS = ["id", "material_type", "material_weight", "property_bits", "plastic", "roughness", "specular", "ior", "attenuation", "power", "glow", "is_total_power"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['id']['start'] = self._io.pos()
            self.id = self._io.read_u4le()
            self._debug['id']['end'] = self._io.pos()
            self._debug['material_type']['start'] = self._io.pos()
            self.material_type = KaitaiStream.resolve_enum(self._root.MaterialType, self._io.read_u4le())
            self._debug['material_type']['end'] = self._io.pos()
            self._debug['material_weight']['start'] = self._io.pos()
            self.material_weight = self._io.read_f4le()
            self._debug['material_weight']['end'] = self._io.pos()
            self._debug['property_bits']['start'] = self._io.pos()
            self.property_bits = self._io.read_u4le()
            self._debug['property_bits']['end'] = self._io.pos()
            if self.has_plastic:
                self._debug['plastic']['start'] = self._io.pos()
                self.plastic = self._io.read_f4le()
                self._debug['plastic']['end'] = self._io.pos()

            if self.has_roughness:
                self._debug['roughness']['start'] = self._io.pos()
                self.roughness = self._io.read_f4le()
                self._debug['roughness']['end'] = self._io.pos()

            if self.has_specular:
                self._debug['specular']['start'] = self._io.pos()
                self.specular = self._io.read_f4le()
                self._debug['specular']['end'] = self._io.pos()

            if self.has_ior:
                self._debug['ior']['start'] = self._io.pos()
                self.ior = self._io.read_f4le()
                self._debug['ior']['end'] = self._io.pos()

            if self.has_attenuation:
                self._debug['attenuation']['start'] = self._io.pos()
                self.attenuation = self._io.read_f4le()
                self._debug['attenuation']['end'] = self._io.pos()

            if self.has_power:
                self._debug['power']['start'] = self._io.pos()
                self.power = self._io.read_f4le()
                self._debug['power']['end'] = self._io.pos()

            if self.has_glow:
                self._debug['glow']['start'] = self._io.pos()
                self.glow = self._io.read_f4le()
                self._debug['glow']['end'] = self._io.pos()

            if self.has_is_total_power:
                self._debug['is_total_power']['start'] = self._io.pos()
                self.is_total_power = self._io.read_f4le()
                self._debug['is_total_power']['end'] = self._io.pos()


        @property
        def has_is_total_power(self):
            if hasattr(self, '_m_has_is_total_power'):
                return self._m_has_is_total_power if hasattr(self, '_m_has_is_total_power') else None

            self._m_has_is_total_power = (self.property_bits & 128) != 0
            return self._m_has_is_total_power if hasattr(self, '_m_has_is_total_power') else None

        @property
        def has_plastic(self):
            if hasattr(self, '_m_has_plastic'):
                return self._m_has_plastic if hasattr(self, '_m_has_plastic') else None

            self._m_has_plastic = (self.property_bits & 1) != 0
            return self._m_has_plastic if hasattr(self, '_m_has_plastic') else None

        @property
        def has_attenuation(self):
            if hasattr(self, '_m_has_attenuation'):
                return self._m_has_attenuation if hasattr(self, '_m_has_attenuation') else None

            self._m_has_attenuation = (self.property_bits & 16) != 0
            return self._m_has_attenuation if hasattr(self, '_m_has_attenuation') else None

        @property
        def has_power(self):
            if hasattr(self, '_m_has_power'):
                return self._m_has_power if hasattr(self, '_m_has_power') else None

            self._m_has_power = (self.property_bits & 32) != 0
            return self._m_has_power if hasattr(self, '_m_has_power') else None

        @property
        def has_roughness(self):
            if hasattr(self, '_m_has_roughness'):
                return self._m_has_roughness if hasattr(self, '_m_has_roughness') else None

            self._m_has_roughness = (self.property_bits & 2) != 0
            return self._m_has_roughness if hasattr(self, '_m_has_roughness') else None

        @property
        def has_specular(self):
            if hasattr(self, '_m_has_specular'):
                return self._m_has_specular if hasattr(self, '_m_has_specular') else None

            self._m_has_specular = (self.property_bits & 4) != 0
            return self._m_has_specular if hasattr(self, '_m_has_specular') else None

        @property
        def has_ior(self):
            if hasattr(self, '_m_has_ior'):
                return self._m_has_ior if hasattr(self, '_m_has_ior') else None

            self._m_has_ior = (self.property_bits & 8) != 0
            return self._m_has_ior if hasattr(self, '_m_has_ior') else None

        @property
        def has_glow(self):
            if hasattr(self, '_m_has_glow'):
                return self._m_has_glow if hasattr(self, '_m_has_glow') else None

            self._m_has_glow = (self.property_bits & 64) != 0
            return self._m_has_glow if hasattr(self, '_m_has_glow') else None


    class Xyzi(KaitaiStruct):
        SEQ_FIELDS = ["num_voxels", "voxels"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_voxels']['start'] = self._io.pos()
            self.num_voxels = self._io.read_u4le()
            self._debug['num_voxels']['end'] = self._io.pos()
            self._debug['voxels']['start'] = self._io.pos()
            self.voxels = [None] * (self.num_voxels)
            for i in range(self.num_voxels):
                if not 'arr' in self._debug['voxels']:
                    self._debug['voxels']['arr'] = []
                self._debug['voxels']['arr'].append({'start': self._io.pos()})
                _t_voxels = self._root.Voxel(self._io, self, self._root)
                _t_voxels._read()
                self.voxels[i] = _t_voxels
                self._debug['voxels']['arr'][i]['end'] = self._io.pos()

            self._debug['voxels']['end'] = self._io.pos()


    class Color(KaitaiStruct):
        SEQ_FIELDS = ["r", "g", "b", "a"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['r']['start'] = self._io.pos()
            self.r = self._io.read_u1()
            self._debug['r']['end'] = self._io.pos()
            self._debug['g']['start'] = self._io.pos()
            self.g = self._io.read_u1()
            self._debug['g']['end'] = self._io.pos()
            self._debug['b']['start'] = self._io.pos()
            self.b = self._io.read_u1()
            self._debug['b']['end'] = self._io.pos()
            self._debug['a']['start'] = self._io.pos()
            self.a = self._io.read_u1()
            self._debug['a']['end'] = self._io.pos()


    class Voxel(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "z", "color_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u1()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u1()
            self._debug['y']['end'] = self._io.pos()
            self._debug['z']['start'] = self._io.pos()
            self.z = self._io.read_u1()
            self._debug['z']['end'] = self._io.pos()
            self._debug['color_index']['start'] = self._io.pos()
            self.color_index = self._io.read_u1()
            self._debug['color_index']['end'] = self._io.pos()



