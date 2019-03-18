from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class DoomWad(KaitaiStruct):
    SEQ_FIELDS = ["magic", "num_index_entries", "index_offset"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = (self._io.read_bytes(4)).decode(u"ASCII")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['num_index_entries']['start'] = self._io.pos()
        self.num_index_entries = self._io.read_s4le()
        self._debug['num_index_entries']['end'] = self._io.pos()
        self._debug['index_offset']['start'] = self._io.pos()
        self.index_offset = self._io.read_s4le()
        self._debug['index_offset']['end'] = self._io.pos()

    class Sectors(KaitaiStruct):
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
                _t_entries = self._root.Sector(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Vertex(KaitaiStruct):
        SEQ_FIELDS = ["x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_s2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_s2le()
            self._debug['y']['end'] = self._io.pos()


    class Texture12(KaitaiStruct):
        """Used for TEXTURE1 and TEXTURE2 lumps, which designate how to
        combine wall patches to make wall textures. This essentially
        provides a very simple form of image compression, allowing
        certain elements ("patches") to be reused / recombined on
        different textures for more variety in the game.
        
        .. seealso::
           Source - http://doom.wikia.com/wiki/TEXTURE1
        """
        SEQ_FIELDS = ["num_textures", "textures"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_textures']['start'] = self._io.pos()
            self.num_textures = self._io.read_s4le()
            self._debug['num_textures']['end'] = self._io.pos()
            self._debug['textures']['start'] = self._io.pos()
            self.textures = [None] * (self.num_textures)
            for i in range(self.num_textures):
                if not 'arr' in self._debug['textures']:
                    self._debug['textures']['arr'] = []
                self._debug['textures']['arr'].append({'start': self._io.pos()})
                _t_textures = self._root.Texture12.TextureIndex(self._io, self, self._root)
                _t_textures._read()
                self.textures[i] = _t_textures
                self._debug['textures']['arr'][i]['end'] = self._io.pos()

            self._debug['textures']['end'] = self._io.pos()

        class TextureIndex(KaitaiStruct):
            SEQ_FIELDS = ["offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_s4le()
                self._debug['offset']['end'] = self._io.pos()

            @property
            def body(self):
                if hasattr(self, '_m_body'):
                    return self._m_body if hasattr(self, '_m_body') else None

                _pos = self._io.pos()
                self._io.seek(self.offset)
                self._debug['_m_body']['start'] = self._io.pos()
                self._m_body = self._root.Texture12.TextureBody(self._io, self, self._root)
                self._m_body._read()
                self._debug['_m_body']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_body if hasattr(self, '_m_body') else None


        class TextureBody(KaitaiStruct):
            SEQ_FIELDS = ["name", "masked", "width", "height", "column_directory", "num_patches", "patches"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['name']['start'] = self._io.pos()
                self.name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 0)).decode(u"ASCII")
                self._debug['name']['end'] = self._io.pos()
                self._debug['masked']['start'] = self._io.pos()
                self.masked = self._io.read_u4le()
                self._debug['masked']['end'] = self._io.pos()
                self._debug['width']['start'] = self._io.pos()
                self.width = self._io.read_u2le()
                self._debug['width']['end'] = self._io.pos()
                self._debug['height']['start'] = self._io.pos()
                self.height = self._io.read_u2le()
                self._debug['height']['end'] = self._io.pos()
                self._debug['column_directory']['start'] = self._io.pos()
                self.column_directory = self._io.read_u4le()
                self._debug['column_directory']['end'] = self._io.pos()
                self._debug['num_patches']['start'] = self._io.pos()
                self.num_patches = self._io.read_u2le()
                self._debug['num_patches']['end'] = self._io.pos()
                self._debug['patches']['start'] = self._io.pos()
                self.patches = [None] * (self.num_patches)
                for i in range(self.num_patches):
                    if not 'arr' in self._debug['patches']:
                        self._debug['patches']['arr'] = []
                    self._debug['patches']['arr'].append({'start': self._io.pos()})
                    _t_patches = self._root.Texture12.Patch(self._io, self, self._root)
                    _t_patches._read()
                    self.patches[i] = _t_patches
                    self._debug['patches']['arr'][i]['end'] = self._io.pos()

                self._debug['patches']['end'] = self._io.pos()


        class Patch(KaitaiStruct):
            SEQ_FIELDS = ["origin_x", "origin_y", "patch_id", "step_dir", "colormap"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['origin_x']['start'] = self._io.pos()
                self.origin_x = self._io.read_s2le()
                self._debug['origin_x']['end'] = self._io.pos()
                self._debug['origin_y']['start'] = self._io.pos()
                self.origin_y = self._io.read_s2le()
                self._debug['origin_y']['end'] = self._io.pos()
                self._debug['patch_id']['start'] = self._io.pos()
                self.patch_id = self._io.read_u2le()
                self._debug['patch_id']['end'] = self._io.pos()
                self._debug['step_dir']['start'] = self._io.pos()
                self.step_dir = self._io.read_u2le()
                self._debug['step_dir']['end'] = self._io.pos()
                self._debug['colormap']['start'] = self._io.pos()
                self.colormap = self._io.read_u2le()
                self._debug['colormap']['end'] = self._io.pos()



    class Linedef(KaitaiStruct):
        SEQ_FIELDS = ["vertex_start_idx", "vertex_end_idx", "flags", "line_type", "sector_tag", "sidedef_right_idx", "sidedef_left_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['vertex_start_idx']['start'] = self._io.pos()
            self.vertex_start_idx = self._io.read_u2le()
            self._debug['vertex_start_idx']['end'] = self._io.pos()
            self._debug['vertex_end_idx']['start'] = self._io.pos()
            self.vertex_end_idx = self._io.read_u2le()
            self._debug['vertex_end_idx']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['line_type']['start'] = self._io.pos()
            self.line_type = self._io.read_u2le()
            self._debug['line_type']['end'] = self._io.pos()
            self._debug['sector_tag']['start'] = self._io.pos()
            self.sector_tag = self._io.read_u2le()
            self._debug['sector_tag']['end'] = self._io.pos()
            self._debug['sidedef_right_idx']['start'] = self._io.pos()
            self.sidedef_right_idx = self._io.read_u2le()
            self._debug['sidedef_right_idx']['end'] = self._io.pos()
            self._debug['sidedef_left_idx']['start'] = self._io.pos()
            self.sidedef_left_idx = self._io.read_u2le()
            self._debug['sidedef_left_idx']['end'] = self._io.pos()


    class Pnames(KaitaiStruct):
        """
        .. seealso::
           Source - http://doom.wikia.com/wiki/PNAMES
        """
        SEQ_FIELDS = ["num_patches", "names"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_patches']['start'] = self._io.pos()
            self.num_patches = self._io.read_u4le()
            self._debug['num_patches']['end'] = self._io.pos()
            self._debug['names']['start'] = self._io.pos()
            self.names = [None] * (self.num_patches)
            for i in range(self.num_patches):
                if not 'arr' in self._debug['names']:
                    self._debug['names']['arr'] = []
                self._debug['names']['arr'].append({'start': self._io.pos()})
                self.names[i] = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 0)).decode(u"ASCII")
                self._debug['names']['arr'][i]['end'] = self._io.pos()

            self._debug['names']['end'] = self._io.pos()


    class Thing(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "angle", "type", "flags"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_s2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_s2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['angle']['start'] = self._io.pos()
            self.angle = self._io.read_u2le()
            self._debug['angle']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u2le()
            self._debug['type']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()


    class Sector(KaitaiStruct):

        class SpecialSector(Enum):
            normal = 0
            d_light_flicker = 1
            d_light_strobe_fast = 2
            d_light_strobe_slow = 3
            d_light_strobe_hurt = 4
            d_damage_hellslime = 5
            d_damage_nukage = 7
            d_light_glow = 8
            secret = 9
            d_sector_door_close_in_30 = 10
            d_damage_end = 11
            d_light_strobe_slow_sync = 12
            d_light_strobe_fast_sync = 13
            d_sector_door_raise_in_5_mins = 14
            d_friction_low = 15
            d_damage_super_hellslime = 16
            d_light_fire_flicker = 17
            d_damage_lava_wimpy = 18
            d_damage_lava_hefty = 19
            d_scroll_east_lava_damage = 20
            light_phased = 21
            light_sequence_start = 22
            light_sequence_special1 = 23
            light_sequence_special2 = 24
        SEQ_FIELDS = ["floor_z", "ceil_z", "floor_flat", "ceil_flat", "light", "special_type", "tag"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['floor_z']['start'] = self._io.pos()
            self.floor_z = self._io.read_s2le()
            self._debug['floor_z']['end'] = self._io.pos()
            self._debug['ceil_z']['start'] = self._io.pos()
            self.ceil_z = self._io.read_s2le()
            self._debug['ceil_z']['end'] = self._io.pos()
            self._debug['floor_flat']['start'] = self._io.pos()
            self.floor_flat = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['floor_flat']['end'] = self._io.pos()
            self._debug['ceil_flat']['start'] = self._io.pos()
            self.ceil_flat = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['ceil_flat']['end'] = self._io.pos()
            self._debug['light']['start'] = self._io.pos()
            self.light = self._io.read_s2le()
            self._debug['light']['end'] = self._io.pos()
            self._debug['special_type']['start'] = self._io.pos()
            self.special_type = KaitaiStream.resolve_enum(self._root.Sector.SpecialSector, self._io.read_u2le())
            self._debug['special_type']['end'] = self._io.pos()
            self._debug['tag']['start'] = self._io.pos()
            self.tag = self._io.read_u2le()
            self._debug['tag']['end'] = self._io.pos()


    class Vertexes(KaitaiStruct):
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
                _t_entries = self._root.Vertex(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Sidedef(KaitaiStruct):
        SEQ_FIELDS = ["offset_x", "offset_y", "upper_texture_name", "lower_texture_name", "normal_texture_name", "sector_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['offset_x']['start'] = self._io.pos()
            self.offset_x = self._io.read_s2le()
            self._debug['offset_x']['end'] = self._io.pos()
            self._debug['offset_y']['start'] = self._io.pos()
            self.offset_y = self._io.read_s2le()
            self._debug['offset_y']['end'] = self._io.pos()
            self._debug['upper_texture_name']['start'] = self._io.pos()
            self.upper_texture_name = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['upper_texture_name']['end'] = self._io.pos()
            self._debug['lower_texture_name']['start'] = self._io.pos()
            self.lower_texture_name = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['lower_texture_name']['end'] = self._io.pos()
            self._debug['normal_texture_name']['start'] = self._io.pos()
            self.normal_texture_name = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['normal_texture_name']['end'] = self._io.pos()
            self._debug['sector_id']['start'] = self._io.pos()
            self.sector_id = self._io.read_s2le()
            self._debug['sector_id']['end'] = self._io.pos()


    class Things(KaitaiStruct):
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
                _t_entries = self._root.Thing(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Linedefs(KaitaiStruct):
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
                _t_entries = self._root.Linedef(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class IndexEntry(KaitaiStruct):
        SEQ_FIELDS = ["offset", "size", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_s4le()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_s4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 0)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()

        @property
        def contents(self):
            if hasattr(self, '_m_contents'):
                return self._m_contents if hasattr(self, '_m_contents') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_contents']['start'] = io.pos()
            _on = self.name
            if _on == u"SECTORS":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Sectors(io, self, self._root)
                self._m_contents._read()
            elif _on == u"TEXTURE1":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Texture12(io, self, self._root)
                self._m_contents._read()
            elif _on == u"VERTEXES":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Vertexes(io, self, self._root)
                self._m_contents._read()
            elif _on == u"BLOCKMAP":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Blockmap(io, self, self._root)
                self._m_contents._read()
            elif _on == u"PNAMES":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Pnames(io, self, self._root)
                self._m_contents._read()
            elif _on == u"TEXTURE2":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Texture12(io, self, self._root)
                self._m_contents._read()
            elif _on == u"THINGS":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Things(io, self, self._root)
                self._m_contents._read()
            elif _on == u"LINEDEFS":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Linedefs(io, self, self._root)
                self._m_contents._read()
            elif _on == u"SIDEDEFS":
                self._raw__m_contents = io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw__m_contents))
                self._m_contents = self._root.Sidedefs(io, self, self._root)
                self._m_contents._read()
            else:
                self._m_contents = io.read_bytes(self.size)
            self._debug['_m_contents']['end'] = io.pos()
            io.seek(_pos)
            return self._m_contents if hasattr(self, '_m_contents') else None


    class Sidedefs(KaitaiStruct):
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
                _t_entries = self._root.Sidedef(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Blockmap(KaitaiStruct):
        SEQ_FIELDS = ["origin_x", "origin_y", "num_cols", "num_rows", "linedefs_in_block"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['origin_x']['start'] = self._io.pos()
            self.origin_x = self._io.read_s2le()
            self._debug['origin_x']['end'] = self._io.pos()
            self._debug['origin_y']['start'] = self._io.pos()
            self.origin_y = self._io.read_s2le()
            self._debug['origin_y']['end'] = self._io.pos()
            self._debug['num_cols']['start'] = self._io.pos()
            self.num_cols = self._io.read_s2le()
            self._debug['num_cols']['end'] = self._io.pos()
            self._debug['num_rows']['start'] = self._io.pos()
            self.num_rows = self._io.read_s2le()
            self._debug['num_rows']['end'] = self._io.pos()
            self._debug['linedefs_in_block']['start'] = self._io.pos()
            self.linedefs_in_block = [None] * ((self.num_cols * self.num_rows))
            for i in range((self.num_cols * self.num_rows)):
                if not 'arr' in self._debug['linedefs_in_block']:
                    self._debug['linedefs_in_block']['arr'] = []
                self._debug['linedefs_in_block']['arr'].append({'start': self._io.pos()})
                _t_linedefs_in_block = self._root.Blockmap.Blocklist(self._io, self, self._root)
                _t_linedefs_in_block._read()
                self.linedefs_in_block[i] = _t_linedefs_in_block
                self._debug['linedefs_in_block']['arr'][i]['end'] = self._io.pos()

            self._debug['linedefs_in_block']['end'] = self._io.pos()

        class Blocklist(KaitaiStruct):
            SEQ_FIELDS = ["offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_u2le()
                self._debug['offset']['end'] = self._io.pos()

            @property
            def linedefs(self):
                """List of linedefs found in this block."""
                if hasattr(self, '_m_linedefs'):
                    return self._m_linedefs if hasattr(self, '_m_linedefs') else None

                _pos = self._io.pos()
                self._io.seek((self.offset * 2))
                self._debug['_m_linedefs']['start'] = self._io.pos()
                self._m_linedefs = []
                i = 0
                while True:
                    if not 'arr' in self._debug['_m_linedefs']:
                        self._debug['_m_linedefs']['arr'] = []
                    self._debug['_m_linedefs']['arr'].append({'start': self._io.pos()})
                    _ = self._io.read_s2le()
                    self._m_linedefs.append(_)
                    self._debug['_m_linedefs']['arr'][len(self._m_linedefs) - 1]['end'] = self._io.pos()
                    if _ == -1:
                        break
                    i += 1
                self._debug['_m_linedefs']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_linedefs if hasattr(self, '_m_linedefs') else None



    @property
    def index(self):
        if hasattr(self, '_m_index'):
            return self._m_index if hasattr(self, '_m_index') else None

        _pos = self._io.pos()
        self._io.seek(self.index_offset)
        self._debug['_m_index']['start'] = self._io.pos()
        self._m_index = [None] * (self.num_index_entries)
        for i in range(self.num_index_entries):
            if not 'arr' in self._debug['_m_index']:
                self._debug['_m_index']['arr'] = []
            self._debug['_m_index']['arr'].append({'start': self._io.pos()})
            _t__m_index = self._root.IndexEntry(self._io, self, self._root)
            _t__m_index._read()
            self._m_index[i] = _t__m_index
            self._debug['_m_index']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_index']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_index if hasattr(self, '_m_index') else None


