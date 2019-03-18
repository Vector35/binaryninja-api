from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class QuakeMdl(KaitaiStruct):
    SEQ_FIELDS = ["header", "skins", "texture_coordinates", "triangles", "frames"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.MdlHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['skins']['start'] = self._io.pos()
        self.skins = [None] * (self.header.num_skins)
        for i in range(self.header.num_skins):
            if not 'arr' in self._debug['skins']:
                self._debug['skins']['arr'] = []
            self._debug['skins']['arr'].append({'start': self._io.pos()})
            _t_skins = self._root.MdlSkin(self._io, self, self._root)
            _t_skins._read()
            self.skins[i] = _t_skins
            self._debug['skins']['arr'][i]['end'] = self._io.pos()

        self._debug['skins']['end'] = self._io.pos()
        self._debug['texture_coordinates']['start'] = self._io.pos()
        self.texture_coordinates = [None] * (self.header.num_verts)
        for i in range(self.header.num_verts):
            if not 'arr' in self._debug['texture_coordinates']:
                self._debug['texture_coordinates']['arr'] = []
            self._debug['texture_coordinates']['arr'].append({'start': self._io.pos()})
            _t_texture_coordinates = self._root.MdlTexcoord(self._io, self, self._root)
            _t_texture_coordinates._read()
            self.texture_coordinates[i] = _t_texture_coordinates
            self._debug['texture_coordinates']['arr'][i]['end'] = self._io.pos()

        self._debug['texture_coordinates']['end'] = self._io.pos()
        self._debug['triangles']['start'] = self._io.pos()
        self.triangles = [None] * (self.header.num_tris)
        for i in range(self.header.num_tris):
            if not 'arr' in self._debug['triangles']:
                self._debug['triangles']['arr'] = []
            self._debug['triangles']['arr'].append({'start': self._io.pos()})
            _t_triangles = self._root.MdlTriangle(self._io, self, self._root)
            _t_triangles._read()
            self.triangles[i] = _t_triangles
            self._debug['triangles']['arr'][i]['end'] = self._io.pos()

        self._debug['triangles']['end'] = self._io.pos()
        self._debug['frames']['start'] = self._io.pos()
        self.frames = [None] * (self.header.num_frames)
        for i in range(self.header.num_frames):
            if not 'arr' in self._debug['frames']:
                self._debug['frames']['arr'] = []
            self._debug['frames']['arr'].append({'start': self._io.pos()})
            _t_frames = self._root.MdlFrame(self._io, self, self._root)
            _t_frames._read()
            self.frames[i] = _t_frames
            self._debug['frames']['arr'][i]['end'] = self._io.pos()

        self._debug['frames']['end'] = self._io.pos()

    class MdlVertex(KaitaiStruct):
        SEQ_FIELDS = ["values", "normal_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['values']['start'] = self._io.pos()
            self.values = [None] * (3)
            for i in range(3):
                if not 'arr' in self._debug['values']:
                    self._debug['values']['arr'] = []
                self._debug['values']['arr'].append({'start': self._io.pos()})
                self.values[i] = self._io.read_u1()
                self._debug['values']['arr'][i]['end'] = self._io.pos()

            self._debug['values']['end'] = self._io.pos()
            self._debug['normal_index']['start'] = self._io.pos()
            self.normal_index = self._io.read_u1()
            self._debug['normal_index']['end'] = self._io.pos()


    class MdlTexcoord(KaitaiStruct):
        SEQ_FIELDS = ["on_seam", "s", "t"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['on_seam']['start'] = self._io.pos()
            self.on_seam = self._io.read_s4le()
            self._debug['on_seam']['end'] = self._io.pos()
            self._debug['s']['start'] = self._io.pos()
            self.s = self._io.read_s4le()
            self._debug['s']['end'] = self._io.pos()
            self._debug['t']['start'] = self._io.pos()
            self.t = self._io.read_s4le()
            self._debug['t']['end'] = self._io.pos()


    class MdlHeader(KaitaiStruct):
        SEQ_FIELDS = ["ident", "version_must_be_6", "scale", "origin", "radius", "eye_position", "num_skins", "skin_width", "skin_height", "num_verts", "num_tris", "num_frames", "synctype", "flags", "size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ident']['start'] = self._io.pos()
            self.ident = self._io.ensure_fixed_contents(b"\x49\x44\x50\x4F")
            self._debug['ident']['end'] = self._io.pos()
            self._debug['version_must_be_6']['start'] = self._io.pos()
            self.version_must_be_6 = self._io.ensure_fixed_contents(b"\x06\x00\x00\x00")
            self._debug['version_must_be_6']['end'] = self._io.pos()
            self._debug['scale']['start'] = self._io.pos()
            self.scale = self._root.Vec3(self._io, self, self._root)
            self.scale._read()
            self._debug['scale']['end'] = self._io.pos()
            self._debug['origin']['start'] = self._io.pos()
            self.origin = self._root.Vec3(self._io, self, self._root)
            self.origin._read()
            self._debug['origin']['end'] = self._io.pos()
            self._debug['radius']['start'] = self._io.pos()
            self.radius = self._io.read_f4le()
            self._debug['radius']['end'] = self._io.pos()
            self._debug['eye_position']['start'] = self._io.pos()
            self.eye_position = self._root.Vec3(self._io, self, self._root)
            self.eye_position._read()
            self._debug['eye_position']['end'] = self._io.pos()
            self._debug['num_skins']['start'] = self._io.pos()
            self.num_skins = self._io.read_s4le()
            self._debug['num_skins']['end'] = self._io.pos()
            self._debug['skin_width']['start'] = self._io.pos()
            self.skin_width = self._io.read_s4le()
            self._debug['skin_width']['end'] = self._io.pos()
            self._debug['skin_height']['start'] = self._io.pos()
            self.skin_height = self._io.read_s4le()
            self._debug['skin_height']['end'] = self._io.pos()
            self._debug['num_verts']['start'] = self._io.pos()
            self.num_verts = self._io.read_s4le()
            self._debug['num_verts']['end'] = self._io.pos()
            self._debug['num_tris']['start'] = self._io.pos()
            self.num_tris = self._io.read_s4le()
            self._debug['num_tris']['end'] = self._io.pos()
            self._debug['num_frames']['start'] = self._io.pos()
            self.num_frames = self._io.read_s4le()
            self._debug['num_frames']['end'] = self._io.pos()
            self._debug['synctype']['start'] = self._io.pos()
            self.synctype = self._io.read_s4le()
            self._debug['synctype']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_s4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_f4le()
            self._debug['size']['end'] = self._io.pos()

        @property
        def version(self):
            if hasattr(self, '_m_version'):
                return self._m_version if hasattr(self, '_m_version') else None

            self._m_version = 6
            return self._m_version if hasattr(self, '_m_version') else None

        @property
        def skin_size(self):
            if hasattr(self, '_m_skin_size'):
                return self._m_skin_size if hasattr(self, '_m_skin_size') else None

            self._m_skin_size = (self.skin_width * self.skin_height)
            return self._m_skin_size if hasattr(self, '_m_skin_size') else None


    class MdlSkin(KaitaiStruct):
        SEQ_FIELDS = ["group", "single_texture_data", "num_frames", "frame_times", "group_texture_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['group']['start'] = self._io.pos()
            self.group = self._io.read_s4le()
            self._debug['group']['end'] = self._io.pos()
            if self.group == 0:
                self._debug['single_texture_data']['start'] = self._io.pos()
                self.single_texture_data = self._io.read_bytes(self._root.header.skin_size)
                self._debug['single_texture_data']['end'] = self._io.pos()

            if self.group != 0:
                self._debug['num_frames']['start'] = self._io.pos()
                self.num_frames = self._io.read_u4le()
                self._debug['num_frames']['end'] = self._io.pos()

            if self.group != 0:
                self._debug['frame_times']['start'] = self._io.pos()
                self.frame_times = [None] * (self.num_frames)
                for i in range(self.num_frames):
                    if not 'arr' in self._debug['frame_times']:
                        self._debug['frame_times']['arr'] = []
                    self._debug['frame_times']['arr'].append({'start': self._io.pos()})
                    self.frame_times[i] = self._io.read_f4le()
                    self._debug['frame_times']['arr'][i]['end'] = self._io.pos()

                self._debug['frame_times']['end'] = self._io.pos()

            if self.group != 0:
                self._debug['group_texture_data']['start'] = self._io.pos()
                self.group_texture_data = [None] * (self.num_frames)
                for i in range(self.num_frames):
                    if not 'arr' in self._debug['group_texture_data']:
                        self._debug['group_texture_data']['arr'] = []
                    self._debug['group_texture_data']['arr'].append({'start': self._io.pos()})
                    self.group_texture_data[i] = self._io.read_bytes(self._root.header.skin_size)
                    self._debug['group_texture_data']['arr'][i]['end'] = self._io.pos()

                self._debug['group_texture_data']['end'] = self._io.pos()



    class MdlFrame(KaitaiStruct):
        SEQ_FIELDS = ["type", "min", "max", "time", "frames"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_s4le()
            self._debug['type']['end'] = self._io.pos()
            if self.type != 0:
                self._debug['min']['start'] = self._io.pos()
                self.min = self._root.MdlVertex(self._io, self, self._root)
                self.min._read()
                self._debug['min']['end'] = self._io.pos()

            if self.type != 0:
                self._debug['max']['start'] = self._io.pos()
                self.max = self._root.MdlVertex(self._io, self, self._root)
                self.max._read()
                self._debug['max']['end'] = self._io.pos()

            if self.type != 0:
                self._debug['time']['start'] = self._io.pos()
                self.time = [None] * (self.type)
                for i in range(self.type):
                    if not 'arr' in self._debug['time']:
                        self._debug['time']['arr'] = []
                    self._debug['time']['arr'].append({'start': self._io.pos()})
                    self.time[i] = self._io.read_f4le()
                    self._debug['time']['arr'][i]['end'] = self._io.pos()

                self._debug['time']['end'] = self._io.pos()

            self._debug['frames']['start'] = self._io.pos()
            self.frames = [None] * (self.num_simple_frames)
            for i in range(self.num_simple_frames):
                if not 'arr' in self._debug['frames']:
                    self._debug['frames']['arr'] = []
                self._debug['frames']['arr'].append({'start': self._io.pos()})
                _t_frames = self._root.MdlSimpleFrame(self._io, self, self._root)
                _t_frames._read()
                self.frames[i] = _t_frames
                self._debug['frames']['arr'][i]['end'] = self._io.pos()

            self._debug['frames']['end'] = self._io.pos()

        @property
        def num_simple_frames(self):
            if hasattr(self, '_m_num_simple_frames'):
                return self._m_num_simple_frames if hasattr(self, '_m_num_simple_frames') else None

            self._m_num_simple_frames = (1 if self.type == 0 else self.type)
            return self._m_num_simple_frames if hasattr(self, '_m_num_simple_frames') else None


    class MdlSimpleFrame(KaitaiStruct):
        SEQ_FIELDS = ["bbox_min", "bbox_max", "name", "vertices"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bbox_min']['start'] = self._io.pos()
            self.bbox_min = self._root.MdlVertex(self._io, self, self._root)
            self.bbox_min._read()
            self._debug['bbox_min']['end'] = self._io.pos()
            self._debug['bbox_max']['start'] = self._io.pos()
            self.bbox_max = self._root.MdlVertex(self._io, self, self._root)
            self.bbox_max._read()
            self._debug['bbox_max']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (KaitaiStream.bytes_terminate(KaitaiStream.bytes_strip_right(self._io.read_bytes(16), 0), 0, False)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()
            self._debug['vertices']['start'] = self._io.pos()
            self.vertices = [None] * (self._root.header.num_verts)
            for i in range(self._root.header.num_verts):
                if not 'arr' in self._debug['vertices']:
                    self._debug['vertices']['arr'] = []
                self._debug['vertices']['arr'].append({'start': self._io.pos()})
                _t_vertices = self._root.MdlVertex(self._io, self, self._root)
                _t_vertices._read()
                self.vertices[i] = _t_vertices
                self._debug['vertices']['arr'][i]['end'] = self._io.pos()

            self._debug['vertices']['end'] = self._io.pos()


    class MdlTriangle(KaitaiStruct):
        SEQ_FIELDS = ["faces_front", "vertices"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['faces_front']['start'] = self._io.pos()
            self.faces_front = self._io.read_s4le()
            self._debug['faces_front']['end'] = self._io.pos()
            self._debug['vertices']['start'] = self._io.pos()
            self.vertices = [None] * (3)
            for i in range(3):
                if not 'arr' in self._debug['vertices']:
                    self._debug['vertices']['arr'] = []
                self._debug['vertices']['arr'].append({'start': self._io.pos()})
                self.vertices[i] = self._io.read_s4le()
                self._debug['vertices']['arr'][i]['end'] = self._io.pos()

            self._debug['vertices']['end'] = self._io.pos()


    class Vec3(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "z"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_f4le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_f4le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['z']['start'] = self._io.pos()
            self.z = self._io.read_f4le()
            self._debug['z']['end'] = self._io.pos()



