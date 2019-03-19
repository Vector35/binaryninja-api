# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Stl(KaitaiStruct):
    """STL files are used to represent simple 3D models, defined using
    triangular 3D faces.
    
    Initially it was introduced as native format for 3D Systems
    Stereolithography CAD system, but due to its extreme simplicity, it
    was adopted by a wide range of 3D modelling, CAD, rapid prototyping
    and 3D printing applications as the simplest 3D model exchange
    format.
    
    STL is extremely bare-bones format: there are no complex headers, no
    texture / color support, no units specifications, no distinct vertex
    arrays. Whole model is specified as a collection of triangular
    faces.
    
    There are two versions of the format (text and binary), this spec
    describes binary version.
    """
    SEQ_FIELDS = ["header", "num_triangles", "triangles"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._io.read_bytes(80)
        self._debug['header']['end'] = self._io.pos()
        self._debug['num_triangles']['start'] = self._io.pos()
        self.num_triangles = self._io.read_u4le()
        self._debug['num_triangles']['end'] = self._io.pos()
        self._debug['triangles']['start'] = self._io.pos()
        self.triangles = [None] * (self.num_triangles)
        for i in range(self.num_triangles):
            if not 'arr' in self._debug['triangles']:
                self._debug['triangles']['arr'] = []
            self._debug['triangles']['arr'].append({'start': self._io.pos()})
            _t_triangles = self._root.Triangle(self._io, self, self._root)
            _t_triangles._read()
            self.triangles[i] = _t_triangles
            self._debug['triangles']['arr'][i]['end'] = self._io.pos()

        self._debug['triangles']['end'] = self._io.pos()

    class Triangle(KaitaiStruct):
        """Each STL triangle is defined by its 3 points in 3D space and a
        normal vector, which is generally used to determine where is
        "inside" and "outside" of the model.
        """
        SEQ_FIELDS = ["normal", "vertices"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['normal']['start'] = self._io.pos()
            self.normal = self._root.Vec3d(self._io, self, self._root)
            self.normal._read()
            self._debug['normal']['end'] = self._io.pos()
            self._debug['vertices']['start'] = self._io.pos()
            self.vertices = [None] * (3)
            for i in range(3):
                if not 'arr' in self._debug['vertices']:
                    self._debug['vertices']['arr'] = []
                self._debug['vertices']['arr'].append({'start': self._io.pos()})
                _t_vertices = self._root.Vec3d(self._io, self, self._root)
                _t_vertices._read()
                self.vertices[i] = _t_vertices
                self._debug['vertices']['arr'][i]['end'] = self._io.pos()

            self._debug['vertices']['end'] = self._io.pos()


    class Vec3d(KaitaiStruct):
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



