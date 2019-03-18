from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class ShapefileMain(KaitaiStruct):

    class ShapeType(Enum):
        null_shape = 0
        point = 1
        poly_line = 3
        polygon = 5
        multi_point = 8
        point_z = 11
        poly_line_z = 13
        polygon_z = 15
        multi_point_z = 18
        point_m = 21
        poly_line_m = 23
        polygon_m = 25
        multi_point_m = 28
        multi_patch = 31

    class PartType(Enum):
        triangle_strip = 0
        triangle_fan = 1
        outer_ring = 2
        inner_ring = 3
        first_ring = 4
        ring = 5
    SEQ_FIELDS = ["header", "records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.FileHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['records']['start'] = self._io.pos()
        self.records = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            _t_records = self._root.Record(self._io, self, self._root)
            _t_records._read()
            self.records.append(_t_records)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['records']['end'] = self._io.pos()

    class MultiPointM(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_points", "points", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class BoundingBoxXYZM(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "z", "m"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._root.BoundsMinMax(self._io, self, self._root)
            self.x._read()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._root.BoundsMinMax(self._io, self, self._root)
            self.y._read()
            self._debug['y']['end'] = self._io.pos()
            self._debug['z']['start'] = self._io.pos()
            self.z = self._root.BoundsMinMax(self._io, self, self._root)
            self.z._read()
            self._debug['z']['end'] = self._io.pos()
            self._debug['m']['start'] = self._io.pos()
            self.m = self._root.BoundsMinMax(self._io, self, self._root)
            self.m._read()
            self._debug['m']['end'] = self._io.pos()


    class Point(KaitaiStruct):
        SEQ_FIELDS = ["x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_f8le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_f8le()
            self._debug['y']['end'] = self._io.pos()


    class Polygon(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()


    class BoundsMinMax(KaitaiStruct):
        SEQ_FIELDS = ["min", "max"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['min']['start'] = self._io.pos()
            self.min = self._io.read_f8le()
            self._debug['min']['end'] = self._io.pos()
            self._debug['max']['start'] = self._io.pos()
            self.max = self._io.read_f8le()
            self._debug['max']['end'] = self._io.pos()


    class PolyLine(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()


    class MultiPointZ(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_points", "points", "z_range", "z_values", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['z_range']['start'] = self._io.pos()
            self.z_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.z_range._read()
            self._debug['z_range']['end'] = self._io.pos()
            self._debug['z_values']['start'] = self._io.pos()
            self.z_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['z_values']:
                    self._debug['z_values']['arr'] = []
                self._debug['z_values']['arr'].append({'start': self._io.pos()})
                self.z_values[i] = self._io.read_f8le()
                self._debug['z_values']['arr'][i]['end'] = self._io.pos()

            self._debug['z_values']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class PolyLineZ(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points", "z_range", "z_values", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['z_range']['start'] = self._io.pos()
            self.z_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.z_range._read()
            self._debug['z_range']['end'] = self._io.pos()
            self._debug['z_values']['start'] = self._io.pos()
            self.z_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['z_values']:
                    self._debug['z_values']['arr'] = []
                self._debug['z_values']['arr'].append({'start': self._io.pos()})
                self.z_values[i] = self._io.read_f8le()
                self._debug['z_values']['arr'][i]['end'] = self._io.pos()

            self._debug['z_values']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class PolygonZ(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points", "z_range", "z_values", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['z_range']['start'] = self._io.pos()
            self.z_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.z_range._read()
            self._debug['z_range']['end'] = self._io.pos()
            self._debug['z_values']['start'] = self._io.pos()
            self.z_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['z_values']:
                    self._debug['z_values']['arr'] = []
                self._debug['z_values']['arr'].append({'start': self._io.pos()})
                self.z_values[i] = self._io.read_f8le()
                self._debug['z_values']['arr'][i]['end'] = self._io.pos()

            self._debug['z_values']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class BoundingBoxXY(KaitaiStruct):
        SEQ_FIELDS = ["x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._root.BoundsMinMax(self._io, self, self._root)
            self.x._read()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._root.BoundsMinMax(self._io, self, self._root)
            self.y._read()
            self._debug['y']['end'] = self._io.pos()


    class PointM(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "m"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_f8le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_f8le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['m']['start'] = self._io.pos()
            self.m = self._io.read_f8le()
            self._debug['m']['end'] = self._io.pos()


    class PolygonM(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class RecordHeader(KaitaiStruct):
        SEQ_FIELDS = ["record_number", "content_length"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['record_number']['start'] = self._io.pos()
            self.record_number = self._io.read_s4be()
            self._debug['record_number']['end'] = self._io.pos()
            self._debug['content_length']['start'] = self._io.pos()
            self.content_length = self._io.read_s4be()
            self._debug['content_length']['end'] = self._io.pos()


    class MultiPoint(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_points", "points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()


    class FileHeader(KaitaiStruct):
        SEQ_FIELDS = ["file_code", "unused_field_1", "unused_field_2", "unused_field_3", "unused_field_4", "unused_field_5", "file_length", "version", "shape_type", "bounding_box"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['file_code']['start'] = self._io.pos()
            self.file_code = self._io.ensure_fixed_contents(b"\x00\x00\x27\x0A")
            self._debug['file_code']['end'] = self._io.pos()
            self._debug['unused_field_1']['start'] = self._io.pos()
            self.unused_field_1 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['unused_field_1']['end'] = self._io.pos()
            self._debug['unused_field_2']['start'] = self._io.pos()
            self.unused_field_2 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['unused_field_2']['end'] = self._io.pos()
            self._debug['unused_field_3']['start'] = self._io.pos()
            self.unused_field_3 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['unused_field_3']['end'] = self._io.pos()
            self._debug['unused_field_4']['start'] = self._io.pos()
            self.unused_field_4 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['unused_field_4']['end'] = self._io.pos()
            self._debug['unused_field_5']['start'] = self._io.pos()
            self.unused_field_5 = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['unused_field_5']['end'] = self._io.pos()
            self._debug['file_length']['start'] = self._io.pos()
            self.file_length = self._io.read_s4be()
            self._debug['file_length']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.ensure_fixed_contents(b"\xE8\x03\x00\x00")
            self._debug['version']['end'] = self._io.pos()
            self._debug['shape_type']['start'] = self._io.pos()
            self.shape_type = KaitaiStream.resolve_enum(self._root.ShapeType, self._io.read_s4le())
            self._debug['shape_type']['end'] = self._io.pos()
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXYZM(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()


    class PointZ(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "z", "m"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_f8le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_f8le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['z']['start'] = self._io.pos()
            self.z = self._io.read_f8le()
            self._debug['z']['end'] = self._io.pos()
            self._debug['m']['start'] = self._io.pos()
            self.m = self._io.read_f8le()
            self._debug['m']['end'] = self._io.pos()


    class Record(KaitaiStruct):
        SEQ_FIELDS = ["header", "contents"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self.header = self._root.RecordHeader(self._io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            self._debug['contents']['start'] = self._io.pos()
            self.contents = self._root.RecordContents(self._io, self, self._root)
            self.contents._read()
            self._debug['contents']['end'] = self._io.pos()


    class RecordContents(KaitaiStruct):
        SEQ_FIELDS = ["shape_type", "shape_parameters"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['shape_type']['start'] = self._io.pos()
            self.shape_type = KaitaiStream.resolve_enum(self._root.ShapeType, self._io.read_s4le())
            self._debug['shape_type']['end'] = self._io.pos()
            if self.shape_type != self._root.ShapeType.null_shape:
                self._debug['shape_parameters']['start'] = self._io.pos()
                _on = self.shape_type
                if _on == self._root.ShapeType.poly_line_z:
                    self.shape_parameters = self._root.PolyLineZ(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.multi_patch:
                    self.shape_parameters = self._root.MultiPatch(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.poly_line_m:
                    self.shape_parameters = self._root.PolyLineM(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.polygon:
                    self.shape_parameters = self._root.Polygon(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.polygon_z:
                    self.shape_parameters = self._root.PolygonZ(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.point_z:
                    self.shape_parameters = self._root.PointZ(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.poly_line:
                    self.shape_parameters = self._root.PolyLine(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.point_m:
                    self.shape_parameters = self._root.PointM(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.polygon_m:
                    self.shape_parameters = self._root.PolygonM(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.multi_point:
                    self.shape_parameters = self._root.MultiPoint(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.point:
                    self.shape_parameters = self._root.Point(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.multi_point_m:
                    self.shape_parameters = self._root.MultiPointM(self._io, self, self._root)
                    self.shape_parameters._read()
                elif _on == self._root.ShapeType.multi_point_z:
                    self.shape_parameters = self._root.MultiPointZ(self._io, self, self._root)
                    self.shape_parameters._read()
                self._debug['shape_parameters']['end'] = self._io.pos()



    class MultiPatch(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "part_types", "points", "z_range", "z_values", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['part_types']['start'] = self._io.pos()
            self.part_types = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['part_types']:
                    self._debug['part_types']['arr'] = []
                self._debug['part_types']['arr'].append({'start': self._io.pos()})
                self.part_types[i] = KaitaiStream.resolve_enum(self._root.PartType, self._io.read_s4le())
                self._debug['part_types']['arr'][i]['end'] = self._io.pos()

            self._debug['part_types']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['z_range']['start'] = self._io.pos()
            self.z_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.z_range._read()
            self._debug['z_range']['end'] = self._io.pos()
            self._debug['z_values']['start'] = self._io.pos()
            self.z_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['z_values']:
                    self._debug['z_values']['arr'] = []
                self._debug['z_values']['arr'].append({'start': self._io.pos()})
                self.z_values[i] = self._io.read_f8le()
                self._debug['z_values']['arr'][i]['end'] = self._io.pos()

            self._debug['z_values']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()


    class PolyLineM(KaitaiStruct):
        SEQ_FIELDS = ["bounding_box", "number_of_parts", "number_of_points", "parts", "points", "m_range", "m_values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bounding_box']['start'] = self._io.pos()
            self.bounding_box = self._root.BoundingBoxXY(self._io, self, self._root)
            self.bounding_box._read()
            self._debug['bounding_box']['end'] = self._io.pos()
            self._debug['number_of_parts']['start'] = self._io.pos()
            self.number_of_parts = self._io.read_s4le()
            self._debug['number_of_parts']['end'] = self._io.pos()
            self._debug['number_of_points']['start'] = self._io.pos()
            self.number_of_points = self._io.read_s4le()
            self._debug['number_of_points']['end'] = self._io.pos()
            self._debug['parts']['start'] = self._io.pos()
            self.parts = [None] * (self.number_of_parts)
            for i in range(self.number_of_parts):
                if not 'arr' in self._debug['parts']:
                    self._debug['parts']['arr'] = []
                self._debug['parts']['arr'].append({'start': self._io.pos()})
                self.parts[i] = self._io.read_s4le()
                self._debug['parts']['arr'][i]['end'] = self._io.pos()

            self._debug['parts']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.Point(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()
            self._debug['m_range']['start'] = self._io.pos()
            self.m_range = self._root.BoundsMinMax(self._io, self, self._root)
            self.m_range._read()
            self._debug['m_range']['end'] = self._io.pos()
            self._debug['m_values']['start'] = self._io.pos()
            self.m_values = [None] * (self.number_of_points)
            for i in range(self.number_of_points):
                if not 'arr' in self._debug['m_values']:
                    self._debug['m_values']['arr'] = []
                self._debug['m_values']['arr'].append({'start': self._io.pos()})
                self.m_values[i] = self._io.read_f8le()
                self._debug['m_values']['arr'][i]['end'] = self._io.pos()

            self._debug['m_values']['end'] = self._io.pos()



