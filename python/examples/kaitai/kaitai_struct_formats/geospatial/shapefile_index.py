from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class ShapefileIndex(KaitaiStruct):

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


    class Record(KaitaiStruct):
        SEQ_FIELDS = ["offset", "content_length"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_s4be()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['content_length']['start'] = self._io.pos()
            self.content_length = self._io.read_s4be()
            self._debug['content_length']['end'] = self._io.pos()


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


    class BoundsMinMax(KaitaiStruct):
        SEQ_FIELDS = ["min", "max"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['min']['start'] = self._io.pos()
            self.min = self._io.read_f8be()
            self._debug['min']['end'] = self._io.pos()
            self._debug['max']['start'] = self._io.pos()
            self.max = self._io.read_f8be()
            self._debug['max']['end'] = self._io.pos()



