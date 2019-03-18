from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Wmf(KaitaiStruct):
    """WMF (Windows Metafile) is a relatively early vector image format
    introduced for Microsoft Windows in 1990.
    
    Inside, it provides a serialized list of Windows GDI (Graphics
    Device Interface) function calls, which, if played back, result in
    an image being drawn on a given surface (display, off-screen buffer,
    printer, etc).
    
    .. seealso::
       Source - http://www.digitalpreservation.gov/formats/digformatspecs/WindowsMetafileFormat(wmf)Specification.pdf
    """

    class Func(Enum):
        eof = 0
        savedc = 30
        realizepalette = 53
        setpalentries = 55
        createpalette = 247
        setbkmode = 258
        setmapmode = 259
        setrop2 = 260
        setrelabs = 261
        setpolyfillmode = 262
        setstretchbltmode = 263
        settextcharextra = 264
        restoredc = 295
        invertregion = 298
        paintregion = 299
        selectclipregion = 300
        selectobject = 301
        settextalign = 302
        resizepalette = 313
        dibcreatepatternbrush = 322
        setlayout = 329
        deleteobject = 496
        createpatternbrush = 505
        setbkcolor = 513
        settextcolor = 521
        settextjustification = 522
        setwindoworg = 523
        setwindowext = 524
        setviewportorg = 525
        setviewportext = 526
        offsetwindoworg = 527
        offsetviewportorg = 529
        lineto = 531
        moveto = 532
        offsetcliprgn = 544
        fillregion = 552
        setmapperflags = 561
        selectpalette = 564
        createpenindirect = 762
        createfontindirect = 763
        createbrushindirect = 764
        polygon = 804
        polyline = 805
        scalewindowext = 1040
        scaleviewportext = 1042
        excludecliprect = 1045
        intersectcliprect = 1046
        ellipse = 1048
        floodfill = 1049
        rectangle = 1051
        setpixel = 1055
        frameregion = 1065
        animatepalette = 1078
        textout = 1313
        polypolygon = 1336
        extfloodfill = 1352
        roundrect = 1564
        patblt = 1565
        escape = 1574
        createregion = 1791
        arc = 2071
        pie = 2074
        chord = 2096
        bitblt = 2338
        dibbitblt = 2368
        exttextout = 2610
        stretchblt = 2851
        dibstretchblt = 2881
        setdibtodev = 3379
        stretchdib = 3907

    class BinRasterOp(Enum):
        black = 1
        notmergepen = 2
        masknotpen = 3
        notcopypen = 4
        maskpennot = 5
        not = 6
        xorpen = 7
        notmaskpen = 8
        maskpen = 9
        notxorpen = 10
        nop = 11
        mergenotpen = 12
        copypen = 13
        mergepennot = 14
        mergepen = 15
        white = 16

    class MixMode(Enum):
        transparent = 1
        opaque = 2

    class PolyFillMode(Enum):
        alternate = 1
        winding = 2
    SEQ_FIELDS = ["special_header", "header", "records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['special_header']['start'] = self._io.pos()
        self.special_header = self._root.SpecialHeader(self._io, self, self._root)
        self.special_header._read()
        self._debug['special_header']['end'] = self._io.pos()
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.Header(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['records']['start'] = self._io.pos()
        self.records = []
        i = 0
        while True:
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            _t_records = self._root.Record(self._io, self, self._root)
            _t_records._read()
            _ = _t_records
            self.records.append(_)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            if _.function == self._root.Func.eof:
                break
            i += 1
        self._debug['records']['end'] = self._io.pos()

    class ParamsSetwindoworg(KaitaiStruct):
        SEQ_FIELDS = ["y", "x"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_s2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_s2le()
            self._debug['x']['end'] = self._io.pos()


    class ParamsSetbkmode(KaitaiStruct):
        SEQ_FIELDS = ["bk_mode"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bk_mode']['start'] = self._io.pos()
            self.bk_mode = KaitaiStream.resolve_enum(self._root.MixMode, self._io.read_u2le())
            self._debug['bk_mode']['end'] = self._io.pos()


    class PointS(KaitaiStruct):
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


    class ParamsSetwindowext(KaitaiStruct):
        SEQ_FIELDS = ["y", "x"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_s2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_s2le()
            self._debug['x']['end'] = self._io.pos()


    class ParamsPolygon(KaitaiStruct):
        SEQ_FIELDS = ["num_points", "points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_points']['start'] = self._io.pos()
            self.num_points = self._io.read_s2le()
            self._debug['num_points']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.num_points)
            for i in range(self.num_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.PointS(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()


    class Header(KaitaiStruct):

        class MetafileType(Enum):
            memory_metafile = 1
            disk_metafile = 2
        SEQ_FIELDS = ["metafile_type", "header_size", "version", "size", "number_of_objects", "max_record", "number_of_members"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['metafile_type']['start'] = self._io.pos()
            self.metafile_type = KaitaiStream.resolve_enum(self._root.Header.MetafileType, self._io.read_u2le())
            self._debug['metafile_type']['end'] = self._io.pos()
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u2le()
            self._debug['header_size']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2le()
            self._debug['version']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['number_of_objects']['start'] = self._io.pos()
            self.number_of_objects = self._io.read_u2le()
            self._debug['number_of_objects']['end'] = self._io.pos()
            self._debug['max_record']['start'] = self._io.pos()
            self.max_record = self._io.read_u4le()
            self._debug['max_record']['end'] = self._io.pos()
            self._debug['number_of_members']['start'] = self._io.pos()
            self.number_of_members = self._io.read_u2le()
            self._debug['number_of_members']['end'] = self._io.pos()


    class ColorRef(KaitaiStruct):
        SEQ_FIELDS = ["red", "green", "blue", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['red']['start'] = self._io.pos()
            self.red = self._io.read_u1()
            self._debug['red']['end'] = self._io.pos()
            self._debug['green']['start'] = self._io.pos()
            self.green = self._io.read_u1()
            self._debug['green']['end'] = self._io.pos()
            self._debug['blue']['start'] = self._io.pos()
            self.blue = self._io.read_u1()
            self._debug['blue']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_u1()
            self._debug['reserved']['end'] = self._io.pos()


    class ParamsSetrop2(KaitaiStruct):
        SEQ_FIELDS = ["draw_mode"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['draw_mode']['start'] = self._io.pos()
            self.draw_mode = KaitaiStream.resolve_enum(self._root.BinRasterOp, self._io.read_u2le())
            self._debug['draw_mode']['end'] = self._io.pos()


    class ParamsSetpolyfillmode(KaitaiStruct):
        SEQ_FIELDS = ["poly_fill_mode"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['poly_fill_mode']['start'] = self._io.pos()
            self.poly_fill_mode = KaitaiStream.resolve_enum(self._root.PolyFillMode, self._io.read_u2le())
            self._debug['poly_fill_mode']['end'] = self._io.pos()


    class ParamsPolyline(KaitaiStruct):
        SEQ_FIELDS = ["num_points", "points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_points']['start'] = self._io.pos()
            self.num_points = self._io.read_s2le()
            self._debug['num_points']['end'] = self._io.pos()
            self._debug['points']['start'] = self._io.pos()
            self.points = [None] * (self.num_points)
            for i in range(self.num_points):
                if not 'arr' in self._debug['points']:
                    self._debug['points']['arr'] = []
                self._debug['points']['arr'].append({'start': self._io.pos()})
                _t_points = self._root.PointS(self._io, self, self._root)
                _t_points._read()
                self.points[i] = _t_points
                self._debug['points']['arr'][i]['end'] = self._io.pos()

            self._debug['points']['end'] = self._io.pos()


    class SpecialHeader(KaitaiStruct):
        SEQ_FIELDS = ["magic", "handle", "left", "top", "right", "bottom", "inch", "reserved", "checksum"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\xD7\xCD\xC6\x9A")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['handle']['start'] = self._io.pos()
            self.handle = self._io.ensure_fixed_contents(b"\x00\x00")
            self._debug['handle']['end'] = self._io.pos()
            self._debug['left']['start'] = self._io.pos()
            self.left = self._io.read_s2le()
            self._debug['left']['end'] = self._io.pos()
            self._debug['top']['start'] = self._io.pos()
            self.top = self._io.read_s2le()
            self._debug['top']['end'] = self._io.pos()
            self._debug['right']['start'] = self._io.pos()
            self.right = self._io.read_s2le()
            self._debug['right']['end'] = self._io.pos()
            self._debug['bottom']['start'] = self._io.pos()
            self.bottom = self._io.read_s2le()
            self._debug['bottom']['end'] = self._io.pos()
            self._debug['inch']['start'] = self._io.pos()
            self.inch = self._io.read_u2le()
            self._debug['inch']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00")
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u2le()
            self._debug['checksum']['end'] = self._io.pos()


    class Record(KaitaiStruct):
        SEQ_FIELDS = ["size", "function", "params"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['function']['start'] = self._io.pos()
            self.function = KaitaiStream.resolve_enum(self._root.Func, self._io.read_u2le())
            self._debug['function']['end'] = self._io.pos()
            self._debug['params']['start'] = self._io.pos()
            _on = self.function
            if _on == self._root.Func.setbkmode:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsSetbkmode(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.polygon:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsPolygon(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.setbkcolor:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ColorRef(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.setpolyfillmode:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsSetpolyfillmode(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.setwindoworg:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsSetwindoworg(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.setrop2:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsSetrop2(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.setwindowext:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsSetwindowext(io, self, self._root)
                self.params._read()
            elif _on == self._root.Func.polyline:
                self._raw_params = self._io.read_bytes(((self.size - 3) * 2))
                io = KaitaiStream(BytesIO(self._raw_params))
                self.params = self._root.ParamsPolyline(io, self, self._root)
                self.params._read()
            else:
                self.params = self._io.read_bytes(((self.size - 3) * 2))
            self._debug['params']['end'] = self._io.pos()



