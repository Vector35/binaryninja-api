from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from exif import Exif
class Jpeg(KaitaiStruct):

    class ComponentId(Enum):
        y = 1
        cb = 2
        cr = 3
        i = 4
        q = 5
    SEQ_FIELDS = ["segments"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['segments']['start'] = self._io.pos()
        self.segments = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['segments']:
                self._debug['segments']['arr'] = []
            self._debug['segments']['arr'].append({'start': self._io.pos()})
            _t_segments = self._root.Segment(self._io, self, self._root)
            _t_segments._read()
            self.segments.append(_t_segments)
            self._debug['segments']['arr'][len(self.segments) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['segments']['end'] = self._io.pos()

    class Segment(KaitaiStruct):

        class MarkerEnum(Enum):
            tem = 1
            sof0 = 192
            sof1 = 193
            sof2 = 194
            sof3 = 195
            dht = 196
            sof5 = 197
            sof6 = 198
            sof7 = 199
            soi = 216
            eoi = 217
            sos = 218
            dqt = 219
            dnl = 220
            dri = 221
            dhp = 222
            app0 = 224
            app1 = 225
            app2 = 226
            app3 = 227
            app4 = 228
            app5 = 229
            app6 = 230
            app7 = 231
            app8 = 232
            app9 = 233
            app10 = 234
            app11 = 235
            app12 = 236
            app13 = 237
            app14 = 238
            app15 = 239
            com = 254
        SEQ_FIELDS = ["magic", "marker", "length", "data", "image_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\xFF")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['marker']['start'] = self._io.pos()
            self.marker = KaitaiStream.resolve_enum(self._root.Segment.MarkerEnum, self._io.read_u1())
            self._debug['marker']['end'] = self._io.pos()
            if  ((self.marker != self._root.Segment.MarkerEnum.soi) and (self.marker != self._root.Segment.MarkerEnum.eoi)) :
                self._debug['length']['start'] = self._io.pos()
                self.length = self._io.read_u2be()
                self._debug['length']['end'] = self._io.pos()

            if  ((self.marker != self._root.Segment.MarkerEnum.soi) and (self.marker != self._root.Segment.MarkerEnum.eoi)) :
                self._debug['data']['start'] = self._io.pos()
                _on = self.marker
                if _on == self._root.Segment.MarkerEnum.app1:
                    self._raw_data = self._io.read_bytes((self.length - 2))
                    io = KaitaiStream(BytesIO(self._raw_data))
                    self.data = self._root.SegmentApp1(io, self, self._root)
                    self.data._read()
                elif _on == self._root.Segment.MarkerEnum.app0:
                    self._raw_data = self._io.read_bytes((self.length - 2))
                    io = KaitaiStream(BytesIO(self._raw_data))
                    self.data = self._root.SegmentApp0(io, self, self._root)
                    self.data._read()
                elif _on == self._root.Segment.MarkerEnum.sof0:
                    self._raw_data = self._io.read_bytes((self.length - 2))
                    io = KaitaiStream(BytesIO(self._raw_data))
                    self.data = self._root.SegmentSof0(io, self, self._root)
                    self.data._read()
                elif _on == self._root.Segment.MarkerEnum.sos:
                    self._raw_data = self._io.read_bytes((self.length - 2))
                    io = KaitaiStream(BytesIO(self._raw_data))
                    self.data = self._root.SegmentSos(io, self, self._root)
                    self.data._read()
                else:
                    self.data = self._io.read_bytes((self.length - 2))
                self._debug['data']['end'] = self._io.pos()

            if self.marker == self._root.Segment.MarkerEnum.sos:
                self._debug['image_data']['start'] = self._io.pos()
                self.image_data = self._io.read_bytes_full()
                self._debug['image_data']['end'] = self._io.pos()



    class SegmentSos(KaitaiStruct):
        SEQ_FIELDS = ["num_components", "components", "start_spectral_selection", "end_spectral", "appr_bit_pos"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_components']['start'] = self._io.pos()
            self.num_components = self._io.read_u1()
            self._debug['num_components']['end'] = self._io.pos()
            self._debug['components']['start'] = self._io.pos()
            self.components = [None] * (self.num_components)
            for i in range(self.num_components):
                if not 'arr' in self._debug['components']:
                    self._debug['components']['arr'] = []
                self._debug['components']['arr'].append({'start': self._io.pos()})
                _t_components = self._root.SegmentSos.Component(self._io, self, self._root)
                _t_components._read()
                self.components[i] = _t_components
                self._debug['components']['arr'][i]['end'] = self._io.pos()

            self._debug['components']['end'] = self._io.pos()
            self._debug['start_spectral_selection']['start'] = self._io.pos()
            self.start_spectral_selection = self._io.read_u1()
            self._debug['start_spectral_selection']['end'] = self._io.pos()
            self._debug['end_spectral']['start'] = self._io.pos()
            self.end_spectral = self._io.read_u1()
            self._debug['end_spectral']['end'] = self._io.pos()
            self._debug['appr_bit_pos']['start'] = self._io.pos()
            self.appr_bit_pos = self._io.read_u1()
            self._debug['appr_bit_pos']['end'] = self._io.pos()

        class Component(KaitaiStruct):
            SEQ_FIELDS = ["id", "huffman_table"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['id']['start'] = self._io.pos()
                self.id = KaitaiStream.resolve_enum(self._root.ComponentId, self._io.read_u1())
                self._debug['id']['end'] = self._io.pos()
                self._debug['huffman_table']['start'] = self._io.pos()
                self.huffman_table = self._io.read_u1()
                self._debug['huffman_table']['end'] = self._io.pos()



    class SegmentApp1(KaitaiStruct):
        SEQ_FIELDS = ["magic", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.magic
            if _on == u"Exif":
                self.body = self._root.ExifInJpeg(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class SegmentSof0(KaitaiStruct):
        SEQ_FIELDS = ["bits_per_sample", "image_height", "image_width", "num_components", "components"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bits_per_sample']['start'] = self._io.pos()
            self.bits_per_sample = self._io.read_u1()
            self._debug['bits_per_sample']['end'] = self._io.pos()
            self._debug['image_height']['start'] = self._io.pos()
            self.image_height = self._io.read_u2be()
            self._debug['image_height']['end'] = self._io.pos()
            self._debug['image_width']['start'] = self._io.pos()
            self.image_width = self._io.read_u2be()
            self._debug['image_width']['end'] = self._io.pos()
            self._debug['num_components']['start'] = self._io.pos()
            self.num_components = self._io.read_u1()
            self._debug['num_components']['end'] = self._io.pos()
            self._debug['components']['start'] = self._io.pos()
            self.components = [None] * (self.num_components)
            for i in range(self.num_components):
                if not 'arr' in self._debug['components']:
                    self._debug['components']['arr'] = []
                self._debug['components']['arr'].append({'start': self._io.pos()})
                _t_components = self._root.SegmentSof0.Component(self._io, self, self._root)
                _t_components._read()
                self.components[i] = _t_components
                self._debug['components']['arr'][i]['end'] = self._io.pos()

            self._debug['components']['end'] = self._io.pos()

        class Component(KaitaiStruct):
            SEQ_FIELDS = ["id", "sampling_factors", "quantization_table_id"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['id']['start'] = self._io.pos()
                self.id = KaitaiStream.resolve_enum(self._root.ComponentId, self._io.read_u1())
                self._debug['id']['end'] = self._io.pos()
                self._debug['sampling_factors']['start'] = self._io.pos()
                self.sampling_factors = self._io.read_u1()
                self._debug['sampling_factors']['end'] = self._io.pos()
                self._debug['quantization_table_id']['start'] = self._io.pos()
                self.quantization_table_id = self._io.read_u1()
                self._debug['quantization_table_id']['end'] = self._io.pos()

            @property
            def sampling_x(self):
                if hasattr(self, '_m_sampling_x'):
                    return self._m_sampling_x if hasattr(self, '_m_sampling_x') else None

                self._m_sampling_x = ((self.sampling_factors & 240) >> 4)
                return self._m_sampling_x if hasattr(self, '_m_sampling_x') else None

            @property
            def sampling_y(self):
                if hasattr(self, '_m_sampling_y'):
                    return self._m_sampling_y if hasattr(self, '_m_sampling_y') else None

                self._m_sampling_y = (self.sampling_factors & 15)
                return self._m_sampling_y if hasattr(self, '_m_sampling_y') else None



    class ExifInJpeg(KaitaiStruct):
        SEQ_FIELDS = ["extra_zero", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['extra_zero']['start'] = self._io.pos()
            self.extra_zero = self._io.ensure_fixed_contents(b"\x00")
            self._debug['extra_zero']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self._raw_data = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_data))
            self.data = Exif(io)
            self.data._read()
            self._debug['data']['end'] = self._io.pos()


    class SegmentApp0(KaitaiStruct):

        class DensityUnit(Enum):
            no_units = 0
            pixels_per_inch = 1
            pixels_per_cm = 2
        SEQ_FIELDS = ["magic", "version_major", "version_minor", "density_units", "density_x", "density_y", "thumbnail_x", "thumbnail_y", "thumbnail"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = (self._io.read_bytes(5)).decode(u"ASCII")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version_major']['start'] = self._io.pos()
            self.version_major = self._io.read_u1()
            self._debug['version_major']['end'] = self._io.pos()
            self._debug['version_minor']['start'] = self._io.pos()
            self.version_minor = self._io.read_u1()
            self._debug['version_minor']['end'] = self._io.pos()
            self._debug['density_units']['start'] = self._io.pos()
            self.density_units = KaitaiStream.resolve_enum(self._root.SegmentApp0.DensityUnit, self._io.read_u1())
            self._debug['density_units']['end'] = self._io.pos()
            self._debug['density_x']['start'] = self._io.pos()
            self.density_x = self._io.read_u2be()
            self._debug['density_x']['end'] = self._io.pos()
            self._debug['density_y']['start'] = self._io.pos()
            self.density_y = self._io.read_u2be()
            self._debug['density_y']['end'] = self._io.pos()
            self._debug['thumbnail_x']['start'] = self._io.pos()
            self.thumbnail_x = self._io.read_u1()
            self._debug['thumbnail_x']['end'] = self._io.pos()
            self._debug['thumbnail_y']['start'] = self._io.pos()
            self.thumbnail_y = self._io.read_u1()
            self._debug['thumbnail_y']['end'] = self._io.pos()
            self._debug['thumbnail']['start'] = self._io.pos()
            self.thumbnail = self._io.read_bytes(((self.thumbnail_x * self.thumbnail_y) * 3))
            self._debug['thumbnail']['end'] = self._io.pos()



