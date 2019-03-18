from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ....kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class NtMdt(KaitaiStruct):
    """A native file format of NT-MDT scientific software. Usually contains
    any of:
    
    * [Scanning probe](https://en.wikipedia.org/wiki/Scanning_probe_microscopy) microscopy scans and spectra
    * [Raman spectra](https://en.wikipedia.org/wiki/Raman_spectroscopy)
    * results of their analysis
    
    Some examples of mdt files can be downloaded at:
    
    * http://www.ntmdt-si.ru/scan-gallery
    * http://callistosoft.narod.ru/Resources/Mdt.zip
    
    .. seealso::
       Source - https://svn.code.sf.net/p/gwyddion/code/trunk/gwyddion/modules/file/nt-mdt.c
    """

    class AdcMode(Enum):
        height = 0
        dfl = 1
        lateral_f = 2
        bias_v = 3
        current = 4
        fb_out = 5
        mag = 6
        mag_sin = 7
        mag_cos = 8
        rms = 9
        calc_mag = 10
        phase1 = 11
        phase2 = 12
        calc_phase = 13
        ex1 = 14
        ex2 = 15
        hv_x = 16
        hv_y = 17
        snap_back = 18
        false = 255

    class XmlScanLocation(Enum):
        hlt = 0
        hlb = 1
        hrt = 2
        hrb = 3
        vlt = 4
        vlb = 5
        vrt = 6
        vrb = 7

    class DataType(Enum):
        floatfix = -65544
        float80 = -16138
        float64 = -13320
        float48 = -9990
        float32 = -5892
        int64 = -8
        int32 = -4
        int16 = -2
        int8 = -1
        unknown0 = 0
        uint8 = 1
        uint16 = 2
        uint32 = 4
        uint64 = 8

    class XmlParamType(Enum):
        none = 0
        laser_wavelength = 1
        units = 2
        data_array = 255

    class SpmMode(Enum):
        constant_force = 0
        contact_constant_height = 1
        contact_error = 2
        lateral_force = 3
        force_modulation = 4
        spreading_resistance_imaging = 5
        semicontact_topography = 6
        semicontact_error = 7
        phase_contrast = 8
        ac_magnetic_force = 9
        dc_magnetic_force = 10
        electrostatic_force = 11
        capacitance_contrast = 12
        kelvin_probe = 13
        constant_current = 14
        barrier_height = 15
        constant_height = 16
        afam = 17
        contact_efm = 18
        shear_force_topography = 19
        sfom = 20
        contact_capacitance = 21
        snom_transmission = 22
        snom_reflection = 23
        snom_all = 24
        snom = 25

    class Unit(Enum):
        raman_shift = -10
        reserved0 = -9
        reserved1 = -8
        reserved2 = -7
        reserved3 = -6
        meter = -5
        centi_meter = -4
        milli_meter = -3
        micro_meter = -2
        nano_meter = -1
        angstrom = 0
        nano_ampere = 1
        volt = 2
        none = 3
        kilo_hertz = 4
        degrees = 5
        percent = 6
        celsius_degree = 7
        volt_high = 8
        second = 9
        milli_second = 10
        micro_second = 11
        nano_second = 12
        counts = 13
        pixels = 14
        reserved_sfom0 = 15
        reserved_sfom1 = 16
        reserved_sfom2 = 17
        reserved_sfom3 = 18
        reserved_sfom4 = 19
        ampere2 = 20
        milli_ampere = 21
        micro_ampere = 22
        nano_ampere2 = 23
        pico_ampere = 24
        volt2 = 25
        milli_volt = 26
        micro_volt = 27
        nano_volt = 28
        pico_volt = 29
        newton = 30
        milli_newton = 31
        micro_newton = 32
        nano_newton = 33
        pico_newton = 34
        reserved_dos0 = 35
        reserved_dos1 = 36
        reserved_dos2 = 37
        reserved_dos3 = 38
        reserved_dos4 = 39

    class SpmTechnique(Enum):
        contact_mode = 0
        semicontact_mode = 1
        tunnel_current = 2
        snom = 3

    class Consts(Enum):
        frame_mode_size = 8
        frame_header_size = 22
        axis_scales_size = 30
        file_header_size = 32
        spectro_vars_min_size = 38
        scan_vars_min_size = 77
    SEQ_FIELDS = ["signature", "size", "reserved0", "last_frame", "reserved1", "wrond_doc", "frames"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['signature']['start'] = self._io.pos()
        self.signature = self._io.ensure_fixed_contents(b"\x01\xB0\x93\xFF")
        self._debug['signature']['end'] = self._io.pos()
        self._debug['size']['start'] = self._io.pos()
        self.size = self._io.read_u4le()
        self._debug['size']['end'] = self._io.pos()
        self._debug['reserved0']['start'] = self._io.pos()
        self.reserved0 = self._io.read_bytes(4)
        self._debug['reserved0']['end'] = self._io.pos()
        self._debug['last_frame']['start'] = self._io.pos()
        self.last_frame = self._io.read_u2le()
        self._debug['last_frame']['end'] = self._io.pos()
        self._debug['reserved1']['start'] = self._io.pos()
        self.reserved1 = self._io.read_bytes(18)
        self._debug['reserved1']['end'] = self._io.pos()
        self._debug['wrond_doc']['start'] = self._io.pos()
        self.wrond_doc = self._io.read_bytes(1)
        self._debug['wrond_doc']['end'] = self._io.pos()
        self._debug['frames']['start'] = self._io.pos()
        self._raw_frames = self._io.read_bytes(self.size)
        io = KaitaiStream(BytesIO(self._raw_frames))
        self.frames = self._root.Framez(io, self, self._root)
        self.frames._read()
        self._debug['frames']['end'] = self._io.pos()

    class Uuid(KaitaiStruct):
        SEQ_FIELDS = ["data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['data']['start'] = self._io.pos()
            self.data = [None] * (16)
            for i in range(16):
                if not 'arr' in self._debug['data']:
                    self._debug['data']['arr'] = []
                self._debug['data']['arr'].append({'start': self._io.pos()})
                self.data[i] = self._io.read_u1()
                self._debug['data']['arr'][i]['end'] = self._io.pos()

            self._debug['data']['end'] = self._io.pos()


    class Framez(KaitaiStruct):
        SEQ_FIELDS = ["frames"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['frames']['start'] = self._io.pos()
            self.frames = [None] * ((self._root.last_frame + 1))
            for i in range((self._root.last_frame + 1)):
                if not 'arr' in self._debug['frames']:
                    self._debug['frames']['arr'] = []
                self._debug['frames']['arr'].append({'start': self._io.pos()})
                _t_frames = self._root.Frame(self._io, self, self._root)
                _t_frames._read()
                self.frames[i] = _t_frames
                self._debug['frames']['arr'][i]['end'] = self._io.pos()

            self._debug['frames']['end'] = self._io.pos()


    class Frame(KaitaiStruct):

        class FrameType(Enum):
            scanned = 0
            spectroscopy = 1
            text = 3
            old_mda = 105
            mda = 106
            palette = 107
            curves_new = 190
            curves = 201
        SEQ_FIELDS = ["size", "main"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['main']['start'] = self._io.pos()
            self._raw_main = self._io.read_bytes((self.size - 4))
            io = KaitaiStream(BytesIO(self._raw_main))
            self.main = self._root.Frame.FrameMain(io, self, self._root)
            self.main._read()
            self._debug['main']['end'] = self._io.pos()

        class Dots(KaitaiStruct):
            SEQ_FIELDS = ["fm_ndots", "coord_header", "coordinates", "data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['fm_ndots']['start'] = self._io.pos()
                self.fm_ndots = self._io.read_u2le()
                self._debug['fm_ndots']['end'] = self._io.pos()
                if self.fm_ndots > 0:
                    self._debug['coord_header']['start'] = self._io.pos()
                    self.coord_header = self._root.Frame.Dots.DotsHeader(self._io, self, self._root)
                    self.coord_header._read()
                    self._debug['coord_header']['end'] = self._io.pos()

                self._debug['coordinates']['start'] = self._io.pos()
                self.coordinates = [None] * (self.fm_ndots)
                for i in range(self.fm_ndots):
                    if not 'arr' in self._debug['coordinates']:
                        self._debug['coordinates']['arr'] = []
                    self._debug['coordinates']['arr'].append({'start': self._io.pos()})
                    _t_coordinates = self._root.Frame.Dots.DotsData(self._io, self, self._root)
                    _t_coordinates._read()
                    self.coordinates[i] = _t_coordinates
                    self._debug['coordinates']['arr'][i]['end'] = self._io.pos()

                self._debug['coordinates']['end'] = self._io.pos()
                self._debug['data']['start'] = self._io.pos()
                self.data = [None] * (self.fm_ndots)
                for i in range(self.fm_ndots):
                    if not 'arr' in self._debug['data']:
                        self._debug['data']['arr'] = []
                    self._debug['data']['arr'].append({'start': self._io.pos()})
                    _t_data = self._root.Frame.Dots.DataLinez(i, self._io, self, self._root)
                    _t_data._read()
                    self.data[i] = _t_data
                    self._debug['data']['arr'][i]['end'] = self._io.pos()

                self._debug['data']['end'] = self._io.pos()

            class DotsHeader(KaitaiStruct):
                SEQ_FIELDS = ["header_size", "header"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['header_size']['start'] = self._io.pos()
                    self.header_size = self._io.read_s4le()
                    self._debug['header_size']['end'] = self._io.pos()
                    self._debug['header']['start'] = self._io.pos()
                    self._raw_header = self._io.read_bytes(self.header_size)
                    io = KaitaiStream(BytesIO(self._raw_header))
                    self.header = self._root.Frame.Dots.DotsHeader.Header(io, self, self._root)
                    self.header._read()
                    self._debug['header']['end'] = self._io.pos()

                class Header(KaitaiStruct):
                    SEQ_FIELDS = ["coord_size", "version", "xyunits"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['coord_size']['start'] = self._io.pos()
                        self.coord_size = self._io.read_s4le()
                        self._debug['coord_size']['end'] = self._io.pos()
                        self._debug['version']['start'] = self._io.pos()
                        self.version = self._io.read_s4le()
                        self._debug['version']['end'] = self._io.pos()
                        self._debug['xyunits']['start'] = self._io.pos()
                        self.xyunits = KaitaiStream.resolve_enum(self._root.Unit, self._io.read_s2le())
                        self._debug['xyunits']['end'] = self._io.pos()



            class DotsData(KaitaiStruct):
                SEQ_FIELDS = ["coord_x", "coord_y", "forward_size", "backward_size"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['coord_x']['start'] = self._io.pos()
                    self.coord_x = self._io.read_f4le()
                    self._debug['coord_x']['end'] = self._io.pos()
                    self._debug['coord_y']['start'] = self._io.pos()
                    self.coord_y = self._io.read_f4le()
                    self._debug['coord_y']['end'] = self._io.pos()
                    self._debug['forward_size']['start'] = self._io.pos()
                    self.forward_size = self._io.read_s4le()
                    self._debug['forward_size']['end'] = self._io.pos()
                    self._debug['backward_size']['start'] = self._io.pos()
                    self.backward_size = self._io.read_s4le()
                    self._debug['backward_size']['end'] = self._io.pos()


            class DataLinez(KaitaiStruct):
                SEQ_FIELDS = ["forward", "backward"]
                def __init__(self, index, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.index = index
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['forward']['start'] = self._io.pos()
                    self.forward = [None] * (self._parent.coordinates[self.index].forward_size)
                    for i in range(self._parent.coordinates[self.index].forward_size):
                        if not 'arr' in self._debug['forward']:
                            self._debug['forward']['arr'] = []
                        self._debug['forward']['arr'].append({'start': self._io.pos()})
                        self.forward[i] = self._io.read_s2le()
                        self._debug['forward']['arr'][i]['end'] = self._io.pos()

                    self._debug['forward']['end'] = self._io.pos()
                    self._debug['backward']['start'] = self._io.pos()
                    self.backward = [None] * (self._parent.coordinates[self.index].backward_size)
                    for i in range(self._parent.coordinates[self.index].backward_size):
                        if not 'arr' in self._debug['backward']:
                            self._debug['backward']['arr'] = []
                        self._debug['backward']['arr'].append({'start': self._io.pos()})
                        self.backward[i] = self._io.read_s2le()
                        self._debug['backward']['arr'][i]['end'] = self._io.pos()

                    self._debug['backward']['end'] = self._io.pos()



        class FrameMain(KaitaiStruct):
            SEQ_FIELDS = ["type", "version", "date_time", "var_size", "frame_data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.Frame.FrameType, self._io.read_u2le())
                self._debug['type']['end'] = self._io.pos()
                self._debug['version']['start'] = self._io.pos()
                self.version = self._root.Version(self._io, self, self._root)
                self.version._read()
                self._debug['version']['end'] = self._io.pos()
                self._debug['date_time']['start'] = self._io.pos()
                self.date_time = self._root.Frame.DateTime(self._io, self, self._root)
                self.date_time._read()
                self._debug['date_time']['end'] = self._io.pos()
                self._debug['var_size']['start'] = self._io.pos()
                self.var_size = self._io.read_u2le()
                self._debug['var_size']['end'] = self._io.pos()
                self._debug['frame_data']['start'] = self._io.pos()
                _on = self.type
                if _on == self._root.Frame.FrameType.mda:
                    self._raw_frame_data = self._io.read_bytes_full()
                    io = KaitaiStream(BytesIO(self._raw_frame_data))
                    self.frame_data = self._root.Frame.FdMetaData(io, self, self._root)
                    self.frame_data._read()
                elif _on == self._root.Frame.FrameType.curves_new:
                    self._raw_frame_data = self._io.read_bytes_full()
                    io = KaitaiStream(BytesIO(self._raw_frame_data))
                    self.frame_data = self._root.Frame.FdCurvesNew(io, self, self._root)
                    self.frame_data._read()
                elif _on == self._root.Frame.FrameType.curves:
                    self._raw_frame_data = self._io.read_bytes_full()
                    io = KaitaiStream(BytesIO(self._raw_frame_data))
                    self.frame_data = self._root.Frame.FdSpectroscopy(io, self, self._root)
                    self.frame_data._read()
                elif _on == self._root.Frame.FrameType.spectroscopy:
                    self._raw_frame_data = self._io.read_bytes_full()
                    io = KaitaiStream(BytesIO(self._raw_frame_data))
                    self.frame_data = self._root.Frame.FdSpectroscopy(io, self, self._root)
                    self.frame_data._read()
                elif _on == self._root.Frame.FrameType.scanned:
                    self._raw_frame_data = self._io.read_bytes_full()
                    io = KaitaiStream(BytesIO(self._raw_frame_data))
                    self.frame_data = self._root.Frame.FdScanned(io, self, self._root)
                    self.frame_data._read()
                else:
                    self.frame_data = self._io.read_bytes_full()
                self._debug['frame_data']['end'] = self._io.pos()


        class FdCurvesNew(KaitaiStruct):
            SEQ_FIELDS = ["block_count", "blocks_headers", "blocks_names", "blocks_data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['block_count']['start'] = self._io.pos()
                self.block_count = self._io.read_u4le()
                self._debug['block_count']['end'] = self._io.pos()
                self._debug['blocks_headers']['start'] = self._io.pos()
                self.blocks_headers = [None] * (self.block_count)
                for i in range(self.block_count):
                    if not 'arr' in self._debug['blocks_headers']:
                        self._debug['blocks_headers']['arr'] = []
                    self._debug['blocks_headers']['arr'].append({'start': self._io.pos()})
                    _t_blocks_headers = self._root.Frame.FdCurvesNew.BlockDescr(self._io, self, self._root)
                    _t_blocks_headers._read()
                    self.blocks_headers[i] = _t_blocks_headers
                    self._debug['blocks_headers']['arr'][i]['end'] = self._io.pos()

                self._debug['blocks_headers']['end'] = self._io.pos()
                self._debug['blocks_names']['start'] = self._io.pos()
                self.blocks_names = [None] * (self.block_count)
                for i in range(self.block_count):
                    if not 'arr' in self._debug['blocks_names']:
                        self._debug['blocks_names']['arr'] = []
                    self._debug['blocks_names']['arr'].append({'start': self._io.pos()})
                    self.blocks_names[i] = (self._io.read_bytes(self.blocks_headers[i].name_len)).decode(u"UTF-8")
                    self._debug['blocks_names']['arr'][i]['end'] = self._io.pos()

                self._debug['blocks_names']['end'] = self._io.pos()
                self._debug['blocks_data']['start'] = self._io.pos()
                self.blocks_data = [None] * (self.block_count)
                for i in range(self.block_count):
                    if not 'arr' in self._debug['blocks_data']:
                        self._debug['blocks_data']['arr'] = []
                    self._debug['blocks_data']['arr'].append({'start': self._io.pos()})
                    self.blocks_data[i] = self._io.read_bytes(self.blocks_headers[i].len)
                    self._debug['blocks_data']['arr'][i]['end'] = self._io.pos()

                self._debug['blocks_data']['end'] = self._io.pos()

            class BlockDescr(KaitaiStruct):
                SEQ_FIELDS = ["name_len", "len"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['name_len']['start'] = self._io.pos()
                    self.name_len = self._io.read_u4le()
                    self._debug['name_len']['end'] = self._io.pos()
                    self._debug['len']['start'] = self._io.pos()
                    self.len = self._io.read_u4le()
                    self._debug['len']['end'] = self._io.pos()



        class FdMetaData(KaitaiStruct):
            SEQ_FIELDS = ["head_size", "tot_len", "guids", "frame_status", "name_size", "comm_size", "view_info_size", "spec_size", "source_info_size", "var_size", "data_offset", "data_size", "title", "xml", "struct_len", "array_size", "cell_size", "n_dimensions", "n_mesurands", "dimensions", "mesurands"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['head_size']['start'] = self._io.pos()
                self.head_size = self._io.read_u4le()
                self._debug['head_size']['end'] = self._io.pos()
                self._debug['tot_len']['start'] = self._io.pos()
                self.tot_len = self._io.read_u4le()
                self._debug['tot_len']['end'] = self._io.pos()
                self._debug['guids']['start'] = self._io.pos()
                self.guids = [None] * (2)
                for i in range(2):
                    if not 'arr' in self._debug['guids']:
                        self._debug['guids']['arr'] = []
                    self._debug['guids']['arr'].append({'start': self._io.pos()})
                    _t_guids = self._root.Uuid(self._io, self, self._root)
                    _t_guids._read()
                    self.guids[i] = _t_guids
                    self._debug['guids']['arr'][i]['end'] = self._io.pos()

                self._debug['guids']['end'] = self._io.pos()
                self._debug['frame_status']['start'] = self._io.pos()
                self.frame_status = self._io.read_bytes(4)
                self._debug['frame_status']['end'] = self._io.pos()
                self._debug['name_size']['start'] = self._io.pos()
                self.name_size = self._io.read_u4le()
                self._debug['name_size']['end'] = self._io.pos()
                self._debug['comm_size']['start'] = self._io.pos()
                self.comm_size = self._io.read_u4le()
                self._debug['comm_size']['end'] = self._io.pos()
                self._debug['view_info_size']['start'] = self._io.pos()
                self.view_info_size = self._io.read_u4le()
                self._debug['view_info_size']['end'] = self._io.pos()
                self._debug['spec_size']['start'] = self._io.pos()
                self.spec_size = self._io.read_u4le()
                self._debug['spec_size']['end'] = self._io.pos()
                self._debug['source_info_size']['start'] = self._io.pos()
                self.source_info_size = self._io.read_u4le()
                self._debug['source_info_size']['end'] = self._io.pos()
                self._debug['var_size']['start'] = self._io.pos()
                self.var_size = self._io.read_u4le()
                self._debug['var_size']['end'] = self._io.pos()
                self._debug['data_offset']['start'] = self._io.pos()
                self.data_offset = self._io.read_u4le()
                self._debug['data_offset']['end'] = self._io.pos()
                self._debug['data_size']['start'] = self._io.pos()
                self.data_size = self._io.read_u4le()
                self._debug['data_size']['end'] = self._io.pos()
                self._debug['title']['start'] = self._io.pos()
                self.title = (self._io.read_bytes(self.name_size)).decode(u"UTF-8")
                self._debug['title']['end'] = self._io.pos()
                self._debug['xml']['start'] = self._io.pos()
                self.xml = (self._io.read_bytes(self.comm_size)).decode(u"UTF-8")
                self._debug['xml']['end'] = self._io.pos()
                self._debug['struct_len']['start'] = self._io.pos()
                self.struct_len = self._io.read_u4le()
                self._debug['struct_len']['end'] = self._io.pos()
                self._debug['array_size']['start'] = self._io.pos()
                self.array_size = self._io.read_u8le()
                self._debug['array_size']['end'] = self._io.pos()
                self._debug['cell_size']['start'] = self._io.pos()
                self.cell_size = self._io.read_u4le()
                self._debug['cell_size']['end'] = self._io.pos()
                self._debug['n_dimensions']['start'] = self._io.pos()
                self.n_dimensions = self._io.read_u4le()
                self._debug['n_dimensions']['end'] = self._io.pos()
                self._debug['n_mesurands']['start'] = self._io.pos()
                self.n_mesurands = self._io.read_u4le()
                self._debug['n_mesurands']['end'] = self._io.pos()
                self._debug['dimensions']['start'] = self._io.pos()
                self.dimensions = [None] * (self.n_dimensions)
                for i in range(self.n_dimensions):
                    if not 'arr' in self._debug['dimensions']:
                        self._debug['dimensions']['arr'] = []
                    self._debug['dimensions']['arr'].append({'start': self._io.pos()})
                    _t_dimensions = self._root.Frame.FdMetaData.Calibration(self._io, self, self._root)
                    _t_dimensions._read()
                    self.dimensions[i] = _t_dimensions
                    self._debug['dimensions']['arr'][i]['end'] = self._io.pos()

                self._debug['dimensions']['end'] = self._io.pos()
                self._debug['mesurands']['start'] = self._io.pos()
                self.mesurands = [None] * (self.n_mesurands)
                for i in range(self.n_mesurands):
                    if not 'arr' in self._debug['mesurands']:
                        self._debug['mesurands']['arr'] = []
                    self._debug['mesurands']['arr'].append({'start': self._io.pos()})
                    _t_mesurands = self._root.Frame.FdMetaData.Calibration(self._io, self, self._root)
                    _t_mesurands._read()
                    self.mesurands[i] = _t_mesurands
                    self._debug['mesurands']['arr'][i]['end'] = self._io.pos()

                self._debug['mesurands']['end'] = self._io.pos()

            class Image(KaitaiStruct):
                SEQ_FIELDS = ["image"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['image']['start'] = self._io.pos()
                    self.image = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['image']:
                            self._debug['image']['arr'] = []
                        self._debug['image']['arr'].append({'start': self._io.pos()})
                        _t_image = self._root.Frame.FdMetaData.Image.Vec(self._io, self, self._root)
                        _t_image._read()
                        self.image.append(_t_image)
                        self._debug['image']['arr'][len(self.image) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['image']['end'] = self._io.pos()

                class Vec(KaitaiStruct):
                    SEQ_FIELDS = ["items"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['items']['start'] = self._io.pos()
                        self.items = [None] * (self._parent._parent.n_mesurands)
                        for i in range(self._parent._parent.n_mesurands):
                            if not 'arr' in self._debug['items']:
                                self._debug['items']['arr'] = []
                            self._debug['items']['arr'].append({'start': self._io.pos()})
                            _on = self._parent._parent.mesurands[i].data_type
                            if _on == self._root.DataType.uint64:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_u8le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.uint8:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_u1()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.float32:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_f4le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.int8:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_s1()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.uint16:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_u2le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.int64:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_s8le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.uint32:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_u4le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.float64:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_f8le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.int16:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_s2le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            elif _on == self._root.DataType.int32:
                                if not 'arr' in self._debug['items']:
                                    self._debug['items']['arr'] = []
                                self._debug['items']['arr'].append({'start': self._io.pos()})
                                self.items[i] = self._io.read_s4le()
                                self._debug['items']['arr'][i]['end'] = self._io.pos()
                            self._debug['items']['arr'][i]['end'] = self._io.pos()

                        self._debug['items']['end'] = self._io.pos()



            class Calibration(KaitaiStruct):
                SEQ_FIELDS = ["len_tot", "len_struct", "len_name", "len_comment", "len_unit", "si_unit", "accuracy", "function_id_and_dimensions", "bias", "scale", "min_index", "max_index", "data_type", "len_author", "name", "comment", "unit", "author"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['len_tot']['start'] = self._io.pos()
                    self.len_tot = self._io.read_u4le()
                    self._debug['len_tot']['end'] = self._io.pos()
                    self._debug['len_struct']['start'] = self._io.pos()
                    self.len_struct = self._io.read_u4le()
                    self._debug['len_struct']['end'] = self._io.pos()
                    self._debug['len_name']['start'] = self._io.pos()
                    self.len_name = self._io.read_u4le()
                    self._debug['len_name']['end'] = self._io.pos()
                    self._debug['len_comment']['start'] = self._io.pos()
                    self.len_comment = self._io.read_u4le()
                    self._debug['len_comment']['end'] = self._io.pos()
                    self._debug['len_unit']['start'] = self._io.pos()
                    self.len_unit = self._io.read_u4le()
                    self._debug['len_unit']['end'] = self._io.pos()
                    self._debug['si_unit']['start'] = self._io.pos()
                    self.si_unit = self._io.read_u8le()
                    self._debug['si_unit']['end'] = self._io.pos()
                    self._debug['accuracy']['start'] = self._io.pos()
                    self.accuracy = self._io.read_f8le()
                    self._debug['accuracy']['end'] = self._io.pos()
                    self._debug['function_id_and_dimensions']['start'] = self._io.pos()
                    self.function_id_and_dimensions = self._io.read_u8le()
                    self._debug['function_id_and_dimensions']['end'] = self._io.pos()
                    self._debug['bias']['start'] = self._io.pos()
                    self.bias = self._io.read_f8le()
                    self._debug['bias']['end'] = self._io.pos()
                    self._debug['scale']['start'] = self._io.pos()
                    self.scale = self._io.read_f8le()
                    self._debug['scale']['end'] = self._io.pos()
                    self._debug['min_index']['start'] = self._io.pos()
                    self.min_index = self._io.read_u8le()
                    self._debug['min_index']['end'] = self._io.pos()
                    self._debug['max_index']['start'] = self._io.pos()
                    self.max_index = self._io.read_u8le()
                    self._debug['max_index']['end'] = self._io.pos()
                    self._debug['data_type']['start'] = self._io.pos()
                    self.data_type = KaitaiStream.resolve_enum(self._root.DataType, self._io.read_s4le())
                    self._debug['data_type']['end'] = self._io.pos()
                    self._debug['len_author']['start'] = self._io.pos()
                    self.len_author = self._io.read_u4le()
                    self._debug['len_author']['end'] = self._io.pos()
                    self._debug['name']['start'] = self._io.pos()
                    self.name = (self._io.read_bytes(self.len_name)).decode(u"utf-8")
                    self._debug['name']['end'] = self._io.pos()
                    self._debug['comment']['start'] = self._io.pos()
                    self.comment = (self._io.read_bytes(self.len_comment)).decode(u"utf-8")
                    self._debug['comment']['end'] = self._io.pos()
                    self._debug['unit']['start'] = self._io.pos()
                    self.unit = (self._io.read_bytes(self.len_unit)).decode(u"utf-8")
                    self._debug['unit']['end'] = self._io.pos()
                    self._debug['author']['start'] = self._io.pos()
                    self.author = (self._io.read_bytes(self.len_author)).decode(u"utf-8")
                    self._debug['author']['end'] = self._io.pos()

                @property
                def count(self):
                    if hasattr(self, '_m_count'):
                        return self._m_count if hasattr(self, '_m_count') else None

                    self._m_count = ((self.max_index - self.min_index) + 1)
                    return self._m_count if hasattr(self, '_m_count') else None


            @property
            def image(self):
                if hasattr(self, '_m_image'):
                    return self._m_image if hasattr(self, '_m_image') else None

                _pos = self._io.pos()
                self._io.seek(self.data_offset)
                self._debug['_m_image']['start'] = self._io.pos()
                self._raw__m_image = self._io.read_bytes(self.data_size)
                io = KaitaiStream(BytesIO(self._raw__m_image))
                self._m_image = self._root.Frame.FdMetaData.Image(io, self, self._root)
                self._m_image._read()
                self._debug['_m_image']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_image if hasattr(self, '_m_image') else None


        class FdSpectroscopy(KaitaiStruct):
            SEQ_FIELDS = ["vars", "fm_mode", "fm_xres", "fm_yres", "dots", "data", "title", "xml"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['vars']['start'] = self._io.pos()
                self._raw_vars = self._io.read_bytes(self._parent.var_size)
                io = KaitaiStream(BytesIO(self._raw_vars))
                self.vars = self._root.Frame.FdSpectroscopy.Vars(io, self, self._root)
                self.vars._read()
                self._debug['vars']['end'] = self._io.pos()
                self._debug['fm_mode']['start'] = self._io.pos()
                self.fm_mode = self._io.read_u2le()
                self._debug['fm_mode']['end'] = self._io.pos()
                self._debug['fm_xres']['start'] = self._io.pos()
                self.fm_xres = self._io.read_u2le()
                self._debug['fm_xres']['end'] = self._io.pos()
                self._debug['fm_yres']['start'] = self._io.pos()
                self.fm_yres = self._io.read_u2le()
                self._debug['fm_yres']['end'] = self._io.pos()
                self._debug['dots']['start'] = self._io.pos()
                self.dots = self._root.Frame.Dots(self._io, self, self._root)
                self.dots._read()
                self._debug['dots']['end'] = self._io.pos()
                self._debug['data']['start'] = self._io.pos()
                self.data = [None] * ((self.fm_xres * self.fm_yres))
                for i in range((self.fm_xres * self.fm_yres)):
                    if not 'arr' in self._debug['data']:
                        self._debug['data']['arr'] = []
                    self._debug['data']['arr'].append({'start': self._io.pos()})
                    self.data[i] = self._io.read_s2le()
                    self._debug['data']['arr'][i]['end'] = self._io.pos()

                self._debug['data']['end'] = self._io.pos()
                self._debug['title']['start'] = self._io.pos()
                self.title = self._root.Title(self._io, self, self._root)
                self.title._read()
                self._debug['title']['end'] = self._io.pos()
                self._debug['xml']['start'] = self._io.pos()
                self.xml = self._root.Xml(self._io, self, self._root)
                self.xml._read()
                self._debug['xml']['end'] = self._io.pos()

            class Vars(KaitaiStruct):
                SEQ_FIELDS = ["x_scale", "y_scale", "z_scale", "sp_mode", "sp_filter", "u_begin", "u_end", "z_up", "z_down", "sp_averaging", "sp_repeat", "sp_back", "sp_4nx", "sp_osc", "sp_n4", "sp_4x0", "sp_4xr", "sp_4u", "sp_4i", "sp_nx"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['x_scale']['start'] = self._io.pos()
                    self.x_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.x_scale._read()
                    self._debug['x_scale']['end'] = self._io.pos()
                    self._debug['y_scale']['start'] = self._io.pos()
                    self.y_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.y_scale._read()
                    self._debug['y_scale']['end'] = self._io.pos()
                    self._debug['z_scale']['start'] = self._io.pos()
                    self.z_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.z_scale._read()
                    self._debug['z_scale']['end'] = self._io.pos()
                    self._debug['sp_mode']['start'] = self._io.pos()
                    self.sp_mode = self._io.read_u2le()
                    self._debug['sp_mode']['end'] = self._io.pos()
                    self._debug['sp_filter']['start'] = self._io.pos()
                    self.sp_filter = self._io.read_u2le()
                    self._debug['sp_filter']['end'] = self._io.pos()
                    self._debug['u_begin']['start'] = self._io.pos()
                    self.u_begin = self._io.read_f4le()
                    self._debug['u_begin']['end'] = self._io.pos()
                    self._debug['u_end']['start'] = self._io.pos()
                    self.u_end = self._io.read_f4le()
                    self._debug['u_end']['end'] = self._io.pos()
                    self._debug['z_up']['start'] = self._io.pos()
                    self.z_up = self._io.read_s2le()
                    self._debug['z_up']['end'] = self._io.pos()
                    self._debug['z_down']['start'] = self._io.pos()
                    self.z_down = self._io.read_s2le()
                    self._debug['z_down']['end'] = self._io.pos()
                    self._debug['sp_averaging']['start'] = self._io.pos()
                    self.sp_averaging = self._io.read_u2le()
                    self._debug['sp_averaging']['end'] = self._io.pos()
                    self._debug['sp_repeat']['start'] = self._io.pos()
                    self.sp_repeat = self._io.read_u1()
                    self._debug['sp_repeat']['end'] = self._io.pos()
                    self._debug['sp_back']['start'] = self._io.pos()
                    self.sp_back = self._io.read_u1()
                    self._debug['sp_back']['end'] = self._io.pos()
                    self._debug['sp_4nx']['start'] = self._io.pos()
                    self.sp_4nx = self._io.read_s2le()
                    self._debug['sp_4nx']['end'] = self._io.pos()
                    self._debug['sp_osc']['start'] = self._io.pos()
                    self.sp_osc = self._io.read_u1()
                    self._debug['sp_osc']['end'] = self._io.pos()
                    self._debug['sp_n4']['start'] = self._io.pos()
                    self.sp_n4 = self._io.read_u1()
                    self._debug['sp_n4']['end'] = self._io.pos()
                    self._debug['sp_4x0']['start'] = self._io.pos()
                    self.sp_4x0 = self._io.read_f4le()
                    self._debug['sp_4x0']['end'] = self._io.pos()
                    self._debug['sp_4xr']['start'] = self._io.pos()
                    self.sp_4xr = self._io.read_f4le()
                    self._debug['sp_4xr']['end'] = self._io.pos()
                    self._debug['sp_4u']['start'] = self._io.pos()
                    self.sp_4u = self._io.read_s2le()
                    self._debug['sp_4u']['end'] = self._io.pos()
                    self._debug['sp_4i']['start'] = self._io.pos()
                    self.sp_4i = self._io.read_s2le()
                    self._debug['sp_4i']['end'] = self._io.pos()
                    self._debug['sp_nx']['start'] = self._io.pos()
                    self.sp_nx = self._io.read_s2le()
                    self._debug['sp_nx']['end'] = self._io.pos()



        class DateTime(KaitaiStruct):
            SEQ_FIELDS = ["date", "time"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['date']['start'] = self._io.pos()
                self.date = self._root.Frame.DateTime.Date(self._io, self, self._root)
                self.date._read()
                self._debug['date']['end'] = self._io.pos()
                self._debug['time']['start'] = self._io.pos()
                self.time = self._root.Frame.DateTime.Time(self._io, self, self._root)
                self.time._read()
                self._debug['time']['end'] = self._io.pos()

            class Date(KaitaiStruct):
                SEQ_FIELDS = ["year", "month", "day"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['year']['start'] = self._io.pos()
                    self.year = self._io.read_u2le()
                    self._debug['year']['end'] = self._io.pos()
                    self._debug['month']['start'] = self._io.pos()
                    self.month = self._io.read_u2le()
                    self._debug['month']['end'] = self._io.pos()
                    self._debug['day']['start'] = self._io.pos()
                    self.day = self._io.read_u2le()
                    self._debug['day']['end'] = self._io.pos()


            class Time(KaitaiStruct):
                SEQ_FIELDS = ["hour", "min", "sec"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['hour']['start'] = self._io.pos()
                    self.hour = self._io.read_u2le()
                    self._debug['hour']['end'] = self._io.pos()
                    self._debug['min']['start'] = self._io.pos()
                    self.min = self._io.read_u2le()
                    self._debug['min']['end'] = self._io.pos()
                    self._debug['sec']['start'] = self._io.pos()
                    self.sec = self._io.read_u2le()
                    self._debug['sec']['end'] = self._io.pos()



        class AxisScale(KaitaiStruct):
            SEQ_FIELDS = ["offset", "step", "unit"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_f4le()
                self._debug['offset']['end'] = self._io.pos()
                self._debug['step']['start'] = self._io.pos()
                self.step = self._io.read_f4le()
                self._debug['step']['end'] = self._io.pos()
                self._debug['unit']['start'] = self._io.pos()
                self.unit = KaitaiStream.resolve_enum(self._root.Unit, self._io.read_s2le())
                self._debug['unit']['end'] = self._io.pos()


        class FdScanned(KaitaiStruct):

            class Mode(Enum):
                stm = 0
                afm = 1
                unknown2 = 2
                unknown3 = 3
                unknown4 = 4

            class InputSignal(Enum):
                extension_slot = 0
                bias_v = 1
                ground = 2

            class LiftMode(Enum):
                step = 0
                fine = 1
                slope = 2
            SEQ_FIELDS = ["vars", "orig_format", "tune", "feedback_gain", "dac_scale", "overscan", "fm_mode", "fm_xres", "fm_yres", "dots", "image", "title", "xml"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['vars']['start'] = self._io.pos()
                self._raw_vars = self._io.read_bytes(self._parent.var_size)
                io = KaitaiStream(BytesIO(self._raw_vars))
                self.vars = self._root.Frame.FdScanned.Vars(io, self, self._root)
                self.vars._read()
                self._debug['vars']['end'] = self._io.pos()
                if False:
                    self._debug['orig_format']['start'] = self._io.pos()
                    self.orig_format = self._io.read_u4le()
                    self._debug['orig_format']['end'] = self._io.pos()

                if False:
                    self._debug['tune']['start'] = self._io.pos()
                    self.tune = KaitaiStream.resolve_enum(self._root.Frame.FdScanned.LiftMode, self._io.read_u4le())
                    self._debug['tune']['end'] = self._io.pos()

                if False:
                    self._debug['feedback_gain']['start'] = self._io.pos()
                    self.feedback_gain = self._io.read_f8le()
                    self._debug['feedback_gain']['end'] = self._io.pos()

                if False:
                    self._debug['dac_scale']['start'] = self._io.pos()
                    self.dac_scale = self._io.read_s4le()
                    self._debug['dac_scale']['end'] = self._io.pos()

                if False:
                    self._debug['overscan']['start'] = self._io.pos()
                    self.overscan = self._io.read_s4le()
                    self._debug['overscan']['end'] = self._io.pos()

                self._debug['fm_mode']['start'] = self._io.pos()
                self.fm_mode = self._io.read_u2le()
                self._debug['fm_mode']['end'] = self._io.pos()
                self._debug['fm_xres']['start'] = self._io.pos()
                self.fm_xres = self._io.read_u2le()
                self._debug['fm_xres']['end'] = self._io.pos()
                self._debug['fm_yres']['start'] = self._io.pos()
                self.fm_yres = self._io.read_u2le()
                self._debug['fm_yres']['end'] = self._io.pos()
                self._debug['dots']['start'] = self._io.pos()
                self.dots = self._root.Frame.Dots(self._io, self, self._root)
                self.dots._read()
                self._debug['dots']['end'] = self._io.pos()
                self._debug['image']['start'] = self._io.pos()
                self.image = [None] * ((self.fm_xres * self.fm_yres))
                for i in range((self.fm_xres * self.fm_yres)):
                    if not 'arr' in self._debug['image']:
                        self._debug['image']['arr'] = []
                    self._debug['image']['arr'].append({'start': self._io.pos()})
                    self.image[i] = self._io.read_s2le()
                    self._debug['image']['arr'][i]['end'] = self._io.pos()

                self._debug['image']['end'] = self._io.pos()
                self._debug['title']['start'] = self._io.pos()
                self.title = self._root.Title(self._io, self, self._root)
                self.title._read()
                self._debug['title']['end'] = self._io.pos()
                self._debug['xml']['start'] = self._io.pos()
                self.xml = self._root.Xml(self._io, self, self._root)
                self.xml._read()
                self._debug['xml']['end'] = self._io.pos()

            class Vars(KaitaiStruct):
                SEQ_FIELDS = ["x_scale", "y_scale", "z_scale", "channel_index", "mode", "xres", "yres", "ndacq", "step_length", "adt", "adc_gain_amp_log10", "adc_index", "input_signal_or_version", "substr_plane_order_or_pass_num", "scan_dir", "power_of_2", "velocity", "setpoint", "bias_voltage", "draw", "reserved", "xoff", "yoff", "nl_corr"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['x_scale']['start'] = self._io.pos()
                    self.x_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.x_scale._read()
                    self._debug['x_scale']['end'] = self._io.pos()
                    self._debug['y_scale']['start'] = self._io.pos()
                    self.y_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.y_scale._read()
                    self._debug['y_scale']['end'] = self._io.pos()
                    self._debug['z_scale']['start'] = self._io.pos()
                    self.z_scale = self._root.Frame.AxisScale(self._io, self, self._root)
                    self.z_scale._read()
                    self._debug['z_scale']['end'] = self._io.pos()
                    self._debug['channel_index']['start'] = self._io.pos()
                    self.channel_index = KaitaiStream.resolve_enum(self._root.AdcMode, self._io.read_u1())
                    self._debug['channel_index']['end'] = self._io.pos()
                    self._debug['mode']['start'] = self._io.pos()
                    self.mode = KaitaiStream.resolve_enum(self._root.Frame.FdScanned.Mode, self._io.read_u1())
                    self._debug['mode']['end'] = self._io.pos()
                    self._debug['xres']['start'] = self._io.pos()
                    self.xres = self._io.read_u2le()
                    self._debug['xres']['end'] = self._io.pos()
                    self._debug['yres']['start'] = self._io.pos()
                    self.yres = self._io.read_u2le()
                    self._debug['yres']['end'] = self._io.pos()
                    self._debug['ndacq']['start'] = self._io.pos()
                    self.ndacq = self._io.read_u2le()
                    self._debug['ndacq']['end'] = self._io.pos()
                    self._debug['step_length']['start'] = self._io.pos()
                    self.step_length = self._io.read_f4le()
                    self._debug['step_length']['end'] = self._io.pos()
                    self._debug['adt']['start'] = self._io.pos()
                    self.adt = self._io.read_u2le()
                    self._debug['adt']['end'] = self._io.pos()
                    self._debug['adc_gain_amp_log10']['start'] = self._io.pos()
                    self.adc_gain_amp_log10 = self._io.read_u1()
                    self._debug['adc_gain_amp_log10']['end'] = self._io.pos()
                    self._debug['adc_index']['start'] = self._io.pos()
                    self.adc_index = self._io.read_u1()
                    self._debug['adc_index']['end'] = self._io.pos()
                    self._debug['input_signal_or_version']['start'] = self._io.pos()
                    self.input_signal_or_version = self._io.read_u1()
                    self._debug['input_signal_or_version']['end'] = self._io.pos()
                    self._debug['substr_plane_order_or_pass_num']['start'] = self._io.pos()
                    self.substr_plane_order_or_pass_num = self._io.read_u1()
                    self._debug['substr_plane_order_or_pass_num']['end'] = self._io.pos()
                    self._debug['scan_dir']['start'] = self._io.pos()
                    self.scan_dir = self._root.Frame.FdScanned.ScanDir(self._io, self, self._root)
                    self.scan_dir._read()
                    self._debug['scan_dir']['end'] = self._io.pos()
                    self._debug['power_of_2']['start'] = self._io.pos()
                    self.power_of_2 = self._io.read_u1()
                    self._debug['power_of_2']['end'] = self._io.pos()
                    self._debug['velocity']['start'] = self._io.pos()
                    self.velocity = self._io.read_f4le()
                    self._debug['velocity']['end'] = self._io.pos()
                    self._debug['setpoint']['start'] = self._io.pos()
                    self.setpoint = self._io.read_f4le()
                    self._debug['setpoint']['end'] = self._io.pos()
                    self._debug['bias_voltage']['start'] = self._io.pos()
                    self.bias_voltage = self._io.read_f4le()
                    self._debug['bias_voltage']['end'] = self._io.pos()
                    self._debug['draw']['start'] = self._io.pos()
                    self.draw = self._io.read_u1()
                    self._debug['draw']['end'] = self._io.pos()
                    self._debug['reserved']['start'] = self._io.pos()
                    self.reserved = self._io.read_u1()
                    self._debug['reserved']['end'] = self._io.pos()
                    self._debug['xoff']['start'] = self._io.pos()
                    self.xoff = self._io.read_s4le()
                    self._debug['xoff']['end'] = self._io.pos()
                    self._debug['yoff']['start'] = self._io.pos()
                    self.yoff = self._io.read_s4le()
                    self._debug['yoff']['end'] = self._io.pos()
                    self._debug['nl_corr']['start'] = self._io.pos()
                    self.nl_corr = self._io.read_u1()
                    self._debug['nl_corr']['end'] = self._io.pos()


            class Dot(KaitaiStruct):
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


            class ScanDir(KaitaiStruct):
                SEQ_FIELDS = ["unkn", "double_pass", "bottom", "left", "horizontal"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['unkn']['start'] = self._io.pos()
                    self.unkn = self._io.read_bits_int(4)
                    self._debug['unkn']['end'] = self._io.pos()
                    self._debug['double_pass']['start'] = self._io.pos()
                    self.double_pass = self._io.read_bits_int(1) != 0
                    self._debug['double_pass']['end'] = self._io.pos()
                    self._debug['bottom']['start'] = self._io.pos()
                    self.bottom = self._io.read_bits_int(1) != 0
                    self._debug['bottom']['end'] = self._io.pos()
                    self._debug['left']['start'] = self._io.pos()
                    self.left = self._io.read_bits_int(1) != 0
                    self._debug['left']['end'] = self._io.pos()
                    self._debug['horizontal']['start'] = self._io.pos()
                    self.horizontal = self._io.read_bits_int(1) != 0
                    self._debug['horizontal']['end'] = self._io.pos()




    class Version(KaitaiStruct):
        SEQ_FIELDS = ["minor", "major"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['minor']['start'] = self._io.pos()
            self.minor = self._io.read_u1()
            self._debug['minor']['end'] = self._io.pos()
            self._debug['major']['start'] = self._io.pos()
            self.major = self._io.read_u1()
            self._debug['major']['end'] = self._io.pos()


    class Xml(KaitaiStruct):
        SEQ_FIELDS = ["xml_len", "xml"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['xml_len']['start'] = self._io.pos()
            self.xml_len = self._io.read_u4le()
            self._debug['xml_len']['end'] = self._io.pos()
            self._debug['xml']['start'] = self._io.pos()
            self.xml = (self._io.read_bytes(self.xml_len)).decode(u"UTF-16LE")
            self._debug['xml']['end'] = self._io.pos()


    class Title(KaitaiStruct):
        SEQ_FIELDS = ["title_len", "title"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['title_len']['start'] = self._io.pos()
            self.title_len = self._io.read_u4le()
            self._debug['title_len']['end'] = self._io.pos()
            self._debug['title']['start'] = self._io.pos()
            self.title = (self._io.read_bytes(self.title_len)).decode(u"cp1251")
            self._debug['title']['end'] = self._io.pos()



