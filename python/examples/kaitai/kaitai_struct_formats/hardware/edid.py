from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Edid(KaitaiStruct):
    SEQ_FIELDS = ["magic", "mfg_bytes", "product_code", "serial", "mfg_week", "mfg_year_mod", "edid_version_major", "edid_version_minor", "input_flags", "screen_size_h", "screen_size_v", "gamma_mod", "features_flags", "chromacity", "est_timings", "std_timings"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['mfg_bytes']['start'] = self._io.pos()
        self.mfg_bytes = self._io.read_u2le()
        self._debug['mfg_bytes']['end'] = self._io.pos()
        self._debug['product_code']['start'] = self._io.pos()
        self.product_code = self._io.read_u2le()
        self._debug['product_code']['end'] = self._io.pos()
        self._debug['serial']['start'] = self._io.pos()
        self.serial = self._io.read_u4le()
        self._debug['serial']['end'] = self._io.pos()
        self._debug['mfg_week']['start'] = self._io.pos()
        self.mfg_week = self._io.read_u1()
        self._debug['mfg_week']['end'] = self._io.pos()
        self._debug['mfg_year_mod']['start'] = self._io.pos()
        self.mfg_year_mod = self._io.read_u1()
        self._debug['mfg_year_mod']['end'] = self._io.pos()
        self._debug['edid_version_major']['start'] = self._io.pos()
        self.edid_version_major = self._io.read_u1()
        self._debug['edid_version_major']['end'] = self._io.pos()
        self._debug['edid_version_minor']['start'] = self._io.pos()
        self.edid_version_minor = self._io.read_u1()
        self._debug['edid_version_minor']['end'] = self._io.pos()
        self._debug['input_flags']['start'] = self._io.pos()
        self.input_flags = self._io.read_u1()
        self._debug['input_flags']['end'] = self._io.pos()
        self._debug['screen_size_h']['start'] = self._io.pos()
        self.screen_size_h = self._io.read_u1()
        self._debug['screen_size_h']['end'] = self._io.pos()
        self._debug['screen_size_v']['start'] = self._io.pos()
        self.screen_size_v = self._io.read_u1()
        self._debug['screen_size_v']['end'] = self._io.pos()
        self._debug['gamma_mod']['start'] = self._io.pos()
        self.gamma_mod = self._io.read_u1()
        self._debug['gamma_mod']['end'] = self._io.pos()
        self._debug['features_flags']['start'] = self._io.pos()
        self.features_flags = self._io.read_u1()
        self._debug['features_flags']['end'] = self._io.pos()
        self._debug['chromacity']['start'] = self._io.pos()
        self.chromacity = self._root.ChromacityInfo(self._io, self, self._root)
        self.chromacity._read()
        self._debug['chromacity']['end'] = self._io.pos()
        self._debug['est_timings']['start'] = self._io.pos()
        self.est_timings = self._root.EstTimingsInfo(self._io, self, self._root)
        self.est_timings._read()
        self._debug['est_timings']['end'] = self._io.pos()
        self._debug['std_timings']['start'] = self._io.pos()
        self.std_timings = [None] * (8)
        for i in range(8):
            if not 'arr' in self._debug['std_timings']:
                self._debug['std_timings']['arr'] = []
            self._debug['std_timings']['arr'].append({'start': self._io.pos()})
            _t_std_timings = self._root.StdTiming(self._io, self, self._root)
            _t_std_timings._read()
            self.std_timings[i] = _t_std_timings
            self._debug['std_timings']['arr'][i]['end'] = self._io.pos()

        self._debug['std_timings']['end'] = self._io.pos()

    class ChromacityInfo(KaitaiStruct):
        """Chromaticity information: colorimetry and white point
        coordinates. All coordinates are stored as fixed precision
        10-bit numbers, bits are shuffled for compactness.
        """
        SEQ_FIELDS = ["red_x_1_0", "red_y_1_0", "green_x_1_0", "green_y_1_0", "blue_x_1_0", "blue_y_1_0", "white_x_1_0", "white_y_1_0", "red_x_9_2", "red_y_9_2", "green_x_9_2", "green_y_9_2", "blue_x_9_2", "blue_y_9_2", "white_x_9_2", "white_y_9_2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['red_x_1_0']['start'] = self._io.pos()
            self.red_x_1_0 = self._io.read_bits_int(2)
            self._debug['red_x_1_0']['end'] = self._io.pos()
            self._debug['red_y_1_0']['start'] = self._io.pos()
            self.red_y_1_0 = self._io.read_bits_int(2)
            self._debug['red_y_1_0']['end'] = self._io.pos()
            self._debug['green_x_1_0']['start'] = self._io.pos()
            self.green_x_1_0 = self._io.read_bits_int(2)
            self._debug['green_x_1_0']['end'] = self._io.pos()
            self._debug['green_y_1_0']['start'] = self._io.pos()
            self.green_y_1_0 = self._io.read_bits_int(2)
            self._debug['green_y_1_0']['end'] = self._io.pos()
            self._debug['blue_x_1_0']['start'] = self._io.pos()
            self.blue_x_1_0 = self._io.read_bits_int(2)
            self._debug['blue_x_1_0']['end'] = self._io.pos()
            self._debug['blue_y_1_0']['start'] = self._io.pos()
            self.blue_y_1_0 = self._io.read_bits_int(2)
            self._debug['blue_y_1_0']['end'] = self._io.pos()
            self._debug['white_x_1_0']['start'] = self._io.pos()
            self.white_x_1_0 = self._io.read_bits_int(2)
            self._debug['white_x_1_0']['end'] = self._io.pos()
            self._debug['white_y_1_0']['start'] = self._io.pos()
            self.white_y_1_0 = self._io.read_bits_int(2)
            self._debug['white_y_1_0']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['red_x_9_2']['start'] = self._io.pos()
            self.red_x_9_2 = self._io.read_u1()
            self._debug['red_x_9_2']['end'] = self._io.pos()
            self._debug['red_y_9_2']['start'] = self._io.pos()
            self.red_y_9_2 = self._io.read_u1()
            self._debug['red_y_9_2']['end'] = self._io.pos()
            self._debug['green_x_9_2']['start'] = self._io.pos()
            self.green_x_9_2 = self._io.read_u1()
            self._debug['green_x_9_2']['end'] = self._io.pos()
            self._debug['green_y_9_2']['start'] = self._io.pos()
            self.green_y_9_2 = self._io.read_u1()
            self._debug['green_y_9_2']['end'] = self._io.pos()
            self._debug['blue_x_9_2']['start'] = self._io.pos()
            self.blue_x_9_2 = self._io.read_u1()
            self._debug['blue_x_9_2']['end'] = self._io.pos()
            self._debug['blue_y_9_2']['start'] = self._io.pos()
            self.blue_y_9_2 = self._io.read_u1()
            self._debug['blue_y_9_2']['end'] = self._io.pos()
            self._debug['white_x_9_2']['start'] = self._io.pos()
            self.white_x_9_2 = self._io.read_u1()
            self._debug['white_x_9_2']['end'] = self._io.pos()
            self._debug['white_y_9_2']['start'] = self._io.pos()
            self.white_y_9_2 = self._io.read_u1()
            self._debug['white_y_9_2']['end'] = self._io.pos()

        @property
        def green_x_int(self):
            if hasattr(self, '_m_green_x_int'):
                return self._m_green_x_int if hasattr(self, '_m_green_x_int') else None

            self._m_green_x_int = ((self.green_x_9_2 << 2) | self.green_x_1_0)
            return self._m_green_x_int if hasattr(self, '_m_green_x_int') else None

        @property
        def red_y(self):
            """Red Y coordinate."""
            if hasattr(self, '_m_red_y'):
                return self._m_red_y if hasattr(self, '_m_red_y') else None

            self._m_red_y = (self.red_y_int / 1024.0)
            return self._m_red_y if hasattr(self, '_m_red_y') else None

        @property
        def green_y_int(self):
            if hasattr(self, '_m_green_y_int'):
                return self._m_green_y_int if hasattr(self, '_m_green_y_int') else None

            self._m_green_y_int = ((self.green_y_9_2 << 2) | self.green_y_1_0)
            return self._m_green_y_int if hasattr(self, '_m_green_y_int') else None

        @property
        def white_y(self):
            """White Y coordinate."""
            if hasattr(self, '_m_white_y'):
                return self._m_white_y if hasattr(self, '_m_white_y') else None

            self._m_white_y = (self.white_y_int / 1024.0)
            return self._m_white_y if hasattr(self, '_m_white_y') else None

        @property
        def red_x(self):
            """Red X coordinate."""
            if hasattr(self, '_m_red_x'):
                return self._m_red_x if hasattr(self, '_m_red_x') else None

            self._m_red_x = (self.red_x_int / 1024.0)
            return self._m_red_x if hasattr(self, '_m_red_x') else None

        @property
        def white_x(self):
            """White X coordinate."""
            if hasattr(self, '_m_white_x'):
                return self._m_white_x if hasattr(self, '_m_white_x') else None

            self._m_white_x = (self.white_x_int / 1024.0)
            return self._m_white_x if hasattr(self, '_m_white_x') else None

        @property
        def blue_x(self):
            """Blue X coordinate."""
            if hasattr(self, '_m_blue_x'):
                return self._m_blue_x if hasattr(self, '_m_blue_x') else None

            self._m_blue_x = (self.blue_x_int / 1024.0)
            return self._m_blue_x if hasattr(self, '_m_blue_x') else None

        @property
        def white_x_int(self):
            if hasattr(self, '_m_white_x_int'):
                return self._m_white_x_int if hasattr(self, '_m_white_x_int') else None

            self._m_white_x_int = ((self.white_x_9_2 << 2) | self.white_x_1_0)
            return self._m_white_x_int if hasattr(self, '_m_white_x_int') else None

        @property
        def white_y_int(self):
            if hasattr(self, '_m_white_y_int'):
                return self._m_white_y_int if hasattr(self, '_m_white_y_int') else None

            self._m_white_y_int = ((self.white_y_9_2 << 2) | self.white_y_1_0)
            return self._m_white_y_int if hasattr(self, '_m_white_y_int') else None

        @property
        def green_x(self):
            """Green X coordinate."""
            if hasattr(self, '_m_green_x'):
                return self._m_green_x if hasattr(self, '_m_green_x') else None

            self._m_green_x = (self.green_x_int / 1024.0)
            return self._m_green_x if hasattr(self, '_m_green_x') else None

        @property
        def red_x_int(self):
            if hasattr(self, '_m_red_x_int'):
                return self._m_red_x_int if hasattr(self, '_m_red_x_int') else None

            self._m_red_x_int = ((self.red_x_9_2 << 2) | self.red_x_1_0)
            return self._m_red_x_int if hasattr(self, '_m_red_x_int') else None

        @property
        def red_y_int(self):
            if hasattr(self, '_m_red_y_int'):
                return self._m_red_y_int if hasattr(self, '_m_red_y_int') else None

            self._m_red_y_int = ((self.red_y_9_2 << 2) | self.red_y_1_0)
            return self._m_red_y_int if hasattr(self, '_m_red_y_int') else None

        @property
        def blue_x_int(self):
            if hasattr(self, '_m_blue_x_int'):
                return self._m_blue_x_int if hasattr(self, '_m_blue_x_int') else None

            self._m_blue_x_int = ((self.blue_x_9_2 << 2) | self.blue_x_1_0)
            return self._m_blue_x_int if hasattr(self, '_m_blue_x_int') else None

        @property
        def blue_y(self):
            """Blue Y coordinate."""
            if hasattr(self, '_m_blue_y'):
                return self._m_blue_y if hasattr(self, '_m_blue_y') else None

            self._m_blue_y = (self.blue_y_int / 1024.0)
            return self._m_blue_y if hasattr(self, '_m_blue_y') else None

        @property
        def green_y(self):
            """Green Y coordinate."""
            if hasattr(self, '_m_green_y'):
                return self._m_green_y if hasattr(self, '_m_green_y') else None

            self._m_green_y = (self.green_y_int / 1024.0)
            return self._m_green_y if hasattr(self, '_m_green_y') else None

        @property
        def blue_y_int(self):
            if hasattr(self, '_m_blue_y_int'):
                return self._m_blue_y_int if hasattr(self, '_m_blue_y_int') else None

            self._m_blue_y_int = ((self.blue_y_9_2 << 2) | self.blue_y_1_0)
            return self._m_blue_y_int if hasattr(self, '_m_blue_y_int') else None


    class EstTimingsInfo(KaitaiStruct):
        SEQ_FIELDS = ["can_720_400_70", "can_720_400_88", "can_640_480_60", "can_640_480_67", "can_640_480_72", "can_640_480_75", "can_800_600_56", "can_800_600_60", "can_800_600_72", "can_800_600_75", "can_832_624_75", "can_1024_768_87_i", "can_1024_768_60", "can_1024_768_70", "can_1024_768_75", "can_1280_1024_75", "can_1152_870_75", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['can_720_400_70']['start'] = self._io.pos()
            self.can_720_400_70 = self._io.read_bits_int(1) != 0
            self._debug['can_720_400_70']['end'] = self._io.pos()
            self._debug['can_720_400_88']['start'] = self._io.pos()
            self.can_720_400_88 = self._io.read_bits_int(1) != 0
            self._debug['can_720_400_88']['end'] = self._io.pos()
            self._debug['can_640_480_60']['start'] = self._io.pos()
            self.can_640_480_60 = self._io.read_bits_int(1) != 0
            self._debug['can_640_480_60']['end'] = self._io.pos()
            self._debug['can_640_480_67']['start'] = self._io.pos()
            self.can_640_480_67 = self._io.read_bits_int(1) != 0
            self._debug['can_640_480_67']['end'] = self._io.pos()
            self._debug['can_640_480_72']['start'] = self._io.pos()
            self.can_640_480_72 = self._io.read_bits_int(1) != 0
            self._debug['can_640_480_72']['end'] = self._io.pos()
            self._debug['can_640_480_75']['start'] = self._io.pos()
            self.can_640_480_75 = self._io.read_bits_int(1) != 0
            self._debug['can_640_480_75']['end'] = self._io.pos()
            self._debug['can_800_600_56']['start'] = self._io.pos()
            self.can_800_600_56 = self._io.read_bits_int(1) != 0
            self._debug['can_800_600_56']['end'] = self._io.pos()
            self._debug['can_800_600_60']['start'] = self._io.pos()
            self.can_800_600_60 = self._io.read_bits_int(1) != 0
            self._debug['can_800_600_60']['end'] = self._io.pos()
            self._debug['can_800_600_72']['start'] = self._io.pos()
            self.can_800_600_72 = self._io.read_bits_int(1) != 0
            self._debug['can_800_600_72']['end'] = self._io.pos()
            self._debug['can_800_600_75']['start'] = self._io.pos()
            self.can_800_600_75 = self._io.read_bits_int(1) != 0
            self._debug['can_800_600_75']['end'] = self._io.pos()
            self._debug['can_832_624_75']['start'] = self._io.pos()
            self.can_832_624_75 = self._io.read_bits_int(1) != 0
            self._debug['can_832_624_75']['end'] = self._io.pos()
            self._debug['can_1024_768_87_i']['start'] = self._io.pos()
            self.can_1024_768_87_i = self._io.read_bits_int(1) != 0
            self._debug['can_1024_768_87_i']['end'] = self._io.pos()
            self._debug['can_1024_768_60']['start'] = self._io.pos()
            self.can_1024_768_60 = self._io.read_bits_int(1) != 0
            self._debug['can_1024_768_60']['end'] = self._io.pos()
            self._debug['can_1024_768_70']['start'] = self._io.pos()
            self.can_1024_768_70 = self._io.read_bits_int(1) != 0
            self._debug['can_1024_768_70']['end'] = self._io.pos()
            self._debug['can_1024_768_75']['start'] = self._io.pos()
            self.can_1024_768_75 = self._io.read_bits_int(1) != 0
            self._debug['can_1024_768_75']['end'] = self._io.pos()
            self._debug['can_1280_1024_75']['start'] = self._io.pos()
            self.can_1280_1024_75 = self._io.read_bits_int(1) != 0
            self._debug['can_1280_1024_75']['end'] = self._io.pos()
            self._debug['can_1152_870_75']['start'] = self._io.pos()
            self.can_1152_870_75 = self._io.read_bits_int(1) != 0
            self._debug['can_1152_870_75']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bits_int(7)
            self._debug['reserved']['end'] = self._io.pos()


    class StdTiming(KaitaiStruct):

        class AspectRatios(Enum):
            ratio_16_10 = 0
            ratio_4_3 = 1
            ratio_5_4 = 2
            ratio_16_9 = 3
        SEQ_FIELDS = ["horiz_active_pixels_mod", "aspect_ratio", "refresh_rate_mod"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['horiz_active_pixels_mod']['start'] = self._io.pos()
            self.horiz_active_pixels_mod = self._io.read_u1()
            self._debug['horiz_active_pixels_mod']['end'] = self._io.pos()
            self._debug['aspect_ratio']['start'] = self._io.pos()
            self.aspect_ratio = KaitaiStream.resolve_enum(self._root.StdTiming.AspectRatios, self._io.read_bits_int(2))
            self._debug['aspect_ratio']['end'] = self._io.pos()
            self._debug['refresh_rate_mod']['start'] = self._io.pos()
            self.refresh_rate_mod = self._io.read_bits_int(5)
            self._debug['refresh_rate_mod']['end'] = self._io.pos()

        @property
        def horiz_active_pixels(self):
            """Range of horizontal active pixels."""
            if hasattr(self, '_m_horiz_active_pixels'):
                return self._m_horiz_active_pixels if hasattr(self, '_m_horiz_active_pixels') else None

            self._m_horiz_active_pixels = ((self.horiz_active_pixels_mod + 31) * 8)
            return self._m_horiz_active_pixels if hasattr(self, '_m_horiz_active_pixels') else None

        @property
        def refresh_rate(self):
            """Vertical refresh rate, Hz."""
            if hasattr(self, '_m_refresh_rate'):
                return self._m_refresh_rate if hasattr(self, '_m_refresh_rate') else None

            self._m_refresh_rate = (self.refresh_rate_mod + 60)
            return self._m_refresh_rate if hasattr(self, '_m_refresh_rate') else None


    @property
    def mfg_year(self):
        if hasattr(self, '_m_mfg_year'):
            return self._m_mfg_year if hasattr(self, '_m_mfg_year') else None

        self._m_mfg_year = (self.mfg_year_mod + 1990)
        return self._m_mfg_year if hasattr(self, '_m_mfg_year') else None

    @property
    def mfg_id_ch1(self):
        if hasattr(self, '_m_mfg_id_ch1'):
            return self._m_mfg_id_ch1 if hasattr(self, '_m_mfg_id_ch1') else None

        self._m_mfg_id_ch1 = ((self.mfg_bytes & 31744) >> 10)
        return self._m_mfg_id_ch1 if hasattr(self, '_m_mfg_id_ch1') else None

    @property
    def mfg_id_ch3(self):
        if hasattr(self, '_m_mfg_id_ch3'):
            return self._m_mfg_id_ch3 if hasattr(self, '_m_mfg_id_ch3') else None

        self._m_mfg_id_ch3 = (self.mfg_bytes & 31)
        return self._m_mfg_id_ch3 if hasattr(self, '_m_mfg_id_ch3') else None

    @property
    def gamma(self):
        if hasattr(self, '_m_gamma'):
            return self._m_gamma if hasattr(self, '_m_gamma') else None

        if self.gamma_mod != 255:
            self._m_gamma = ((self.gamma_mod + 100) / 100.0)

        return self._m_gamma if hasattr(self, '_m_gamma') else None

    @property
    def mfg_id_ch2(self):
        if hasattr(self, '_m_mfg_id_ch2'):
            return self._m_mfg_id_ch2 if hasattr(self, '_m_mfg_id_ch2') else None

        self._m_mfg_id_ch2 = ((self.mfg_bytes & 992) >> 5)
        return self._m_mfg_id_ch2 if hasattr(self, '_m_mfg_id_ch2') else None


