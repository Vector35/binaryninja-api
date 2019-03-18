from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Tga(KaitaiStruct):
    """TGA (AKA Truevision TGA, AKA TARGA), is a raster image file format created by Truevision. It supports up to 32 bits per pixel (three 8-bit RGB channels + 8-bit alpha channel), color mapping and optional lossless RLE compression.
    
    .. seealso::
       Source - http://www.dca.fee.unicamp.br/~martino/disciplinas/ea978/tgaffs.pdf
    """

    class ColorMapEnum(Enum):
        no_color_map = 0
        has_color_map = 1

    class ImageTypeEnum(Enum):
        no_image_data = 0
        uncomp_color_mapped = 1
        uncomp_true_color = 2
        uncomp_bw = 3
        rle_color_mapped = 9
        rle_true_color = 10
        rle_bw = 11
    SEQ_FIELDS = ["image_id_len", "color_map_type", "image_type", "color_map_ofs", "num_color_map", "color_map_depth", "x_offset", "y_offset", "width", "height", "image_depth", "img_descriptor", "image_id", "color_map"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['image_id_len']['start'] = self._io.pos()
        self.image_id_len = self._io.read_u1()
        self._debug['image_id_len']['end'] = self._io.pos()
        self._debug['color_map_type']['start'] = self._io.pos()
        self.color_map_type = KaitaiStream.resolve_enum(self._root.ColorMapEnum, self._io.read_u1())
        self._debug['color_map_type']['end'] = self._io.pos()
        self._debug['image_type']['start'] = self._io.pos()
        self.image_type = KaitaiStream.resolve_enum(self._root.ImageTypeEnum, self._io.read_u1())
        self._debug['image_type']['end'] = self._io.pos()
        self._debug['color_map_ofs']['start'] = self._io.pos()
        self.color_map_ofs = self._io.read_u2le()
        self._debug['color_map_ofs']['end'] = self._io.pos()
        self._debug['num_color_map']['start'] = self._io.pos()
        self.num_color_map = self._io.read_u2le()
        self._debug['num_color_map']['end'] = self._io.pos()
        self._debug['color_map_depth']['start'] = self._io.pos()
        self.color_map_depth = self._io.read_u1()
        self._debug['color_map_depth']['end'] = self._io.pos()
        self._debug['x_offset']['start'] = self._io.pos()
        self.x_offset = self._io.read_u2le()
        self._debug['x_offset']['end'] = self._io.pos()
        self._debug['y_offset']['start'] = self._io.pos()
        self.y_offset = self._io.read_u2le()
        self._debug['y_offset']['end'] = self._io.pos()
        self._debug['width']['start'] = self._io.pos()
        self.width = self._io.read_u2le()
        self._debug['width']['end'] = self._io.pos()
        self._debug['height']['start'] = self._io.pos()
        self.height = self._io.read_u2le()
        self._debug['height']['end'] = self._io.pos()
        self._debug['image_depth']['start'] = self._io.pos()
        self.image_depth = self._io.read_u1()
        self._debug['image_depth']['end'] = self._io.pos()
        self._debug['img_descriptor']['start'] = self._io.pos()
        self.img_descriptor = self._io.read_u1()
        self._debug['img_descriptor']['end'] = self._io.pos()
        self._debug['image_id']['start'] = self._io.pos()
        self.image_id = self._io.read_bytes(self.image_id_len)
        self._debug['image_id']['end'] = self._io.pos()
        if self.color_map_type == self._root.ColorMapEnum.has_color_map:
            self._debug['color_map']['start'] = self._io.pos()
            self.color_map = [None] * (self.num_color_map)
            for i in range(self.num_color_map):
                if not 'arr' in self._debug['color_map']:
                    self._debug['color_map']['arr'] = []
                self._debug['color_map']['arr'].append({'start': self._io.pos()})
                self.color_map[i] = self._io.read_bytes((self.color_map_depth + 7) // 8)
                self._debug['color_map']['arr'][i]['end'] = self._io.pos()

            self._debug['color_map']['end'] = self._io.pos()


    class TgaFooter(KaitaiStruct):
        SEQ_FIELDS = ["ext_area_ofs", "dev_dir_ofs", "version_magic"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ext_area_ofs']['start'] = self._io.pos()
            self.ext_area_ofs = self._io.read_u4le()
            self._debug['ext_area_ofs']['end'] = self._io.pos()
            self._debug['dev_dir_ofs']['start'] = self._io.pos()
            self.dev_dir_ofs = self._io.read_u4le()
            self._debug['dev_dir_ofs']['end'] = self._io.pos()
            self._debug['version_magic']['start'] = self._io.pos()
            self.version_magic = self._io.read_bytes(18)
            self._debug['version_magic']['end'] = self._io.pos()

        @property
        def is_valid(self):
            if hasattr(self, '_m_is_valid'):
                return self._m_is_valid if hasattr(self, '_m_is_valid') else None

            self._m_is_valid = self.version_magic == b"\x54\x52\x55\x45\x56\x49\x53\x49\x4F\x4E\x2D\x58\x46\x49\x4C\x45\x2E\x00"
            return self._m_is_valid if hasattr(self, '_m_is_valid') else None

        @property
        def ext_area(self):
            if hasattr(self, '_m_ext_area'):
                return self._m_ext_area if hasattr(self, '_m_ext_area') else None

            if self.is_valid:
                _pos = self._io.pos()
                self._io.seek(self.ext_area_ofs)
                self._debug['_m_ext_area']['start'] = self._io.pos()
                self._m_ext_area = self._root.TgaExtArea(self._io, self, self._root)
                self._m_ext_area._read()
                self._debug['_m_ext_area']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_ext_area if hasattr(self, '_m_ext_area') else None


    class TgaExtArea(KaitaiStruct):
        SEQ_FIELDS = ["ext_area_size", "author_name", "comments", "timestamp", "job_id", "job_time", "software_id", "software_version", "key_color", "pixel_aspect_ratio", "gamma_value", "color_corr_ofs", "postage_stamp_ofs", "scan_line_ofs", "attributes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ext_area_size']['start'] = self._io.pos()
            self.ext_area_size = self._io.read_u2le()
            self._debug['ext_area_size']['end'] = self._io.pos()
            self._debug['author_name']['start'] = self._io.pos()
            self.author_name = (self._io.read_bytes(41)).decode(u"ASCII")
            self._debug['author_name']['end'] = self._io.pos()
            self._debug['comments']['start'] = self._io.pos()
            self.comments = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['comments']:
                    self._debug['comments']['arr'] = []
                self._debug['comments']['arr'].append({'start': self._io.pos()})
                self.comments[i] = (self._io.read_bytes(81)).decode(u"ASCII")
                self._debug['comments']['arr'][i]['end'] = self._io.pos()

            self._debug['comments']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_bytes(12)
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['job_id']['start'] = self._io.pos()
            self.job_id = (self._io.read_bytes(41)).decode(u"ASCII")
            self._debug['job_id']['end'] = self._io.pos()
            self._debug['job_time']['start'] = self._io.pos()
            self.job_time = (self._io.read_bytes(6)).decode(u"ASCII")
            self._debug['job_time']['end'] = self._io.pos()
            self._debug['software_id']['start'] = self._io.pos()
            self.software_id = (self._io.read_bytes(41)).decode(u"ASCII")
            self._debug['software_id']['end'] = self._io.pos()
            self._debug['software_version']['start'] = self._io.pos()
            self.software_version = self._io.read_bytes(3)
            self._debug['software_version']['end'] = self._io.pos()
            self._debug['key_color']['start'] = self._io.pos()
            self.key_color = self._io.read_u4le()
            self._debug['key_color']['end'] = self._io.pos()
            self._debug['pixel_aspect_ratio']['start'] = self._io.pos()
            self.pixel_aspect_ratio = self._io.read_u4le()
            self._debug['pixel_aspect_ratio']['end'] = self._io.pos()
            self._debug['gamma_value']['start'] = self._io.pos()
            self.gamma_value = self._io.read_u4le()
            self._debug['gamma_value']['end'] = self._io.pos()
            self._debug['color_corr_ofs']['start'] = self._io.pos()
            self.color_corr_ofs = self._io.read_u4le()
            self._debug['color_corr_ofs']['end'] = self._io.pos()
            self._debug['postage_stamp_ofs']['start'] = self._io.pos()
            self.postage_stamp_ofs = self._io.read_u4le()
            self._debug['postage_stamp_ofs']['end'] = self._io.pos()
            self._debug['scan_line_ofs']['start'] = self._io.pos()
            self.scan_line_ofs = self._io.read_u4le()
            self._debug['scan_line_ofs']['end'] = self._io.pos()
            self._debug['attributes']['start'] = self._io.pos()
            self.attributes = self._io.read_u1()
            self._debug['attributes']['end'] = self._io.pos()


    @property
    def footer(self):
        if hasattr(self, '_m_footer'):
            return self._m_footer if hasattr(self, '_m_footer') else None

        _pos = self._io.pos()
        self._io.seek((self._io.size() - 26))
        self._debug['_m_footer']['start'] = self._io.pos()
        self._m_footer = self._root.TgaFooter(self._io, self, self._root)
        self._m_footer._read()
        self._debug['_m_footer']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_footer if hasattr(self, '_m_footer') else None


