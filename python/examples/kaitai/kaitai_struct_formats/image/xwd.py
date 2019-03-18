from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Xwd(KaitaiStruct):
    """xwd is a file format written by eponymous X11 screen capture
    application (xwd stands for "X Window Dump"). Typically, an average
    user transforms xwd format into something more widespread by any of
    `xwdtopnm` and `pnmto...` utilities right away.
    
    xwd format itself provides a raw uncompressed bitmap with some
    metainformation, like pixel format, width, height, bit depth,
    etc. Note that technically format includes machine-dependent fields
    and thus is probably a poor choice for true cross-platform usage.
    """

    class PixmapFormat(Enum):
        x_y_bitmap = 0
        x_y_pixmap = 1
        z_pixmap = 2

    class ByteOrder(Enum):
        le = 0
        be = 1

    class VisualClass(Enum):
        static_gray = 0
        gray_scale = 1
        static_color = 2
        pseudo_color = 3
        true_color = 4
        direct_color = 5
    SEQ_FIELDS = ["header_size", "hdr", "color_map"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header_size']['start'] = self._io.pos()
        self.header_size = self._io.read_u4be()
        self._debug['header_size']['end'] = self._io.pos()
        self._debug['hdr']['start'] = self._io.pos()
        self._raw_hdr = self._io.read_bytes((self.header_size - 4))
        io = KaitaiStream(BytesIO(self._raw_hdr))
        self.hdr = self._root.Header(io, self, self._root)
        self.hdr._read()
        self._debug['hdr']['end'] = self._io.pos()
        self._debug['color_map']['start'] = self._io.pos()
        self._raw_color_map = [None] * (self.hdr.color_map_entries)
        self.color_map = [None] * (self.hdr.color_map_entries)
        for i in range(self.hdr.color_map_entries):
            if not 'arr' in self._debug['color_map']:
                self._debug['color_map']['arr'] = []
            self._debug['color_map']['arr'].append({'start': self._io.pos()})
            self._raw_color_map[i] = self._io.read_bytes(12)
            io = KaitaiStream(BytesIO(self._raw_color_map[i]))
            _t_color_map = self._root.ColorMapEntry(io, self, self._root)
            _t_color_map._read()
            self.color_map[i] = _t_color_map
            self._debug['color_map']['arr'][i]['end'] = self._io.pos()

        self._debug['color_map']['end'] = self._io.pos()

    class Header(KaitaiStruct):
        SEQ_FIELDS = ["file_version", "pixmap_format", "pixmap_depth", "pixmap_width", "pixmap_height", "x_offset", "byte_order", "bitmap_unit", "bitmap_bit_order", "bitmap_pad", "bits_per_pixel", "bytes_per_line", "visual_class", "red_mask", "green_mask", "blue_mask", "bits_per_rgb", "number_of_colors", "color_map_entries", "window_width", "window_height", "window_x", "window_y", "window_border_width", "creator"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['file_version']['start'] = self._io.pos()
            self.file_version = self._io.read_u4be()
            self._debug['file_version']['end'] = self._io.pos()
            self._debug['pixmap_format']['start'] = self._io.pos()
            self.pixmap_format = KaitaiStream.resolve_enum(self._root.PixmapFormat, self._io.read_u4be())
            self._debug['pixmap_format']['end'] = self._io.pos()
            self._debug['pixmap_depth']['start'] = self._io.pos()
            self.pixmap_depth = self._io.read_u4be()
            self._debug['pixmap_depth']['end'] = self._io.pos()
            self._debug['pixmap_width']['start'] = self._io.pos()
            self.pixmap_width = self._io.read_u4be()
            self._debug['pixmap_width']['end'] = self._io.pos()
            self._debug['pixmap_height']['start'] = self._io.pos()
            self.pixmap_height = self._io.read_u4be()
            self._debug['pixmap_height']['end'] = self._io.pos()
            self._debug['x_offset']['start'] = self._io.pos()
            self.x_offset = self._io.read_u4be()
            self._debug['x_offset']['end'] = self._io.pos()
            self._debug['byte_order']['start'] = self._io.pos()
            self.byte_order = KaitaiStream.resolve_enum(self._root.ByteOrder, self._io.read_u4be())
            self._debug['byte_order']['end'] = self._io.pos()
            self._debug['bitmap_unit']['start'] = self._io.pos()
            self.bitmap_unit = self._io.read_u4be()
            self._debug['bitmap_unit']['end'] = self._io.pos()
            self._debug['bitmap_bit_order']['start'] = self._io.pos()
            self.bitmap_bit_order = self._io.read_u4be()
            self._debug['bitmap_bit_order']['end'] = self._io.pos()
            self._debug['bitmap_pad']['start'] = self._io.pos()
            self.bitmap_pad = self._io.read_u4be()
            self._debug['bitmap_pad']['end'] = self._io.pos()
            self._debug['bits_per_pixel']['start'] = self._io.pos()
            self.bits_per_pixel = self._io.read_u4be()
            self._debug['bits_per_pixel']['end'] = self._io.pos()
            self._debug['bytes_per_line']['start'] = self._io.pos()
            self.bytes_per_line = self._io.read_u4be()
            self._debug['bytes_per_line']['end'] = self._io.pos()
            self._debug['visual_class']['start'] = self._io.pos()
            self.visual_class = KaitaiStream.resolve_enum(self._root.VisualClass, self._io.read_u4be())
            self._debug['visual_class']['end'] = self._io.pos()
            self._debug['red_mask']['start'] = self._io.pos()
            self.red_mask = self._io.read_u4be()
            self._debug['red_mask']['end'] = self._io.pos()
            self._debug['green_mask']['start'] = self._io.pos()
            self.green_mask = self._io.read_u4be()
            self._debug['green_mask']['end'] = self._io.pos()
            self._debug['blue_mask']['start'] = self._io.pos()
            self.blue_mask = self._io.read_u4be()
            self._debug['blue_mask']['end'] = self._io.pos()
            self._debug['bits_per_rgb']['start'] = self._io.pos()
            self.bits_per_rgb = self._io.read_u4be()
            self._debug['bits_per_rgb']['end'] = self._io.pos()
            self._debug['number_of_colors']['start'] = self._io.pos()
            self.number_of_colors = self._io.read_u4be()
            self._debug['number_of_colors']['end'] = self._io.pos()
            self._debug['color_map_entries']['start'] = self._io.pos()
            self.color_map_entries = self._io.read_u4be()
            self._debug['color_map_entries']['end'] = self._io.pos()
            self._debug['window_width']['start'] = self._io.pos()
            self.window_width = self._io.read_u4be()
            self._debug['window_width']['end'] = self._io.pos()
            self._debug['window_height']['start'] = self._io.pos()
            self.window_height = self._io.read_u4be()
            self._debug['window_height']['end'] = self._io.pos()
            self._debug['window_x']['start'] = self._io.pos()
            self.window_x = self._io.read_s4be()
            self._debug['window_x']['end'] = self._io.pos()
            self._debug['window_y']['start'] = self._io.pos()
            self.window_y = self._io.read_s4be()
            self._debug['window_y']['end'] = self._io.pos()
            self._debug['window_border_width']['start'] = self._io.pos()
            self.window_border_width = self._io.read_u4be()
            self._debug['window_border_width']['end'] = self._io.pos()
            self._debug['creator']['start'] = self._io.pos()
            self.creator = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
            self._debug['creator']['end'] = self._io.pos()


    class ColorMapEntry(KaitaiStruct):
        SEQ_FIELDS = ["entry_number", "red", "green", "blue", "flags", "padding"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entry_number']['start'] = self._io.pos()
            self.entry_number = self._io.read_u4be()
            self._debug['entry_number']['end'] = self._io.pos()
            self._debug['red']['start'] = self._io.pos()
            self.red = self._io.read_u2be()
            self._debug['red']['end'] = self._io.pos()
            self._debug['green']['start'] = self._io.pos()
            self.green = self._io.read_u2be()
            self._debug['green']['end'] = self._io.pos()
            self._debug['blue']['start'] = self._io.pos()
            self.blue = self._io.read_u2be()
            self._debug['blue']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u1()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_u1()
            self._debug['padding']['end'] = self._io.pos()



