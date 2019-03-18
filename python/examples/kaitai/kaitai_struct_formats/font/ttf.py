from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Ttf(KaitaiStruct):
    """A TrueType font file contains data, in table format, that comprises
    an outline font.
    
    .. seealso::
       Source - https://www.microsoft.com/typography/tt/ttf_spec/ttch02.doc
    """
    SEQ_FIELDS = ["offset_table", "directory_table"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['offset_table']['start'] = self._io.pos()
        self.offset_table = self._root.OffsetTable(self._io, self, self._root)
        self.offset_table._read()
        self._debug['offset_table']['end'] = self._io.pos()
        self._debug['directory_table']['start'] = self._io.pos()
        self.directory_table = [None] * (self.offset_table.num_tables)
        for i in range(self.offset_table.num_tables):
            if not 'arr' in self._debug['directory_table']:
                self._debug['directory_table']['arr'] = []
            self._debug['directory_table']['arr'].append({'start': self._io.pos()})
            _t_directory_table = self._root.DirTableEntry(self._io, self, self._root)
            _t_directory_table._read()
            self.directory_table[i] = _t_directory_table
            self._debug['directory_table']['arr'][i]['end'] = self._io.pos()

        self._debug['directory_table']['end'] = self._io.pos()

    class Post(KaitaiStruct):
        SEQ_FIELDS = ["format", "italic_angle", "underline_position", "underline_thichness", "is_fixed_pitch", "min_mem_type42", "max_mem_type42", "min_mem_type1", "max_mem_type1", "format20"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['format']['start'] = self._io.pos()
            self.format = self._root.Fixed(self._io, self, self._root)
            self.format._read()
            self._debug['format']['end'] = self._io.pos()
            self._debug['italic_angle']['start'] = self._io.pos()
            self.italic_angle = self._root.Fixed(self._io, self, self._root)
            self.italic_angle._read()
            self._debug['italic_angle']['end'] = self._io.pos()
            self._debug['underline_position']['start'] = self._io.pos()
            self.underline_position = self._io.read_s2be()
            self._debug['underline_position']['end'] = self._io.pos()
            self._debug['underline_thichness']['start'] = self._io.pos()
            self.underline_thichness = self._io.read_s2be()
            self._debug['underline_thichness']['end'] = self._io.pos()
            self._debug['is_fixed_pitch']['start'] = self._io.pos()
            self.is_fixed_pitch = self._io.read_u4be()
            self._debug['is_fixed_pitch']['end'] = self._io.pos()
            self._debug['min_mem_type42']['start'] = self._io.pos()
            self.min_mem_type42 = self._io.read_u4be()
            self._debug['min_mem_type42']['end'] = self._io.pos()
            self._debug['max_mem_type42']['start'] = self._io.pos()
            self.max_mem_type42 = self._io.read_u4be()
            self._debug['max_mem_type42']['end'] = self._io.pos()
            self._debug['min_mem_type1']['start'] = self._io.pos()
            self.min_mem_type1 = self._io.read_u4be()
            self._debug['min_mem_type1']['end'] = self._io.pos()
            self._debug['max_mem_type1']['start'] = self._io.pos()
            self.max_mem_type1 = self._io.read_u4be()
            self._debug['max_mem_type1']['end'] = self._io.pos()
            if  ((self.format.major == 2) and (self.format.minor == 0)) :
                self._debug['format20']['start'] = self._io.pos()
                self.format20 = self._root.Post.Format20(self._io, self, self._root)
                self.format20._read()
                self._debug['format20']['end'] = self._io.pos()


        class Format20(KaitaiStruct):
            SEQ_FIELDS = ["number_of_glyphs", "glyph_name_index", "glyph_names"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['number_of_glyphs']['start'] = self._io.pos()
                self.number_of_glyphs = self._io.read_u2be()
                self._debug['number_of_glyphs']['end'] = self._io.pos()
                self._debug['glyph_name_index']['start'] = self._io.pos()
                self.glyph_name_index = [None] * (self.number_of_glyphs)
                for i in range(self.number_of_glyphs):
                    if not 'arr' in self._debug['glyph_name_index']:
                        self._debug['glyph_name_index']['arr'] = []
                    self._debug['glyph_name_index']['arr'].append({'start': self._io.pos()})
                    self.glyph_name_index[i] = self._io.read_u2be()
                    self._debug['glyph_name_index']['arr'][i]['end'] = self._io.pos()

                self._debug['glyph_name_index']['end'] = self._io.pos()
                self._debug['glyph_names']['start'] = self._io.pos()
                self.glyph_names = []
                i = 0
                while True:
                    if not 'arr' in self._debug['glyph_names']:
                        self._debug['glyph_names']['arr'] = []
                    self._debug['glyph_names']['arr'].append({'start': self._io.pos()})
                    _t_glyph_names = self._root.Post.Format20.PascalString(self._io, self, self._root)
                    _t_glyph_names._read()
                    _ = _t_glyph_names
                    self.glyph_names.append(_)
                    self._debug['glyph_names']['arr'][len(self.glyph_names) - 1]['end'] = self._io.pos()
                    if _.length == 0:
                        break
                    i += 1
                self._debug['glyph_names']['end'] = self._io.pos()

            class PascalString(KaitaiStruct):
                SEQ_FIELDS = ["length", "value"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['length']['start'] = self._io.pos()
                    self.length = self._io.read_u1()
                    self._debug['length']['end'] = self._io.pos()
                    if self.length != 0:
                        self._debug['value']['start'] = self._io.pos()
                        self.value = (self._io.read_bytes(self.length)).decode(u"ascii")
                        self._debug['value']['end'] = self._io.pos()





    class Name(KaitaiStruct):
        """Name table is meant to include human-readable string metadata
        that describes font: name of the font, its styles, copyright &
        trademark notices, vendor and designer info, etc.
        
        The table includes a list of "name records", each of which
        corresponds to a single metadata entry.
        
        .. seealso::
           Source - https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6name.html
        """

        class Platforms(Enum):
            unicode = 0
            macintosh = 1
            reserved_2 = 2
            microsoft = 3

        class Names(Enum):
            copyright = 0
            font_family = 1
            font_subfamily = 2
            unique_subfamily_id = 3
            full_font_name = 4
            name_table_version = 5
            postscript_font_name = 6
            trademark = 7
            manufacturer = 8
            designer = 9
            description = 10
            url_vendor = 11
            url_designer = 12
            license = 13
            url_license = 14
            reserved_15 = 15
            preferred_family = 16
            preferred_subfamily = 17
            compatible_full_name = 18
            sample_text = 19
        SEQ_FIELDS = ["format_selector", "num_name_records", "ofs_strings", "name_records"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['format_selector']['start'] = self._io.pos()
            self.format_selector = self._io.read_u2be()
            self._debug['format_selector']['end'] = self._io.pos()
            self._debug['num_name_records']['start'] = self._io.pos()
            self.num_name_records = self._io.read_u2be()
            self._debug['num_name_records']['end'] = self._io.pos()
            self._debug['ofs_strings']['start'] = self._io.pos()
            self.ofs_strings = self._io.read_u2be()
            self._debug['ofs_strings']['end'] = self._io.pos()
            self._debug['name_records']['start'] = self._io.pos()
            self.name_records = [None] * (self.num_name_records)
            for i in range(self.num_name_records):
                if not 'arr' in self._debug['name_records']:
                    self._debug['name_records']['arr'] = []
                self._debug['name_records']['arr'].append({'start': self._io.pos()})
                _t_name_records = self._root.Name.NameRecord(self._io, self, self._root)
                _t_name_records._read()
                self.name_records[i] = _t_name_records
                self._debug['name_records']['arr'][i]['end'] = self._io.pos()

            self._debug['name_records']['end'] = self._io.pos()

        class NameRecord(KaitaiStruct):
            SEQ_FIELDS = ["platform_id", "encoding_id", "language_id", "name_id", "len_str", "ofs_str"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['platform_id']['start'] = self._io.pos()
                self.platform_id = KaitaiStream.resolve_enum(self._root.Name.Platforms, self._io.read_u2be())
                self._debug['platform_id']['end'] = self._io.pos()
                self._debug['encoding_id']['start'] = self._io.pos()
                self.encoding_id = self._io.read_u2be()
                self._debug['encoding_id']['end'] = self._io.pos()
                self._debug['language_id']['start'] = self._io.pos()
                self.language_id = self._io.read_u2be()
                self._debug['language_id']['end'] = self._io.pos()
                self._debug['name_id']['start'] = self._io.pos()
                self.name_id = KaitaiStream.resolve_enum(self._root.Name.Names, self._io.read_u2be())
                self._debug['name_id']['end'] = self._io.pos()
                self._debug['len_str']['start'] = self._io.pos()
                self.len_str = self._io.read_u2be()
                self._debug['len_str']['end'] = self._io.pos()
                self._debug['ofs_str']['start'] = self._io.pos()
                self.ofs_str = self._io.read_u2be()
                self._debug['ofs_str']['end'] = self._io.pos()

            @property
            def ascii_value(self):
                if hasattr(self, '_m_ascii_value'):
                    return self._m_ascii_value if hasattr(self, '_m_ascii_value') else None

                io = self._parent._io
                _pos = io.pos()
                io.seek((self._parent.ofs_strings + self.ofs_str))
                self._debug['_m_ascii_value']['start'] = io.pos()
                self._m_ascii_value = (io.read_bytes(self.len_str)).decode(u"ascii")
                self._debug['_m_ascii_value']['end'] = io.pos()
                io.seek(_pos)
                return self._m_ascii_value if hasattr(self, '_m_ascii_value') else None

            @property
            def unicode_value(self):
                if hasattr(self, '_m_unicode_value'):
                    return self._m_unicode_value if hasattr(self, '_m_unicode_value') else None

                io = self._parent._io
                _pos = io.pos()
                io.seek((self._parent.ofs_strings + self.ofs_str))
                self._debug['_m_unicode_value']['start'] = io.pos()
                self._m_unicode_value = (io.read_bytes(self.len_str)).decode(u"utf-16be")
                self._debug['_m_unicode_value']['end'] = io.pos()
                io.seek(_pos)
                return self._m_unicode_value if hasattr(self, '_m_unicode_value') else None



    class Head(KaitaiStruct):

        class Flags(Enum):
            baseline_at_y0 = 1
            left_sidebearing_at_x0 = 2
            flag_depend_on_point_size = 4
            flag_force_ppem = 8
            flag_may_advance_width = 16

        class FontDirectionHint(Enum):
            fully_mixed_directional_glyphs = 0
            only_strongly_left_to_right = 1
            strongly_left_to_right_and_neutrals = 2
        SEQ_FIELDS = ["version", "font_revision", "checksum_adjustment", "magic_number", "flags", "units_per_em", "created", "modified", "x_min", "y_min", "x_max", "y_max", "mac_style", "lowest_rec_ppem", "font_direction_hint", "index_to_loc_format", "glyph_data_format"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Fixed(self._io, self, self._root)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            self._debug['font_revision']['start'] = self._io.pos()
            self.font_revision = self._root.Fixed(self._io, self, self._root)
            self.font_revision._read()
            self._debug['font_revision']['end'] = self._io.pos()
            self._debug['checksum_adjustment']['start'] = self._io.pos()
            self.checksum_adjustment = self._io.read_u4be()
            self._debug['checksum_adjustment']['end'] = self._io.pos()
            self._debug['magic_number']['start'] = self._io.pos()
            self.magic_number = self._io.ensure_fixed_contents(b"\x5F\x0F\x3C\xF5")
            self._debug['magic_number']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = KaitaiStream.resolve_enum(self._root.Head.Flags, self._io.read_u2be())
            self._debug['flags']['end'] = self._io.pos()
            self._debug['units_per_em']['start'] = self._io.pos()
            self.units_per_em = self._io.read_u2be()
            self._debug['units_per_em']['end'] = self._io.pos()
            self._debug['created']['start'] = self._io.pos()
            self.created = self._io.read_u8be()
            self._debug['created']['end'] = self._io.pos()
            self._debug['modified']['start'] = self._io.pos()
            self.modified = self._io.read_u8be()
            self._debug['modified']['end'] = self._io.pos()
            self._debug['x_min']['start'] = self._io.pos()
            self.x_min = self._io.read_s2be()
            self._debug['x_min']['end'] = self._io.pos()
            self._debug['y_min']['start'] = self._io.pos()
            self.y_min = self._io.read_s2be()
            self._debug['y_min']['end'] = self._io.pos()
            self._debug['x_max']['start'] = self._io.pos()
            self.x_max = self._io.read_s2be()
            self._debug['x_max']['end'] = self._io.pos()
            self._debug['y_max']['start'] = self._io.pos()
            self.y_max = self._io.read_s2be()
            self._debug['y_max']['end'] = self._io.pos()
            self._debug['mac_style']['start'] = self._io.pos()
            self.mac_style = self._io.read_u2be()
            self._debug['mac_style']['end'] = self._io.pos()
            self._debug['lowest_rec_ppem']['start'] = self._io.pos()
            self.lowest_rec_ppem = self._io.read_u2be()
            self._debug['lowest_rec_ppem']['end'] = self._io.pos()
            self._debug['font_direction_hint']['start'] = self._io.pos()
            self.font_direction_hint = KaitaiStream.resolve_enum(self._root.Head.FontDirectionHint, self._io.read_s2be())
            self._debug['font_direction_hint']['end'] = self._io.pos()
            self._debug['index_to_loc_format']['start'] = self._io.pos()
            self.index_to_loc_format = self._io.read_s2be()
            self._debug['index_to_loc_format']['end'] = self._io.pos()
            self._debug['glyph_data_format']['start'] = self._io.pos()
            self.glyph_data_format = self._io.read_s2be()
            self._debug['glyph_data_format']['end'] = self._io.pos()


    class Prep(KaitaiStruct):
        SEQ_FIELDS = ["instructions"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['instructions']['start'] = self._io.pos()
            self.instructions = self._io.read_bytes_full()
            self._debug['instructions']['end'] = self._io.pos()


    class Hhea(KaitaiStruct):
        SEQ_FIELDS = ["version", "ascender", "descender", "line_gap", "advance_width_max", "min_left_side_bearing", "min_right_side_bearing", "x_max_extend", "caret_slope_rise", "caret_slope_run", "reserved", "metric_data_format", "number_of_hmetrics"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Fixed(self._io, self, self._root)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            self._debug['ascender']['start'] = self._io.pos()
            self.ascender = self._io.read_s2be()
            self._debug['ascender']['end'] = self._io.pos()
            self._debug['descender']['start'] = self._io.pos()
            self.descender = self._io.read_s2be()
            self._debug['descender']['end'] = self._io.pos()
            self._debug['line_gap']['start'] = self._io.pos()
            self.line_gap = self._io.read_s2be()
            self._debug['line_gap']['end'] = self._io.pos()
            self._debug['advance_width_max']['start'] = self._io.pos()
            self.advance_width_max = self._io.read_u2be()
            self._debug['advance_width_max']['end'] = self._io.pos()
            self._debug['min_left_side_bearing']['start'] = self._io.pos()
            self.min_left_side_bearing = self._io.read_s2be()
            self._debug['min_left_side_bearing']['end'] = self._io.pos()
            self._debug['min_right_side_bearing']['start'] = self._io.pos()
            self.min_right_side_bearing = self._io.read_s2be()
            self._debug['min_right_side_bearing']['end'] = self._io.pos()
            self._debug['x_max_extend']['start'] = self._io.pos()
            self.x_max_extend = self._io.read_s2be()
            self._debug['x_max_extend']['end'] = self._io.pos()
            self._debug['caret_slope_rise']['start'] = self._io.pos()
            self.caret_slope_rise = self._io.read_s2be()
            self._debug['caret_slope_rise']['end'] = self._io.pos()
            self._debug['caret_slope_run']['start'] = self._io.pos()
            self.caret_slope_run = self._io.read_s2be()
            self._debug['caret_slope_run']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['metric_data_format']['start'] = self._io.pos()
            self.metric_data_format = self._io.read_s2be()
            self._debug['metric_data_format']['end'] = self._io.pos()
            self._debug['number_of_hmetrics']['start'] = self._io.pos()
            self.number_of_hmetrics = self._io.read_u2be()
            self._debug['number_of_hmetrics']['end'] = self._io.pos()


    class Fpgm(KaitaiStruct):
        SEQ_FIELDS = ["instructions"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['instructions']['start'] = self._io.pos()
            self.instructions = self._io.read_bytes_full()
            self._debug['instructions']['end'] = self._io.pos()


    class Kern(KaitaiStruct):
        SEQ_FIELDS = ["version", "subtable_count", "subtables"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2be()
            self._debug['version']['end'] = self._io.pos()
            self._debug['subtable_count']['start'] = self._io.pos()
            self.subtable_count = self._io.read_u2be()
            self._debug['subtable_count']['end'] = self._io.pos()
            self._debug['subtables']['start'] = self._io.pos()
            self.subtables = [None] * (self.subtable_count)
            for i in range(self.subtable_count):
                if not 'arr' in self._debug['subtables']:
                    self._debug['subtables']['arr'] = []
                self._debug['subtables']['arr'].append({'start': self._io.pos()})
                _t_subtables = self._root.Kern.Subtable(self._io, self, self._root)
                _t_subtables._read()
                self.subtables[i] = _t_subtables
                self._debug['subtables']['arr'][i]['end'] = self._io.pos()

            self._debug['subtables']['end'] = self._io.pos()

        class Subtable(KaitaiStruct):
            SEQ_FIELDS = ["version", "length", "format", "reserved", "is_override", "is_cross_stream", "is_minimum", "is_horizontal", "format0"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['version']['start'] = self._io.pos()
                self.version = self._io.read_u2be()
                self._debug['version']['end'] = self._io.pos()
                self._debug['length']['start'] = self._io.pos()
                self.length = self._io.read_u2be()
                self._debug['length']['end'] = self._io.pos()
                self._debug['format']['start'] = self._io.pos()
                self.format = self._io.read_u1()
                self._debug['format']['end'] = self._io.pos()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bits_int(4)
                self._debug['reserved']['end'] = self._io.pos()
                self._debug['is_override']['start'] = self._io.pos()
                self.is_override = self._io.read_bits_int(1) != 0
                self._debug['is_override']['end'] = self._io.pos()
                self._debug['is_cross_stream']['start'] = self._io.pos()
                self.is_cross_stream = self._io.read_bits_int(1) != 0
                self._debug['is_cross_stream']['end'] = self._io.pos()
                self._debug['is_minimum']['start'] = self._io.pos()
                self.is_minimum = self._io.read_bits_int(1) != 0
                self._debug['is_minimum']['end'] = self._io.pos()
                self._debug['is_horizontal']['start'] = self._io.pos()
                self.is_horizontal = self._io.read_bits_int(1) != 0
                self._debug['is_horizontal']['end'] = self._io.pos()
                self._io.align_to_byte()
                if self.format == 0:
                    self._debug['format0']['start'] = self._io.pos()
                    self.format0 = self._root.Kern.Subtable.Format0(self._io, self, self._root)
                    self.format0._read()
                    self._debug['format0']['end'] = self._io.pos()


            class Format0(KaitaiStruct):
                SEQ_FIELDS = ["pair_count", "search_range", "entry_selector", "range_shift", "kerning_pairs"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['pair_count']['start'] = self._io.pos()
                    self.pair_count = self._io.read_u2be()
                    self._debug['pair_count']['end'] = self._io.pos()
                    self._debug['search_range']['start'] = self._io.pos()
                    self.search_range = self._io.read_u2be()
                    self._debug['search_range']['end'] = self._io.pos()
                    self._debug['entry_selector']['start'] = self._io.pos()
                    self.entry_selector = self._io.read_u2be()
                    self._debug['entry_selector']['end'] = self._io.pos()
                    self._debug['range_shift']['start'] = self._io.pos()
                    self.range_shift = self._io.read_u2be()
                    self._debug['range_shift']['end'] = self._io.pos()
                    self._debug['kerning_pairs']['start'] = self._io.pos()
                    self.kerning_pairs = [None] * (self.pair_count)
                    for i in range(self.pair_count):
                        if not 'arr' in self._debug['kerning_pairs']:
                            self._debug['kerning_pairs']['arr'] = []
                        self._debug['kerning_pairs']['arr'].append({'start': self._io.pos()})
                        _t_kerning_pairs = self._root.Kern.Subtable.Format0.KerningPair(self._io, self, self._root)
                        _t_kerning_pairs._read()
                        self.kerning_pairs[i] = _t_kerning_pairs
                        self._debug['kerning_pairs']['arr'][i]['end'] = self._io.pos()

                    self._debug['kerning_pairs']['end'] = self._io.pos()

                class KerningPair(KaitaiStruct):
                    SEQ_FIELDS = ["left", "right", "value"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['left']['start'] = self._io.pos()
                        self.left = self._io.read_u2be()
                        self._debug['left']['end'] = self._io.pos()
                        self._debug['right']['start'] = self._io.pos()
                        self.right = self._io.read_u2be()
                        self._debug['right']['end'] = self._io.pos()
                        self._debug['value']['start'] = self._io.pos()
                        self.value = self._io.read_s2be()
                        self._debug['value']['end'] = self._io.pos()





    class DirTableEntry(KaitaiStruct):
        SEQ_FIELDS = ["tag", "checksum", "offset", "length"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['tag']['start'] = self._io.pos()
            self.tag = (self._io.read_bytes(4)).decode(u"ascii")
            self._debug['tag']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u4be()
            self._debug['checksum']['end'] = self._io.pos()
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4be()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u4be()
            self._debug['length']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.offset)
            self._debug['_m_value']['start'] = io.pos()
            _on = self.tag
            if _on == u"head":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Head(io, self, self._root)
                self._m_value._read()
            elif _on == u"cvt ":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Cvt(io, self, self._root)
                self._m_value._read()
            elif _on == u"prep":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Prep(io, self, self._root)
                self._m_value._read()
            elif _on == u"kern":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Kern(io, self, self._root)
                self._m_value._read()
            elif _on == u"hhea":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Hhea(io, self, self._root)
                self._m_value._read()
            elif _on == u"post":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Post(io, self, self._root)
                self._m_value._read()
            elif _on == u"OS/2":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Os2(io, self, self._root)
                self._m_value._read()
            elif _on == u"name":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Name(io, self, self._root)
                self._m_value._read()
            elif _on == u"maxp":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Maxp(io, self, self._root)
                self._m_value._read()
            elif _on == u"glyf":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Glyf(io, self, self._root)
                self._m_value._read()
            elif _on == u"fpgm":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Fpgm(io, self, self._root)
                self._m_value._read()
            elif _on == u"cmap":
                self._raw__m_value = io.read_bytes(self.length)
                io = KaitaiStream(BytesIO(self._raw__m_value))
                self._m_value = self._root.Cmap(io, self, self._root)
                self._m_value._read()
            else:
                self._m_value = io.read_bytes(self.length)
            self._debug['_m_value']['end'] = io.pos()
            io.seek(_pos)
            return self._m_value if hasattr(self, '_m_value') else None


    class Os2(KaitaiStruct):
        """The OS/2 table consists of a set of metrics that are required by Windows and OS/2."""

        class WeightClass(Enum):
            thin = 100
            extra_light = 200
            light = 300
            normal = 400
            medium = 500
            semi_bold = 600
            bold = 700
            extra_bold = 800
            black = 900

        class WidthClass(Enum):
            ultra_condensed = 1
            extra_condensed = 2
            condensed = 3
            semi_condensed = 4
            normal = 5
            semi_expanded = 6
            expanded = 7
            extra_expanded = 8
            ultra_expanded = 9

        class FsType(Enum):
            restricted_license_embedding = 2
            preview_and_print_embedding = 4
            editable_embedding = 8

        class FsSelection(Enum):
            italic = 1
            underscore = 2
            negative = 4
            outlined = 8
            strikeout = 16
            bold = 32
            regular = 64
        SEQ_FIELDS = ["version", "x_avg_char_width", "weight_class", "width_class", "fs_type", "y_subscript_x_size", "y_subscript_y_size", "y_subscript_x_offset", "y_subscript_y_offset", "y_superscript_x_size", "y_superscript_y_size", "y_superscript_x_offset", "y_superscript_y_offset", "y_strikeout_size", "y_strikeout_position", "s_family_class", "panose", "unicode_range", "ach_vend_id", "selection", "first_char_index", "last_char_index", "typo_ascender", "typo_descender", "typo_line_gap", "win_ascent", "win_descent", "code_page_range"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2be()
            self._debug['version']['end'] = self._io.pos()
            self._debug['x_avg_char_width']['start'] = self._io.pos()
            self.x_avg_char_width = self._io.read_s2be()
            self._debug['x_avg_char_width']['end'] = self._io.pos()
            self._debug['weight_class']['start'] = self._io.pos()
            self.weight_class = KaitaiStream.resolve_enum(self._root.Os2.WeightClass, self._io.read_u2be())
            self._debug['weight_class']['end'] = self._io.pos()
            self._debug['width_class']['start'] = self._io.pos()
            self.width_class = KaitaiStream.resolve_enum(self._root.Os2.WidthClass, self._io.read_u2be())
            self._debug['width_class']['end'] = self._io.pos()
            self._debug['fs_type']['start'] = self._io.pos()
            self.fs_type = KaitaiStream.resolve_enum(self._root.Os2.FsType, self._io.read_s2be())
            self._debug['fs_type']['end'] = self._io.pos()
            self._debug['y_subscript_x_size']['start'] = self._io.pos()
            self.y_subscript_x_size = self._io.read_s2be()
            self._debug['y_subscript_x_size']['end'] = self._io.pos()
            self._debug['y_subscript_y_size']['start'] = self._io.pos()
            self.y_subscript_y_size = self._io.read_s2be()
            self._debug['y_subscript_y_size']['end'] = self._io.pos()
            self._debug['y_subscript_x_offset']['start'] = self._io.pos()
            self.y_subscript_x_offset = self._io.read_s2be()
            self._debug['y_subscript_x_offset']['end'] = self._io.pos()
            self._debug['y_subscript_y_offset']['start'] = self._io.pos()
            self.y_subscript_y_offset = self._io.read_s2be()
            self._debug['y_subscript_y_offset']['end'] = self._io.pos()
            self._debug['y_superscript_x_size']['start'] = self._io.pos()
            self.y_superscript_x_size = self._io.read_s2be()
            self._debug['y_superscript_x_size']['end'] = self._io.pos()
            self._debug['y_superscript_y_size']['start'] = self._io.pos()
            self.y_superscript_y_size = self._io.read_s2be()
            self._debug['y_superscript_y_size']['end'] = self._io.pos()
            self._debug['y_superscript_x_offset']['start'] = self._io.pos()
            self.y_superscript_x_offset = self._io.read_s2be()
            self._debug['y_superscript_x_offset']['end'] = self._io.pos()
            self._debug['y_superscript_y_offset']['start'] = self._io.pos()
            self.y_superscript_y_offset = self._io.read_s2be()
            self._debug['y_superscript_y_offset']['end'] = self._io.pos()
            self._debug['y_strikeout_size']['start'] = self._io.pos()
            self.y_strikeout_size = self._io.read_s2be()
            self._debug['y_strikeout_size']['end'] = self._io.pos()
            self._debug['y_strikeout_position']['start'] = self._io.pos()
            self.y_strikeout_position = self._io.read_s2be()
            self._debug['y_strikeout_position']['end'] = self._io.pos()
            self._debug['s_family_class']['start'] = self._io.pos()
            self.s_family_class = self._io.read_s2be()
            self._debug['s_family_class']['end'] = self._io.pos()
            self._debug['panose']['start'] = self._io.pos()
            self.panose = self._root.Os2.Panose(self._io, self, self._root)
            self.panose._read()
            self._debug['panose']['end'] = self._io.pos()
            self._debug['unicode_range']['start'] = self._io.pos()
            self.unicode_range = self._root.Os2.UnicodeRange(self._io, self, self._root)
            self.unicode_range._read()
            self._debug['unicode_range']['end'] = self._io.pos()
            self._debug['ach_vend_id']['start'] = self._io.pos()
            self.ach_vend_id = (self._io.read_bytes(4)).decode(u"ascii")
            self._debug['ach_vend_id']['end'] = self._io.pos()
            self._debug['selection']['start'] = self._io.pos()
            self.selection = KaitaiStream.resolve_enum(self._root.Os2.FsSelection, self._io.read_u2be())
            self._debug['selection']['end'] = self._io.pos()
            self._debug['first_char_index']['start'] = self._io.pos()
            self.first_char_index = self._io.read_u2be()
            self._debug['first_char_index']['end'] = self._io.pos()
            self._debug['last_char_index']['start'] = self._io.pos()
            self.last_char_index = self._io.read_u2be()
            self._debug['last_char_index']['end'] = self._io.pos()
            self._debug['typo_ascender']['start'] = self._io.pos()
            self.typo_ascender = self._io.read_s2be()
            self._debug['typo_ascender']['end'] = self._io.pos()
            self._debug['typo_descender']['start'] = self._io.pos()
            self.typo_descender = self._io.read_s2be()
            self._debug['typo_descender']['end'] = self._io.pos()
            self._debug['typo_line_gap']['start'] = self._io.pos()
            self.typo_line_gap = self._io.read_s2be()
            self._debug['typo_line_gap']['end'] = self._io.pos()
            self._debug['win_ascent']['start'] = self._io.pos()
            self.win_ascent = self._io.read_u2be()
            self._debug['win_ascent']['end'] = self._io.pos()
            self._debug['win_descent']['start'] = self._io.pos()
            self.win_descent = self._io.read_u2be()
            self._debug['win_descent']['end'] = self._io.pos()
            self._debug['code_page_range']['start'] = self._io.pos()
            self.code_page_range = self._root.Os2.CodePageRange(self._io, self, self._root)
            self.code_page_range._read()
            self._debug['code_page_range']['end'] = self._io.pos()

        class Panose(KaitaiStruct):

            class Weight(Enum):
                any = 0
                no_fit = 1
                very_light = 2
                light = 3
                thin = 4
                book = 5
                medium = 6
                demi = 7
                bold = 8
                heavy = 9
                black = 10
                nord = 11

            class Proportion(Enum):
                any = 0
                no_fit = 1
                old_style = 2
                modern = 3
                even_width = 4
                expanded = 5
                condensed = 6
                very_expanded = 7
                very_condensed = 8
                monospaced = 9

            class FamilyKind(Enum):
                any = 0
                no_fit = 1
                text_and_display = 2
                script = 3
                decorative = 4
                pictorial = 5

            class LetterForm(Enum):
                any = 0
                no_fit = 1
                normal_contact = 2
                normal_weighted = 3
                normal_boxed = 4
                normal_flattened = 5
                normal_rounded = 6
                normal_off_center = 7
                normal_square = 8
                oblique_contact = 9
                oblique_weighted = 10
                oblique_boxed = 11
                oblique_flattened = 12
                oblique_rounded = 13
                oblique_off_center = 14
                oblique_square = 15

            class SerifStyle(Enum):
                any = 0
                no_fit = 1
                cove = 2
                obtuse_cove = 3
                square_cove = 4
                obtuse_square_cove = 5
                square = 6
                thin = 7
                bone = 8
                exaggerated = 9
                triangle = 10
                normal_sans = 11
                obtuse_sans = 12
                perp_sans = 13
                flared = 14
                rounded = 15

            class XHeight(Enum):
                any = 0
                no_fit = 1
                constant_small = 2
                constant_standard = 3
                constant_large = 4
                ducking_small = 5
                ducking_standard = 6
                ducking_large = 7

            class ArmStyle(Enum):
                any = 0
                no_fit = 1
                straight_arms_horizontal = 2
                straight_arms_wedge = 3
                straight_arms_vertical = 4
                straight_arms_single_serif = 5
                straight_arms_double_serif = 6
                non_straight_arms_horizontal = 7
                non_straight_arms_wedge = 8
                non_straight_arms_vertical = 9
                non_straight_arms_single_serif = 10
                non_straight_arms_double_serif = 11

            class StrokeVariation(Enum):
                any = 0
                no_fit = 1
                gradual_diagonal = 2
                gradual_transitional = 3
                gradual_vertical = 4
                gradual_horizontal = 5
                rapid_vertical = 6
                rapid_horizontal = 7
                instant_vertical = 8

            class Contrast(Enum):
                any = 0
                no_fit = 1
                none = 2
                very_low = 3
                low = 4
                medium_low = 5
                medium = 6
                medium_high = 7
                high = 8
                very_high = 9

            class Midline(Enum):
                any = 0
                no_fit = 1
                standard_trimmed = 2
                standard_pointed = 3
                standard_serifed = 4
                high_trimmed = 5
                high_pointed = 6
                high_serifed = 7
                constant_trimmed = 8
                constant_pointed = 9
                constant_serifed = 10
                low_trimmed = 11
                low_pointed = 12
                low_serifed = 13
            SEQ_FIELDS = ["family_type", "serif_style", "weight", "proportion", "contrast", "stroke_variation", "arm_style", "letter_form", "midline", "x_height"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['family_type']['start'] = self._io.pos()
                self.family_type = KaitaiStream.resolve_enum(self._root.Os2.Panose.FamilyKind, self._io.read_u1())
                self._debug['family_type']['end'] = self._io.pos()
                self._debug['serif_style']['start'] = self._io.pos()
                self.serif_style = KaitaiStream.resolve_enum(self._root.Os2.Panose.SerifStyle, self._io.read_u1())
                self._debug['serif_style']['end'] = self._io.pos()
                self._debug['weight']['start'] = self._io.pos()
                self.weight = KaitaiStream.resolve_enum(self._root.Os2.Panose.Weight, self._io.read_u1())
                self._debug['weight']['end'] = self._io.pos()
                self._debug['proportion']['start'] = self._io.pos()
                self.proportion = KaitaiStream.resolve_enum(self._root.Os2.Panose.Proportion, self._io.read_u1())
                self._debug['proportion']['end'] = self._io.pos()
                self._debug['contrast']['start'] = self._io.pos()
                self.contrast = KaitaiStream.resolve_enum(self._root.Os2.Panose.Contrast, self._io.read_u1())
                self._debug['contrast']['end'] = self._io.pos()
                self._debug['stroke_variation']['start'] = self._io.pos()
                self.stroke_variation = KaitaiStream.resolve_enum(self._root.Os2.Panose.StrokeVariation, self._io.read_u1())
                self._debug['stroke_variation']['end'] = self._io.pos()
                self._debug['arm_style']['start'] = self._io.pos()
                self.arm_style = KaitaiStream.resolve_enum(self._root.Os2.Panose.ArmStyle, self._io.read_u1())
                self._debug['arm_style']['end'] = self._io.pos()
                self._debug['letter_form']['start'] = self._io.pos()
                self.letter_form = KaitaiStream.resolve_enum(self._root.Os2.Panose.LetterForm, self._io.read_u1())
                self._debug['letter_form']['end'] = self._io.pos()
                self._debug['midline']['start'] = self._io.pos()
                self.midline = KaitaiStream.resolve_enum(self._root.Os2.Panose.Midline, self._io.read_u1())
                self._debug['midline']['end'] = self._io.pos()
                self._debug['x_height']['start'] = self._io.pos()
                self.x_height = KaitaiStream.resolve_enum(self._root.Os2.Panose.XHeight, self._io.read_u1())
                self._debug['x_height']['end'] = self._io.pos()


        class UnicodeRange(KaitaiStruct):
            SEQ_FIELDS = ["basic_latin", "latin_1_supplement", "latin_extended_a", "latin_extended_b", "ipa_extensions", "spacing_modifier_letters", "combining_diacritical_marks", "basic_greek", "greek_symbols_and_coptic", "cyrillic", "armenian", "basic_hebrew", "hebrew_extended", "basic_arabic", "arabic_extended", "devanagari", "bengali", "gurmukhi", "gujarati", "oriya", "tamil", "telugu", "kannada", "malayalam", "thai", "lao", "basic_georgian", "georgian_extended", "hangul_jamo", "latin_extended_additional", "greek_extended", "general_punctuation", "superscripts_and_subscripts", "currency_symbols", "combining_diacritical_marks_for_symbols", "letterlike_symbols", "number_forms", "arrows", "mathematical_operators", "miscellaneous_technical", "control_pictures", "optical_character_recognition", "enclosed_alphanumerics", "box_drawing", "block_elements", "geometric_shapes", "miscellaneous_symbols", "dingbats", "cjk_symbols_and_punctuation", "hiragana", "katakana", "bopomofo", "hangul_compatibility_jamo", "cjk_miscellaneous", "enclosed_cjk_letters_and_months", "cjk_compatibility", "hangul", "reserved_for_unicode_subranges1", "reserved_for_unicode_subranges2", "cjk_unified_ideographs", "private_use_area", "cjk_compatibility_ideographs", "alphabetic_presentation_forms", "arabic_presentation_forms_a", "combining_half_marks", "cjk_compatibility_forms", "small_form_variants", "arabic_presentation_forms_b", "halfwidth_and_fullwidth_forms", "specials", "reserved"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['basic_latin']['start'] = self._io.pos()
                self.basic_latin = self._io.read_bits_int(1) != 0
                self._debug['basic_latin']['end'] = self._io.pos()
                self._debug['latin_1_supplement']['start'] = self._io.pos()
                self.latin_1_supplement = self._io.read_bits_int(1) != 0
                self._debug['latin_1_supplement']['end'] = self._io.pos()
                self._debug['latin_extended_a']['start'] = self._io.pos()
                self.latin_extended_a = self._io.read_bits_int(1) != 0
                self._debug['latin_extended_a']['end'] = self._io.pos()
                self._debug['latin_extended_b']['start'] = self._io.pos()
                self.latin_extended_b = self._io.read_bits_int(1) != 0
                self._debug['latin_extended_b']['end'] = self._io.pos()
                self._debug['ipa_extensions']['start'] = self._io.pos()
                self.ipa_extensions = self._io.read_bits_int(1) != 0
                self._debug['ipa_extensions']['end'] = self._io.pos()
                self._debug['spacing_modifier_letters']['start'] = self._io.pos()
                self.spacing_modifier_letters = self._io.read_bits_int(1) != 0
                self._debug['spacing_modifier_letters']['end'] = self._io.pos()
                self._debug['combining_diacritical_marks']['start'] = self._io.pos()
                self.combining_diacritical_marks = self._io.read_bits_int(1) != 0
                self._debug['combining_diacritical_marks']['end'] = self._io.pos()
                self._debug['basic_greek']['start'] = self._io.pos()
                self.basic_greek = self._io.read_bits_int(1) != 0
                self._debug['basic_greek']['end'] = self._io.pos()
                self._debug['greek_symbols_and_coptic']['start'] = self._io.pos()
                self.greek_symbols_and_coptic = self._io.read_bits_int(1) != 0
                self._debug['greek_symbols_and_coptic']['end'] = self._io.pos()
                self._debug['cyrillic']['start'] = self._io.pos()
                self.cyrillic = self._io.read_bits_int(1) != 0
                self._debug['cyrillic']['end'] = self._io.pos()
                self._debug['armenian']['start'] = self._io.pos()
                self.armenian = self._io.read_bits_int(1) != 0
                self._debug['armenian']['end'] = self._io.pos()
                self._debug['basic_hebrew']['start'] = self._io.pos()
                self.basic_hebrew = self._io.read_bits_int(1) != 0
                self._debug['basic_hebrew']['end'] = self._io.pos()
                self._debug['hebrew_extended']['start'] = self._io.pos()
                self.hebrew_extended = self._io.read_bits_int(1) != 0
                self._debug['hebrew_extended']['end'] = self._io.pos()
                self._debug['basic_arabic']['start'] = self._io.pos()
                self.basic_arabic = self._io.read_bits_int(1) != 0
                self._debug['basic_arabic']['end'] = self._io.pos()
                self._debug['arabic_extended']['start'] = self._io.pos()
                self.arabic_extended = self._io.read_bits_int(1) != 0
                self._debug['arabic_extended']['end'] = self._io.pos()
                self._debug['devanagari']['start'] = self._io.pos()
                self.devanagari = self._io.read_bits_int(1) != 0
                self._debug['devanagari']['end'] = self._io.pos()
                self._debug['bengali']['start'] = self._io.pos()
                self.bengali = self._io.read_bits_int(1) != 0
                self._debug['bengali']['end'] = self._io.pos()
                self._debug['gurmukhi']['start'] = self._io.pos()
                self.gurmukhi = self._io.read_bits_int(1) != 0
                self._debug['gurmukhi']['end'] = self._io.pos()
                self._debug['gujarati']['start'] = self._io.pos()
                self.gujarati = self._io.read_bits_int(1) != 0
                self._debug['gujarati']['end'] = self._io.pos()
                self._debug['oriya']['start'] = self._io.pos()
                self.oriya = self._io.read_bits_int(1) != 0
                self._debug['oriya']['end'] = self._io.pos()
                self._debug['tamil']['start'] = self._io.pos()
                self.tamil = self._io.read_bits_int(1) != 0
                self._debug['tamil']['end'] = self._io.pos()
                self._debug['telugu']['start'] = self._io.pos()
                self.telugu = self._io.read_bits_int(1) != 0
                self._debug['telugu']['end'] = self._io.pos()
                self._debug['kannada']['start'] = self._io.pos()
                self.kannada = self._io.read_bits_int(1) != 0
                self._debug['kannada']['end'] = self._io.pos()
                self._debug['malayalam']['start'] = self._io.pos()
                self.malayalam = self._io.read_bits_int(1) != 0
                self._debug['malayalam']['end'] = self._io.pos()
                self._debug['thai']['start'] = self._io.pos()
                self.thai = self._io.read_bits_int(1) != 0
                self._debug['thai']['end'] = self._io.pos()
                self._debug['lao']['start'] = self._io.pos()
                self.lao = self._io.read_bits_int(1) != 0
                self._debug['lao']['end'] = self._io.pos()
                self._debug['basic_georgian']['start'] = self._io.pos()
                self.basic_georgian = self._io.read_bits_int(1) != 0
                self._debug['basic_georgian']['end'] = self._io.pos()
                self._debug['georgian_extended']['start'] = self._io.pos()
                self.georgian_extended = self._io.read_bits_int(1) != 0
                self._debug['georgian_extended']['end'] = self._io.pos()
                self._debug['hangul_jamo']['start'] = self._io.pos()
                self.hangul_jamo = self._io.read_bits_int(1) != 0
                self._debug['hangul_jamo']['end'] = self._io.pos()
                self._debug['latin_extended_additional']['start'] = self._io.pos()
                self.latin_extended_additional = self._io.read_bits_int(1) != 0
                self._debug['latin_extended_additional']['end'] = self._io.pos()
                self._debug['greek_extended']['start'] = self._io.pos()
                self.greek_extended = self._io.read_bits_int(1) != 0
                self._debug['greek_extended']['end'] = self._io.pos()
                self._debug['general_punctuation']['start'] = self._io.pos()
                self.general_punctuation = self._io.read_bits_int(1) != 0
                self._debug['general_punctuation']['end'] = self._io.pos()
                self._debug['superscripts_and_subscripts']['start'] = self._io.pos()
                self.superscripts_and_subscripts = self._io.read_bits_int(1) != 0
                self._debug['superscripts_and_subscripts']['end'] = self._io.pos()
                self._debug['currency_symbols']['start'] = self._io.pos()
                self.currency_symbols = self._io.read_bits_int(1) != 0
                self._debug['currency_symbols']['end'] = self._io.pos()
                self._debug['combining_diacritical_marks_for_symbols']['start'] = self._io.pos()
                self.combining_diacritical_marks_for_symbols = self._io.read_bits_int(1) != 0
                self._debug['combining_diacritical_marks_for_symbols']['end'] = self._io.pos()
                self._debug['letterlike_symbols']['start'] = self._io.pos()
                self.letterlike_symbols = self._io.read_bits_int(1) != 0
                self._debug['letterlike_symbols']['end'] = self._io.pos()
                self._debug['number_forms']['start'] = self._io.pos()
                self.number_forms = self._io.read_bits_int(1) != 0
                self._debug['number_forms']['end'] = self._io.pos()
                self._debug['arrows']['start'] = self._io.pos()
                self.arrows = self._io.read_bits_int(1) != 0
                self._debug['arrows']['end'] = self._io.pos()
                self._debug['mathematical_operators']['start'] = self._io.pos()
                self.mathematical_operators = self._io.read_bits_int(1) != 0
                self._debug['mathematical_operators']['end'] = self._io.pos()
                self._debug['miscellaneous_technical']['start'] = self._io.pos()
                self.miscellaneous_technical = self._io.read_bits_int(1) != 0
                self._debug['miscellaneous_technical']['end'] = self._io.pos()
                self._debug['control_pictures']['start'] = self._io.pos()
                self.control_pictures = self._io.read_bits_int(1) != 0
                self._debug['control_pictures']['end'] = self._io.pos()
                self._debug['optical_character_recognition']['start'] = self._io.pos()
                self.optical_character_recognition = self._io.read_bits_int(1) != 0
                self._debug['optical_character_recognition']['end'] = self._io.pos()
                self._debug['enclosed_alphanumerics']['start'] = self._io.pos()
                self.enclosed_alphanumerics = self._io.read_bits_int(1) != 0
                self._debug['enclosed_alphanumerics']['end'] = self._io.pos()
                self._debug['box_drawing']['start'] = self._io.pos()
                self.box_drawing = self._io.read_bits_int(1) != 0
                self._debug['box_drawing']['end'] = self._io.pos()
                self._debug['block_elements']['start'] = self._io.pos()
                self.block_elements = self._io.read_bits_int(1) != 0
                self._debug['block_elements']['end'] = self._io.pos()
                self._debug['geometric_shapes']['start'] = self._io.pos()
                self.geometric_shapes = self._io.read_bits_int(1) != 0
                self._debug['geometric_shapes']['end'] = self._io.pos()
                self._debug['miscellaneous_symbols']['start'] = self._io.pos()
                self.miscellaneous_symbols = self._io.read_bits_int(1) != 0
                self._debug['miscellaneous_symbols']['end'] = self._io.pos()
                self._debug['dingbats']['start'] = self._io.pos()
                self.dingbats = self._io.read_bits_int(1) != 0
                self._debug['dingbats']['end'] = self._io.pos()
                self._debug['cjk_symbols_and_punctuation']['start'] = self._io.pos()
                self.cjk_symbols_and_punctuation = self._io.read_bits_int(1) != 0
                self._debug['cjk_symbols_and_punctuation']['end'] = self._io.pos()
                self._debug['hiragana']['start'] = self._io.pos()
                self.hiragana = self._io.read_bits_int(1) != 0
                self._debug['hiragana']['end'] = self._io.pos()
                self._debug['katakana']['start'] = self._io.pos()
                self.katakana = self._io.read_bits_int(1) != 0
                self._debug['katakana']['end'] = self._io.pos()
                self._debug['bopomofo']['start'] = self._io.pos()
                self.bopomofo = self._io.read_bits_int(1) != 0
                self._debug['bopomofo']['end'] = self._io.pos()
                self._debug['hangul_compatibility_jamo']['start'] = self._io.pos()
                self.hangul_compatibility_jamo = self._io.read_bits_int(1) != 0
                self._debug['hangul_compatibility_jamo']['end'] = self._io.pos()
                self._debug['cjk_miscellaneous']['start'] = self._io.pos()
                self.cjk_miscellaneous = self._io.read_bits_int(1) != 0
                self._debug['cjk_miscellaneous']['end'] = self._io.pos()
                self._debug['enclosed_cjk_letters_and_months']['start'] = self._io.pos()
                self.enclosed_cjk_letters_and_months = self._io.read_bits_int(1) != 0
                self._debug['enclosed_cjk_letters_and_months']['end'] = self._io.pos()
                self._debug['cjk_compatibility']['start'] = self._io.pos()
                self.cjk_compatibility = self._io.read_bits_int(1) != 0
                self._debug['cjk_compatibility']['end'] = self._io.pos()
                self._debug['hangul']['start'] = self._io.pos()
                self.hangul = self._io.read_bits_int(1) != 0
                self._debug['hangul']['end'] = self._io.pos()
                self._debug['reserved_for_unicode_subranges1']['start'] = self._io.pos()
                self.reserved_for_unicode_subranges1 = self._io.read_bits_int(1) != 0
                self._debug['reserved_for_unicode_subranges1']['end'] = self._io.pos()
                self._debug['reserved_for_unicode_subranges2']['start'] = self._io.pos()
                self.reserved_for_unicode_subranges2 = self._io.read_bits_int(1) != 0
                self._debug['reserved_for_unicode_subranges2']['end'] = self._io.pos()
                self._debug['cjk_unified_ideographs']['start'] = self._io.pos()
                self.cjk_unified_ideographs = self._io.read_bits_int(1) != 0
                self._debug['cjk_unified_ideographs']['end'] = self._io.pos()
                self._debug['private_use_area']['start'] = self._io.pos()
                self.private_use_area = self._io.read_bits_int(1) != 0
                self._debug['private_use_area']['end'] = self._io.pos()
                self._debug['cjk_compatibility_ideographs']['start'] = self._io.pos()
                self.cjk_compatibility_ideographs = self._io.read_bits_int(1) != 0
                self._debug['cjk_compatibility_ideographs']['end'] = self._io.pos()
                self._debug['alphabetic_presentation_forms']['start'] = self._io.pos()
                self.alphabetic_presentation_forms = self._io.read_bits_int(1) != 0
                self._debug['alphabetic_presentation_forms']['end'] = self._io.pos()
                self._debug['arabic_presentation_forms_a']['start'] = self._io.pos()
                self.arabic_presentation_forms_a = self._io.read_bits_int(1) != 0
                self._debug['arabic_presentation_forms_a']['end'] = self._io.pos()
                self._debug['combining_half_marks']['start'] = self._io.pos()
                self.combining_half_marks = self._io.read_bits_int(1) != 0
                self._debug['combining_half_marks']['end'] = self._io.pos()
                self._debug['cjk_compatibility_forms']['start'] = self._io.pos()
                self.cjk_compatibility_forms = self._io.read_bits_int(1) != 0
                self._debug['cjk_compatibility_forms']['end'] = self._io.pos()
                self._debug['small_form_variants']['start'] = self._io.pos()
                self.small_form_variants = self._io.read_bits_int(1) != 0
                self._debug['small_form_variants']['end'] = self._io.pos()
                self._debug['arabic_presentation_forms_b']['start'] = self._io.pos()
                self.arabic_presentation_forms_b = self._io.read_bits_int(1) != 0
                self._debug['arabic_presentation_forms_b']['end'] = self._io.pos()
                self._debug['halfwidth_and_fullwidth_forms']['start'] = self._io.pos()
                self.halfwidth_and_fullwidth_forms = self._io.read_bits_int(1) != 0
                self._debug['halfwidth_and_fullwidth_forms']['end'] = self._io.pos()
                self._debug['specials']['start'] = self._io.pos()
                self.specials = self._io.read_bits_int(1) != 0
                self._debug['specials']['end'] = self._io.pos()
                self._io.align_to_byte()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bytes(7)
                self._debug['reserved']['end'] = self._io.pos()


        class CodePageRange(KaitaiStruct):
            SEQ_FIELDS = ["symbol_character_set", "oem_character_set", "macintosh_character_set", "reserved_for_alternate_ansi_oem", "cp1361_korean_johab", "cp950_chinese_traditional_chars_taiwan_and_hong_kong", "cp949_korean_wansung", "cp936_chinese_simplified_chars_prc_and_singapore", "cp932_jis_japan", "cp874_thai", "reserved_for_alternate_ansi", "cp1257_windows_baltic", "cp1256_arabic", "cp1255_hebrew", "cp1254_turkish", "cp1253_greek", "cp1251_cyrillic", "cp1250_latin_2_eastern_europe", "cp1252_latin_1", "cp437_us", "cp850_we_latin_1", "cp708_arabic_asmo_708", "cp737_greek_former_437_g", "cp775_ms_dos_baltic", "cp852_latin_2", "cp855_ibm_cyrillic_primarily_russian", "cp857_ibm_turkish", "cp860_ms_dos_portuguese", "cp861_ms_dos_icelandic", "cp862_hebrew", "cp863_ms_dos_canadian_french", "cp864_arabic", "cp865_ms_dos_nordic", "cp866_ms_dos_russian", "cp869_ibm_greek", "reserved_for_oem"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['symbol_character_set']['start'] = self._io.pos()
                self.symbol_character_set = self._io.read_bits_int(1) != 0
                self._debug['symbol_character_set']['end'] = self._io.pos()
                self._debug['oem_character_set']['start'] = self._io.pos()
                self.oem_character_set = self._io.read_bits_int(1) != 0
                self._debug['oem_character_set']['end'] = self._io.pos()
                self._debug['macintosh_character_set']['start'] = self._io.pos()
                self.macintosh_character_set = self._io.read_bits_int(1) != 0
                self._debug['macintosh_character_set']['end'] = self._io.pos()
                self._debug['reserved_for_alternate_ansi_oem']['start'] = self._io.pos()
                self.reserved_for_alternate_ansi_oem = self._io.read_bits_int(7)
                self._debug['reserved_for_alternate_ansi_oem']['end'] = self._io.pos()
                self._debug['cp1361_korean_johab']['start'] = self._io.pos()
                self.cp1361_korean_johab = self._io.read_bits_int(1) != 0
                self._debug['cp1361_korean_johab']['end'] = self._io.pos()
                self._debug['cp950_chinese_traditional_chars_taiwan_and_hong_kong']['start'] = self._io.pos()
                self.cp950_chinese_traditional_chars_taiwan_and_hong_kong = self._io.read_bits_int(1) != 0
                self._debug['cp950_chinese_traditional_chars_taiwan_and_hong_kong']['end'] = self._io.pos()
                self._debug['cp949_korean_wansung']['start'] = self._io.pos()
                self.cp949_korean_wansung = self._io.read_bits_int(1) != 0
                self._debug['cp949_korean_wansung']['end'] = self._io.pos()
                self._debug['cp936_chinese_simplified_chars_prc_and_singapore']['start'] = self._io.pos()
                self.cp936_chinese_simplified_chars_prc_and_singapore = self._io.read_bits_int(1) != 0
                self._debug['cp936_chinese_simplified_chars_prc_and_singapore']['end'] = self._io.pos()
                self._debug['cp932_jis_japan']['start'] = self._io.pos()
                self.cp932_jis_japan = self._io.read_bits_int(1) != 0
                self._debug['cp932_jis_japan']['end'] = self._io.pos()
                self._debug['cp874_thai']['start'] = self._io.pos()
                self.cp874_thai = self._io.read_bits_int(1) != 0
                self._debug['cp874_thai']['end'] = self._io.pos()
                self._debug['reserved_for_alternate_ansi']['start'] = self._io.pos()
                self.reserved_for_alternate_ansi = self._io.read_bits_int(8)
                self._debug['reserved_for_alternate_ansi']['end'] = self._io.pos()
                self._debug['cp1257_windows_baltic']['start'] = self._io.pos()
                self.cp1257_windows_baltic = self._io.read_bits_int(1) != 0
                self._debug['cp1257_windows_baltic']['end'] = self._io.pos()
                self._debug['cp1256_arabic']['start'] = self._io.pos()
                self.cp1256_arabic = self._io.read_bits_int(1) != 0
                self._debug['cp1256_arabic']['end'] = self._io.pos()
                self._debug['cp1255_hebrew']['start'] = self._io.pos()
                self.cp1255_hebrew = self._io.read_bits_int(1) != 0
                self._debug['cp1255_hebrew']['end'] = self._io.pos()
                self._debug['cp1254_turkish']['start'] = self._io.pos()
                self.cp1254_turkish = self._io.read_bits_int(1) != 0
                self._debug['cp1254_turkish']['end'] = self._io.pos()
                self._debug['cp1253_greek']['start'] = self._io.pos()
                self.cp1253_greek = self._io.read_bits_int(1) != 0
                self._debug['cp1253_greek']['end'] = self._io.pos()
                self._debug['cp1251_cyrillic']['start'] = self._io.pos()
                self.cp1251_cyrillic = self._io.read_bits_int(1) != 0
                self._debug['cp1251_cyrillic']['end'] = self._io.pos()
                self._debug['cp1250_latin_2_eastern_europe']['start'] = self._io.pos()
                self.cp1250_latin_2_eastern_europe = self._io.read_bits_int(1) != 0
                self._debug['cp1250_latin_2_eastern_europe']['end'] = self._io.pos()
                self._debug['cp1252_latin_1']['start'] = self._io.pos()
                self.cp1252_latin_1 = self._io.read_bits_int(1) != 0
                self._debug['cp1252_latin_1']['end'] = self._io.pos()
                self._debug['cp437_us']['start'] = self._io.pos()
                self.cp437_us = self._io.read_bits_int(1) != 0
                self._debug['cp437_us']['end'] = self._io.pos()
                self._debug['cp850_we_latin_1']['start'] = self._io.pos()
                self.cp850_we_latin_1 = self._io.read_bits_int(1) != 0
                self._debug['cp850_we_latin_1']['end'] = self._io.pos()
                self._debug['cp708_arabic_asmo_708']['start'] = self._io.pos()
                self.cp708_arabic_asmo_708 = self._io.read_bits_int(1) != 0
                self._debug['cp708_arabic_asmo_708']['end'] = self._io.pos()
                self._debug['cp737_greek_former_437_g']['start'] = self._io.pos()
                self.cp737_greek_former_437_g = self._io.read_bits_int(1) != 0
                self._debug['cp737_greek_former_437_g']['end'] = self._io.pos()
                self._debug['cp775_ms_dos_baltic']['start'] = self._io.pos()
                self.cp775_ms_dos_baltic = self._io.read_bits_int(1) != 0
                self._debug['cp775_ms_dos_baltic']['end'] = self._io.pos()
                self._debug['cp852_latin_2']['start'] = self._io.pos()
                self.cp852_latin_2 = self._io.read_bits_int(1) != 0
                self._debug['cp852_latin_2']['end'] = self._io.pos()
                self._debug['cp855_ibm_cyrillic_primarily_russian']['start'] = self._io.pos()
                self.cp855_ibm_cyrillic_primarily_russian = self._io.read_bits_int(1) != 0
                self._debug['cp855_ibm_cyrillic_primarily_russian']['end'] = self._io.pos()
                self._debug['cp857_ibm_turkish']['start'] = self._io.pos()
                self.cp857_ibm_turkish = self._io.read_bits_int(1) != 0
                self._debug['cp857_ibm_turkish']['end'] = self._io.pos()
                self._debug['cp860_ms_dos_portuguese']['start'] = self._io.pos()
                self.cp860_ms_dos_portuguese = self._io.read_bits_int(1) != 0
                self._debug['cp860_ms_dos_portuguese']['end'] = self._io.pos()
                self._debug['cp861_ms_dos_icelandic']['start'] = self._io.pos()
                self.cp861_ms_dos_icelandic = self._io.read_bits_int(1) != 0
                self._debug['cp861_ms_dos_icelandic']['end'] = self._io.pos()
                self._debug['cp862_hebrew']['start'] = self._io.pos()
                self.cp862_hebrew = self._io.read_bits_int(1) != 0
                self._debug['cp862_hebrew']['end'] = self._io.pos()
                self._debug['cp863_ms_dos_canadian_french']['start'] = self._io.pos()
                self.cp863_ms_dos_canadian_french = self._io.read_bits_int(1) != 0
                self._debug['cp863_ms_dos_canadian_french']['end'] = self._io.pos()
                self._debug['cp864_arabic']['start'] = self._io.pos()
                self.cp864_arabic = self._io.read_bits_int(1) != 0
                self._debug['cp864_arabic']['end'] = self._io.pos()
                self._debug['cp865_ms_dos_nordic']['start'] = self._io.pos()
                self.cp865_ms_dos_nordic = self._io.read_bits_int(1) != 0
                self._debug['cp865_ms_dos_nordic']['end'] = self._io.pos()
                self._debug['cp866_ms_dos_russian']['start'] = self._io.pos()
                self.cp866_ms_dos_russian = self._io.read_bits_int(1) != 0
                self._debug['cp866_ms_dos_russian']['end'] = self._io.pos()
                self._debug['cp869_ibm_greek']['start'] = self._io.pos()
                self.cp869_ibm_greek = self._io.read_bits_int(1) != 0
                self._debug['cp869_ibm_greek']['end'] = self._io.pos()
                self._debug['reserved_for_oem']['start'] = self._io.pos()
                self.reserved_for_oem = self._io.read_bits_int(16)
                self._debug['reserved_for_oem']['end'] = self._io.pos()



    class Fixed(KaitaiStruct):
        SEQ_FIELDS = ["major", "minor"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['major']['start'] = self._io.pos()
            self.major = self._io.read_u2be()
            self._debug['major']['end'] = self._io.pos()
            self._debug['minor']['start'] = self._io.pos()
            self.minor = self._io.read_u2be()
            self._debug['minor']['end'] = self._io.pos()


    class Glyf(KaitaiStruct):
        SEQ_FIELDS = ["number_of_contours", "x_min", "y_min", "x_max", "y_max", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['number_of_contours']['start'] = self._io.pos()
            self.number_of_contours = self._io.read_s2be()
            self._debug['number_of_contours']['end'] = self._io.pos()
            self._debug['x_min']['start'] = self._io.pos()
            self.x_min = self._io.read_s2be()
            self._debug['x_min']['end'] = self._io.pos()
            self._debug['y_min']['start'] = self._io.pos()
            self.y_min = self._io.read_s2be()
            self._debug['y_min']['end'] = self._io.pos()
            self._debug['x_max']['start'] = self._io.pos()
            self.x_max = self._io.read_s2be()
            self._debug['x_max']['end'] = self._io.pos()
            self._debug['y_max']['start'] = self._io.pos()
            self.y_max = self._io.read_s2be()
            self._debug['y_max']['end'] = self._io.pos()
            if self.number_of_contours > 0:
                self._debug['value']['start'] = self._io.pos()
                self.value = self._root.Glyf.SimpleGlyph(self._io, self, self._root)
                self.value._read()
                self._debug['value']['end'] = self._io.pos()


        class SimpleGlyph(KaitaiStruct):
            SEQ_FIELDS = ["end_pts_of_contours", "instruction_length", "instructions", "flags"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['end_pts_of_contours']['start'] = self._io.pos()
                self.end_pts_of_contours = [None] * (self._parent.number_of_contours)
                for i in range(self._parent.number_of_contours):
                    if not 'arr' in self._debug['end_pts_of_contours']:
                        self._debug['end_pts_of_contours']['arr'] = []
                    self._debug['end_pts_of_contours']['arr'].append({'start': self._io.pos()})
                    self.end_pts_of_contours[i] = self._io.read_u2be()
                    self._debug['end_pts_of_contours']['arr'][i]['end'] = self._io.pos()

                self._debug['end_pts_of_contours']['end'] = self._io.pos()
                self._debug['instruction_length']['start'] = self._io.pos()
                self.instruction_length = self._io.read_u2be()
                self._debug['instruction_length']['end'] = self._io.pos()
                self._debug['instructions']['start'] = self._io.pos()
                self.instructions = self._io.read_bytes(self.instruction_length)
                self._debug['instructions']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                self.flags = [None] * (self.point_count)
                for i in range(self.point_count):
                    if not 'arr' in self._debug['flags']:
                        self._debug['flags']['arr'] = []
                    self._debug['flags']['arr'].append({'start': self._io.pos()})
                    _t_flags = self._root.Glyf.SimpleGlyph.Flag(self._io, self, self._root)
                    _t_flags._read()
                    self.flags[i] = _t_flags
                    self._debug['flags']['arr'][i]['end'] = self._io.pos()

                self._debug['flags']['end'] = self._io.pos()

            class Flag(KaitaiStruct):
                SEQ_FIELDS = ["reserved", "y_is_same", "x_is_same", "repeat", "y_short_vector", "x_short_vector", "on_curve", "repeat_value"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['reserved']['start'] = self._io.pos()
                    self.reserved = self._io.read_bits_int(2)
                    self._debug['reserved']['end'] = self._io.pos()
                    self._debug['y_is_same']['start'] = self._io.pos()
                    self.y_is_same = self._io.read_bits_int(1) != 0
                    self._debug['y_is_same']['end'] = self._io.pos()
                    self._debug['x_is_same']['start'] = self._io.pos()
                    self.x_is_same = self._io.read_bits_int(1) != 0
                    self._debug['x_is_same']['end'] = self._io.pos()
                    self._debug['repeat']['start'] = self._io.pos()
                    self.repeat = self._io.read_bits_int(1) != 0
                    self._debug['repeat']['end'] = self._io.pos()
                    self._debug['y_short_vector']['start'] = self._io.pos()
                    self.y_short_vector = self._io.read_bits_int(1) != 0
                    self._debug['y_short_vector']['end'] = self._io.pos()
                    self._debug['x_short_vector']['start'] = self._io.pos()
                    self.x_short_vector = self._io.read_bits_int(1) != 0
                    self._debug['x_short_vector']['end'] = self._io.pos()
                    self._debug['on_curve']['start'] = self._io.pos()
                    self.on_curve = self._io.read_bits_int(1) != 0
                    self._debug['on_curve']['end'] = self._io.pos()
                    self._io.align_to_byte()
                    if self.repeat:
                        self._debug['repeat_value']['start'] = self._io.pos()
                        self.repeat_value = self._io.read_u1()
                        self._debug['repeat_value']['end'] = self._io.pos()



            @property
            def point_count(self):
                if hasattr(self, '_m_point_count'):
                    return self._m_point_count if hasattr(self, '_m_point_count') else None

                self._m_point_count = (max(self.end_pts_of_contours) + 1)
                return self._m_point_count if hasattr(self, '_m_point_count') else None



    class Cvt(KaitaiStruct):
        """cvt  - Control Value Table This table contains a list of values that can be referenced by instructions. They can be used, among other things, to control characteristics for different glyphs.
        """
        SEQ_FIELDS = ["fwords"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['fwords']['start'] = self._io.pos()
            self.fwords = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['fwords']:
                    self._debug['fwords']['arr'] = []
                self._debug['fwords']['arr'].append({'start': self._io.pos()})
                self.fwords.append(self._io.read_s2be())
                self._debug['fwords']['arr'][len(self.fwords) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['fwords']['end'] = self._io.pos()


    class Maxp(KaitaiStruct):
        SEQ_FIELDS = ["table_version_number", "num_glyphs", "max_points", "max_contours", "max_composite_points", "max_composite_contours", "max_zones", "max_twilight_points", "max_storage", "max_function_defs", "max_instruction_defs", "max_stack_elements", "max_size_of_instructions", "max_component_elements", "max_component_depth"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['table_version_number']['start'] = self._io.pos()
            self.table_version_number = self._root.Fixed(self._io, self, self._root)
            self.table_version_number._read()
            self._debug['table_version_number']['end'] = self._io.pos()
            self._debug['num_glyphs']['start'] = self._io.pos()
            self.num_glyphs = self._io.read_u2be()
            self._debug['num_glyphs']['end'] = self._io.pos()
            self._debug['max_points']['start'] = self._io.pos()
            self.max_points = self._io.read_u2be()
            self._debug['max_points']['end'] = self._io.pos()
            self._debug['max_contours']['start'] = self._io.pos()
            self.max_contours = self._io.read_u2be()
            self._debug['max_contours']['end'] = self._io.pos()
            self._debug['max_composite_points']['start'] = self._io.pos()
            self.max_composite_points = self._io.read_u2be()
            self._debug['max_composite_points']['end'] = self._io.pos()
            self._debug['max_composite_contours']['start'] = self._io.pos()
            self.max_composite_contours = self._io.read_u2be()
            self._debug['max_composite_contours']['end'] = self._io.pos()
            self._debug['max_zones']['start'] = self._io.pos()
            self.max_zones = self._io.read_u2be()
            self._debug['max_zones']['end'] = self._io.pos()
            self._debug['max_twilight_points']['start'] = self._io.pos()
            self.max_twilight_points = self._io.read_u2be()
            self._debug['max_twilight_points']['end'] = self._io.pos()
            self._debug['max_storage']['start'] = self._io.pos()
            self.max_storage = self._io.read_u2be()
            self._debug['max_storage']['end'] = self._io.pos()
            self._debug['max_function_defs']['start'] = self._io.pos()
            self.max_function_defs = self._io.read_u2be()
            self._debug['max_function_defs']['end'] = self._io.pos()
            self._debug['max_instruction_defs']['start'] = self._io.pos()
            self.max_instruction_defs = self._io.read_u2be()
            self._debug['max_instruction_defs']['end'] = self._io.pos()
            self._debug['max_stack_elements']['start'] = self._io.pos()
            self.max_stack_elements = self._io.read_u2be()
            self._debug['max_stack_elements']['end'] = self._io.pos()
            self._debug['max_size_of_instructions']['start'] = self._io.pos()
            self.max_size_of_instructions = self._io.read_u2be()
            self._debug['max_size_of_instructions']['end'] = self._io.pos()
            self._debug['max_component_elements']['start'] = self._io.pos()
            self.max_component_elements = self._io.read_u2be()
            self._debug['max_component_elements']['end'] = self._io.pos()
            self._debug['max_component_depth']['start'] = self._io.pos()
            self.max_component_depth = self._io.read_u2be()
            self._debug['max_component_depth']['end'] = self._io.pos()


    class OffsetTable(KaitaiStruct):
        SEQ_FIELDS = ["sfnt_version", "num_tables", "search_range", "entry_selector", "range_shift"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sfnt_version']['start'] = self._io.pos()
            self.sfnt_version = self._root.Fixed(self._io, self, self._root)
            self.sfnt_version._read()
            self._debug['sfnt_version']['end'] = self._io.pos()
            self._debug['num_tables']['start'] = self._io.pos()
            self.num_tables = self._io.read_u2be()
            self._debug['num_tables']['end'] = self._io.pos()
            self._debug['search_range']['start'] = self._io.pos()
            self.search_range = self._io.read_u2be()
            self._debug['search_range']['end'] = self._io.pos()
            self._debug['entry_selector']['start'] = self._io.pos()
            self.entry_selector = self._io.read_u2be()
            self._debug['entry_selector']['end'] = self._io.pos()
            self._debug['range_shift']['start'] = self._io.pos()
            self.range_shift = self._io.read_u2be()
            self._debug['range_shift']['end'] = self._io.pos()


    class Cmap(KaitaiStruct):
        """cmap - Character To Glyph Index Mapping Table This table defines the mapping of character codes to the glyph index values used in the font.
        """
        SEQ_FIELDS = ["version_number", "number_of_encoding_tables", "tables"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version_number']['start'] = self._io.pos()
            self.version_number = self._io.read_u2be()
            self._debug['version_number']['end'] = self._io.pos()
            self._debug['number_of_encoding_tables']['start'] = self._io.pos()
            self.number_of_encoding_tables = self._io.read_u2be()
            self._debug['number_of_encoding_tables']['end'] = self._io.pos()
            self._debug['tables']['start'] = self._io.pos()
            self.tables = [None] * (self.number_of_encoding_tables)
            for i in range(self.number_of_encoding_tables):
                if not 'arr' in self._debug['tables']:
                    self._debug['tables']['arr'] = []
                self._debug['tables']['arr'].append({'start': self._io.pos()})
                _t_tables = self._root.Cmap.SubtableHeader(self._io, self, self._root)
                _t_tables._read()
                self.tables[i] = _t_tables
                self._debug['tables']['arr'][i]['end'] = self._io.pos()

            self._debug['tables']['end'] = self._io.pos()

        class SubtableHeader(KaitaiStruct):
            SEQ_FIELDS = ["platform_id", "encoding_id", "subtable_offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['platform_id']['start'] = self._io.pos()
                self.platform_id = self._io.read_u2be()
                self._debug['platform_id']['end'] = self._io.pos()
                self._debug['encoding_id']['start'] = self._io.pos()
                self.encoding_id = self._io.read_u2be()
                self._debug['encoding_id']['end'] = self._io.pos()
                self._debug['subtable_offset']['start'] = self._io.pos()
                self.subtable_offset = self._io.read_u4be()
                self._debug['subtable_offset']['end'] = self._io.pos()

            @property
            def table(self):
                if hasattr(self, '_m_table'):
                    return self._m_table if hasattr(self, '_m_table') else None

                io = self._parent._io
                _pos = io.pos()
                io.seek(self.subtable_offset)
                self._debug['_m_table']['start'] = io.pos()
                self._m_table = self._root.Cmap.Subtable(io, self, self._root)
                self._m_table._read()
                self._debug['_m_table']['end'] = io.pos()
                io.seek(_pos)
                return self._m_table if hasattr(self, '_m_table') else None


        class Subtable(KaitaiStruct):

            class SubtableFormat(Enum):
                byte_encoding_table = 0
                high_byte_mapping_through_table = 2
                segment_mapping_to_delta_values = 4
                trimmed_table_mapping = 6
            SEQ_FIELDS = ["format", "length", "version", "value"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['format']['start'] = self._io.pos()
                self.format = KaitaiStream.resolve_enum(self._root.Cmap.Subtable.SubtableFormat, self._io.read_u2be())
                self._debug['format']['end'] = self._io.pos()
                self._debug['length']['start'] = self._io.pos()
                self.length = self._io.read_u2be()
                self._debug['length']['end'] = self._io.pos()
                self._debug['version']['start'] = self._io.pos()
                self.version = self._io.read_u2be()
                self._debug['version']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                _on = self.format
                if _on == self._root.Cmap.Subtable.SubtableFormat.byte_encoding_table:
                    self._raw_value = self._io.read_bytes((self.length - 6))
                    io = KaitaiStream(BytesIO(self._raw_value))
                    self.value = self._root.Cmap.Subtable.ByteEncodingTable(io, self, self._root)
                    self.value._read()
                elif _on == self._root.Cmap.Subtable.SubtableFormat.segment_mapping_to_delta_values:
                    self._raw_value = self._io.read_bytes((self.length - 6))
                    io = KaitaiStream(BytesIO(self._raw_value))
                    self.value = self._root.Cmap.Subtable.SegmentMappingToDeltaValues(io, self, self._root)
                    self.value._read()
                elif _on == self._root.Cmap.Subtable.SubtableFormat.high_byte_mapping_through_table:
                    self._raw_value = self._io.read_bytes((self.length - 6))
                    io = KaitaiStream(BytesIO(self._raw_value))
                    self.value = self._root.Cmap.Subtable.HighByteMappingThroughTable(io, self, self._root)
                    self.value._read()
                elif _on == self._root.Cmap.Subtable.SubtableFormat.trimmed_table_mapping:
                    self._raw_value = self._io.read_bytes((self.length - 6))
                    io = KaitaiStream(BytesIO(self._raw_value))
                    self.value = self._root.Cmap.Subtable.TrimmedTableMapping(io, self, self._root)
                    self.value._read()
                else:
                    self.value = self._io.read_bytes((self.length - 6))
                self._debug['value']['end'] = self._io.pos()

            class ByteEncodingTable(KaitaiStruct):
                SEQ_FIELDS = ["glyph_id_array"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['glyph_id_array']['start'] = self._io.pos()
                    self.glyph_id_array = self._io.read_bytes(256)
                    self._debug['glyph_id_array']['end'] = self._io.pos()


            class HighByteMappingThroughTable(KaitaiStruct):
                SEQ_FIELDS = ["sub_header_keys"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['sub_header_keys']['start'] = self._io.pos()
                    self.sub_header_keys = [None] * (256)
                    for i in range(256):
                        if not 'arr' in self._debug['sub_header_keys']:
                            self._debug['sub_header_keys']['arr'] = []
                        self._debug['sub_header_keys']['arr'].append({'start': self._io.pos()})
                        self.sub_header_keys[i] = self._io.read_u2be()
                        self._debug['sub_header_keys']['arr'][i]['end'] = self._io.pos()

                    self._debug['sub_header_keys']['end'] = self._io.pos()


            class SegmentMappingToDeltaValues(KaitaiStruct):
                SEQ_FIELDS = ["seg_count_x2", "search_range", "entry_selector", "range_shift", "end_count", "reserved_pad", "start_count", "id_delta", "id_range_offset", "glyph_id_array"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['seg_count_x2']['start'] = self._io.pos()
                    self.seg_count_x2 = self._io.read_u2be()
                    self._debug['seg_count_x2']['end'] = self._io.pos()
                    self._debug['search_range']['start'] = self._io.pos()
                    self.search_range = self._io.read_u2be()
                    self._debug['search_range']['end'] = self._io.pos()
                    self._debug['entry_selector']['start'] = self._io.pos()
                    self.entry_selector = self._io.read_u2be()
                    self._debug['entry_selector']['end'] = self._io.pos()
                    self._debug['range_shift']['start'] = self._io.pos()
                    self.range_shift = self._io.read_u2be()
                    self._debug['range_shift']['end'] = self._io.pos()
                    self._debug['end_count']['start'] = self._io.pos()
                    self.end_count = [None] * (self.seg_count)
                    for i in range(self.seg_count):
                        if not 'arr' in self._debug['end_count']:
                            self._debug['end_count']['arr'] = []
                        self._debug['end_count']['arr'].append({'start': self._io.pos()})
                        self.end_count[i] = self._io.read_u2be()
                        self._debug['end_count']['arr'][i]['end'] = self._io.pos()

                    self._debug['end_count']['end'] = self._io.pos()
                    self._debug['reserved_pad']['start'] = self._io.pos()
                    self.reserved_pad = self._io.read_u2be()
                    self._debug['reserved_pad']['end'] = self._io.pos()
                    self._debug['start_count']['start'] = self._io.pos()
                    self.start_count = [None] * (self.seg_count)
                    for i in range(self.seg_count):
                        if not 'arr' in self._debug['start_count']:
                            self._debug['start_count']['arr'] = []
                        self._debug['start_count']['arr'].append({'start': self._io.pos()})
                        self.start_count[i] = self._io.read_u2be()
                        self._debug['start_count']['arr'][i]['end'] = self._io.pos()

                    self._debug['start_count']['end'] = self._io.pos()
                    self._debug['id_delta']['start'] = self._io.pos()
                    self.id_delta = [None] * (self.seg_count)
                    for i in range(self.seg_count):
                        if not 'arr' in self._debug['id_delta']:
                            self._debug['id_delta']['arr'] = []
                        self._debug['id_delta']['arr'].append({'start': self._io.pos()})
                        self.id_delta[i] = self._io.read_u2be()
                        self._debug['id_delta']['arr'][i]['end'] = self._io.pos()

                    self._debug['id_delta']['end'] = self._io.pos()
                    self._debug['id_range_offset']['start'] = self._io.pos()
                    self.id_range_offset = [None] * (self.seg_count)
                    for i in range(self.seg_count):
                        if not 'arr' in self._debug['id_range_offset']:
                            self._debug['id_range_offset']['arr'] = []
                        self._debug['id_range_offset']['arr'].append({'start': self._io.pos()})
                        self.id_range_offset[i] = self._io.read_u2be()
                        self._debug['id_range_offset']['arr'][i]['end'] = self._io.pos()

                    self._debug['id_range_offset']['end'] = self._io.pos()
                    self._debug['glyph_id_array']['start'] = self._io.pos()
                    self.glyph_id_array = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['glyph_id_array']:
                            self._debug['glyph_id_array']['arr'] = []
                        self._debug['glyph_id_array']['arr'].append({'start': self._io.pos()})
                        self.glyph_id_array.append(self._io.read_u2be())
                        self._debug['glyph_id_array']['arr'][len(self.glyph_id_array) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['glyph_id_array']['end'] = self._io.pos()

                @property
                def seg_count(self):
                    if hasattr(self, '_m_seg_count'):
                        return self._m_seg_count if hasattr(self, '_m_seg_count') else None

                    self._m_seg_count = self.seg_count_x2 // 2
                    return self._m_seg_count if hasattr(self, '_m_seg_count') else None


            class TrimmedTableMapping(KaitaiStruct):
                SEQ_FIELDS = ["first_code", "entry_count", "glyph_id_array"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['first_code']['start'] = self._io.pos()
                    self.first_code = self._io.read_u2be()
                    self._debug['first_code']['end'] = self._io.pos()
                    self._debug['entry_count']['start'] = self._io.pos()
                    self.entry_count = self._io.read_u2be()
                    self._debug['entry_count']['end'] = self._io.pos()
                    self._debug['glyph_id_array']['start'] = self._io.pos()
                    self.glyph_id_array = [None] * (self.entry_count)
                    for i in range(self.entry_count):
                        if not 'arr' in self._debug['glyph_id_array']:
                            self._debug['glyph_id_array']['arr'] = []
                        self._debug['glyph_id_array']['arr'].append({'start': self._io.pos()})
                        self.glyph_id_array[i] = self._io.read_u2be()
                        self._debug['glyph_id_array']['arr'][i]['end'] = self._io.pos()

                    self._debug['glyph_id_array']['end'] = self._io.pos()





