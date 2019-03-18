from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class AllegroDat(KaitaiStruct):
    """Allegro library for C (mostly used for game and multimedia apps
    programming) used its own container file format.
    
    In general, it allows storage of arbitrary binary data blocks
    bundled together with some simple key-value style metadata
    ("properties") for every block. Allegro also pre-defines some simple
    formats for bitmaps, fonts, MIDI music, sound samples and
    palettes. Allegro library v4.0+ also support LZSS compression.
    
    This spec applies to Allegro data files for library versions 2.2 up
    to 4.4.
    
    .. seealso::
       Source - https://liballeg.org/stabledocs/en/datafile.html
    """

    class PackEnum(Enum):
        unpacked = 1936484398
    SEQ_FIELDS = ["pack_magic", "dat_magic", "num_objects", "objects"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['pack_magic']['start'] = self._io.pos()
        self.pack_magic = KaitaiStream.resolve_enum(self._root.PackEnum, self._io.read_u4be())
        self._debug['pack_magic']['end'] = self._io.pos()
        self._debug['dat_magic']['start'] = self._io.pos()
        self.dat_magic = self._io.ensure_fixed_contents(b"\x41\x4C\x4C\x2E")
        self._debug['dat_magic']['end'] = self._io.pos()
        self._debug['num_objects']['start'] = self._io.pos()
        self.num_objects = self._io.read_u4be()
        self._debug['num_objects']['end'] = self._io.pos()
        self._debug['objects']['start'] = self._io.pos()
        self.objects = [None] * (self.num_objects)
        for i in range(self.num_objects):
            if not 'arr' in self._debug['objects']:
                self._debug['objects']['arr'] = []
            self._debug['objects']['arr'].append({'start': self._io.pos()})
            _t_objects = self._root.DatObject(self._io, self, self._root)
            _t_objects._read()
            self.objects[i] = _t_objects
            self._debug['objects']['arr'][i]['end'] = self._io.pos()

        self._debug['objects']['end'] = self._io.pos()

    class DatFont16(KaitaiStruct):
        """Simple monochrome monospaced font, 95 characters, 8x16 px
        characters.
        """
        SEQ_FIELDS = ["chars"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chars']['start'] = self._io.pos()
            self.chars = [None] * (95)
            for i in range(95):
                if not 'arr' in self._debug['chars']:
                    self._debug['chars']['arr'] = []
                self._debug['chars']['arr'].append({'start': self._io.pos()})
                self.chars[i] = self._io.read_bytes(16)
                self._debug['chars']['arr'][i]['end'] = self._io.pos()

            self._debug['chars']['end'] = self._io.pos()


    class DatBitmap(KaitaiStruct):
        SEQ_FIELDS = ["bits_per_pixel", "width", "height", "image"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bits_per_pixel']['start'] = self._io.pos()
            self.bits_per_pixel = self._io.read_s2be()
            self._debug['bits_per_pixel']['end'] = self._io.pos()
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u2be()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u2be()
            self._debug['height']['end'] = self._io.pos()
            self._debug['image']['start'] = self._io.pos()
            self.image = self._io.read_bytes_full()
            self._debug['image']['end'] = self._io.pos()


    class DatFont(KaitaiStruct):
        SEQ_FIELDS = ["font_size", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['font_size']['start'] = self._io.pos()
            self.font_size = self._io.read_s2be()
            self._debug['font_size']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.font_size
            if _on == 8:
                self.body = self._root.DatFont8(self._io, self, self._root)
                self.body._read()
            elif _on == 16:
                self.body = self._root.DatFont16(self._io, self, self._root)
                self.body._read()
            elif _on == 0:
                self.body = self._root.DatFont39(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class DatFont8(KaitaiStruct):
        """Simple monochrome monospaced font, 95 characters, 8x8 px
        characters.
        """
        SEQ_FIELDS = ["chars"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chars']['start'] = self._io.pos()
            self.chars = [None] * (95)
            for i in range(95):
                if not 'arr' in self._debug['chars']:
                    self._debug['chars']['arr'] = []
                self._debug['chars']['arr'].append({'start': self._io.pos()})
                self.chars[i] = self._io.read_bytes(8)
                self._debug['chars']['arr'][i]['end'] = self._io.pos()

            self._debug['chars']['end'] = self._io.pos()


    class DatObject(KaitaiStruct):
        SEQ_FIELDS = ["properties", "len_compressed", "len_uncompressed", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['properties']['start'] = self._io.pos()
            self.properties = []
            i = 0
            while True:
                if not 'arr' in self._debug['properties']:
                    self._debug['properties']['arr'] = []
                self._debug['properties']['arr'].append({'start': self._io.pos()})
                _t_properties = self._root.Property(self._io, self, self._root)
                _t_properties._read()
                _ = _t_properties
                self.properties.append(_)
                self._debug['properties']['arr'][len(self.properties) - 1]['end'] = self._io.pos()
                if not (_.is_valid):
                    break
                i += 1
            self._debug['properties']['end'] = self._io.pos()
            self._debug['len_compressed']['start'] = self._io.pos()
            self.len_compressed = self._io.read_s4be()
            self._debug['len_compressed']['end'] = self._io.pos()
            self._debug['len_uncompressed']['start'] = self._io.pos()
            self.len_uncompressed = self._io.read_s4be()
            self._debug['len_uncompressed']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.type
            if _on == u"BMP ":
                self._raw_body = self._io.read_bytes(self.len_compressed)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DatBitmap(io, self, self._root)
                self.body._read()
            elif _on == u"RLE ":
                self._raw_body = self._io.read_bytes(self.len_compressed)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DatRleSprite(io, self, self._root)
                self.body._read()
            elif _on == u"FONT":
                self._raw_body = self._io.read_bytes(self.len_compressed)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DatFont(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.len_compressed)
            self._debug['body']['end'] = self._io.pos()

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type if hasattr(self, '_m_type') else None

            self._m_type = self.properties[-1].magic
            return self._m_type if hasattr(self, '_m_type') else None


    class DatFont39(KaitaiStruct):
        """New bitmap font format introduced since Allegro 3.9: allows
        flexible designation of character ranges, 8-bit colored
        characters, etc.
        """
        SEQ_FIELDS = ["num_ranges", "ranges"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_ranges']['start'] = self._io.pos()
            self.num_ranges = self._io.read_s2be()
            self._debug['num_ranges']['end'] = self._io.pos()
            self._debug['ranges']['start'] = self._io.pos()
            self.ranges = [None] * (self.num_ranges)
            for i in range(self.num_ranges):
                if not 'arr' in self._debug['ranges']:
                    self._debug['ranges']['arr'] = []
                self._debug['ranges']['arr'].append({'start': self._io.pos()})
                _t_ranges = self._root.DatFont39.Range(self._io, self, self._root)
                _t_ranges._read()
                self.ranges[i] = _t_ranges
                self._debug['ranges']['arr'][i]['end'] = self._io.pos()

            self._debug['ranges']['end'] = self._io.pos()

        class Range(KaitaiStruct):
            SEQ_FIELDS = ["mono", "start_char", "end_char", "chars"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['mono']['start'] = self._io.pos()
                self.mono = self._io.read_u1()
                self._debug['mono']['end'] = self._io.pos()
                self._debug['start_char']['start'] = self._io.pos()
                self.start_char = self._io.read_u4be()
                self._debug['start_char']['end'] = self._io.pos()
                self._debug['end_char']['start'] = self._io.pos()
                self.end_char = self._io.read_u4be()
                self._debug['end_char']['end'] = self._io.pos()
                self._debug['chars']['start'] = self._io.pos()
                self.chars = [None] * (((self.end_char - self.start_char) + 1))
                for i in range(((self.end_char - self.start_char) + 1)):
                    if not 'arr' in self._debug['chars']:
                        self._debug['chars']['arr'] = []
                    self._debug['chars']['arr'].append({'start': self._io.pos()})
                    _t_chars = self._root.DatFont39.FontChar(self._io, self, self._root)
                    _t_chars._read()
                    self.chars[i] = _t_chars
                    self._debug['chars']['arr'][i]['end'] = self._io.pos()

                self._debug['chars']['end'] = self._io.pos()


        class FontChar(KaitaiStruct):
            SEQ_FIELDS = ["width", "height", "body"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['width']['start'] = self._io.pos()
                self.width = self._io.read_u2be()
                self._debug['width']['end'] = self._io.pos()
                self._debug['height']['start'] = self._io.pos()
                self.height = self._io.read_u2be()
                self._debug['height']['end'] = self._io.pos()
                self._debug['body']['start'] = self._io.pos()
                self.body = self._io.read_bytes((self.width * self.height))
                self._debug['body']['end'] = self._io.pos()



    class Property(KaitaiStruct):
        SEQ_FIELDS = ["magic", "type", "len_body", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = (self._io.read_bytes(4)).decode(u"UTF-8")
            self._debug['magic']['end'] = self._io.pos()
            if self.is_valid:
                self._debug['type']['start'] = self._io.pos()
                self.type = (self._io.read_bytes(4)).decode(u"UTF-8")
                self._debug['type']['end'] = self._io.pos()

            if self.is_valid:
                self._debug['len_body']['start'] = self._io.pos()
                self.len_body = self._io.read_u4be()
                self._debug['len_body']['end'] = self._io.pos()

            if self.is_valid:
                self._debug['body']['start'] = self._io.pos()
                self.body = (self._io.read_bytes(self.len_body)).decode(u"UTF-8")
                self._debug['body']['end'] = self._io.pos()


        @property
        def is_valid(self):
            if hasattr(self, '_m_is_valid'):
                return self._m_is_valid if hasattr(self, '_m_is_valid') else None

            self._m_is_valid = self.magic == u"prop"
            return self._m_is_valid if hasattr(self, '_m_is_valid') else None


    class DatRleSprite(KaitaiStruct):
        SEQ_FIELDS = ["bits_per_pixel", "width", "height", "len_image", "image"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bits_per_pixel']['start'] = self._io.pos()
            self.bits_per_pixel = self._io.read_s2be()
            self._debug['bits_per_pixel']['end'] = self._io.pos()
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u2be()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u2be()
            self._debug['height']['end'] = self._io.pos()
            self._debug['len_image']['start'] = self._io.pos()
            self.len_image = self._io.read_u4be()
            self._debug['len_image']['end'] = self._io.pos()
            self._debug['image']['start'] = self._io.pos()
            self.image = self._io.read_bytes_full()
            self._debug['image']['end'] = self._io.pos()



