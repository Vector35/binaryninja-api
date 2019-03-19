# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Gzip(KaitaiStruct):
    """Gzip is a popular and standard single-file archiving format. It
    essentially provides a container that stores original file name,
    timestamp and a few other things (like optional comment), basic
    CRCs, etc, and a file compressed by a chosen compression algorithm.
    
    As of 2019, there is actually only one working solution for
    compression algorithms, so it's typically raw DEFLATE stream
    (without zlib header) in all gzipped files.
    
    .. seealso::
       Source - https://tools.ietf.org/html/rfc1952
    """

    class CompressionMethods(Enum):
        deflate = 8

    class Oses(Enum):
        fat = 0
        amiga = 1
        vms = 2
        unix = 3
        vm_cms = 4
        atari_tos = 5
        hpfs = 6
        macintosh = 7
        z_system = 8
        cp_m = 9
        tops_20 = 10
        ntfs = 11
        qdos = 12
        acorn_riscos = 13
        unknown = 255
    SEQ_FIELDS = ["magic", "compression_method", "flags", "mod_time", "extra_flags", "os", "extras", "name", "comment", "header_crc16", "body", "body_crc32", "len_uncompressed"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x1F\x8B")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['compression_method']['start'] = self._io.pos()
        self.compression_method = KaitaiStream.resolve_enum(self._root.CompressionMethods, self._io.read_u1())
        self._debug['compression_method']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._root.Flags(self._io, self, self._root)
        self.flags._read()
        self._debug['flags']['end'] = self._io.pos()
        self._debug['mod_time']['start'] = self._io.pos()
        self.mod_time = self._io.read_u4le()
        self._debug['mod_time']['end'] = self._io.pos()
        self._debug['extra_flags']['start'] = self._io.pos()
        _on = self.compression_method
        if _on == self._root.CompressionMethods.deflate:
            self.extra_flags = self._root.ExtraFlagsDeflate(self._io, self, self._root)
            self.extra_flags._read()
        self._debug['extra_flags']['end'] = self._io.pos()
        self._debug['os']['start'] = self._io.pos()
        self.os = KaitaiStream.resolve_enum(self._root.Oses, self._io.read_u1())
        self._debug['os']['end'] = self._io.pos()
        if self.flags.has_extra:
            self._debug['extras']['start'] = self._io.pos()
            self.extras = self._root.Extras(self._io, self, self._root)
            self.extras._read()
            self._debug['extras']['end'] = self._io.pos()

        if self.flags.has_name:
            self._debug['name']['start'] = self._io.pos()
            self.name = self._io.read_bytes_term(0, False, True, True)
            self._debug['name']['end'] = self._io.pos()

        if self.flags.has_comment:
            self._debug['comment']['start'] = self._io.pos()
            self.comment = self._io.read_bytes_term(0, False, True, True)
            self._debug['comment']['end'] = self._io.pos()

        if self.flags.has_header_crc:
            self._debug['header_crc16']['start'] = self._io.pos()
            self.header_crc16 = self._io.read_u2le()
            self._debug['header_crc16']['end'] = self._io.pos()

        self._debug['body']['start'] = self._io.pos()
        self.body = self._io.read_bytes(((self._io.size() - self._io.pos()) - 8))
        self._debug['body']['end'] = self._io.pos()
        self._debug['body_crc32']['start'] = self._io.pos()
        self.body_crc32 = self._io.read_u4le()
        self._debug['body_crc32']['end'] = self._io.pos()
        self._debug['len_uncompressed']['start'] = self._io.pos()
        self.len_uncompressed = self._io.read_u4le()
        self._debug['len_uncompressed']['end'] = self._io.pos()

    class Flags(KaitaiStruct):
        SEQ_FIELDS = ["reserved1", "has_comment", "has_name", "has_extra", "has_header_crc", "is_text"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(3)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['has_comment']['start'] = self._io.pos()
            self.has_comment = self._io.read_bits_int(1) != 0
            self._debug['has_comment']['end'] = self._io.pos()
            self._debug['has_name']['start'] = self._io.pos()
            self.has_name = self._io.read_bits_int(1) != 0
            self._debug['has_name']['end'] = self._io.pos()
            self._debug['has_extra']['start'] = self._io.pos()
            self.has_extra = self._io.read_bits_int(1) != 0
            self._debug['has_extra']['end'] = self._io.pos()
            self._debug['has_header_crc']['start'] = self._io.pos()
            self.has_header_crc = self._io.read_bits_int(1) != 0
            self._debug['has_header_crc']['end'] = self._io.pos()
            self._debug['is_text']['start'] = self._io.pos()
            self.is_text = self._io.read_bits_int(1) != 0
            self._debug['is_text']['end'] = self._io.pos()


    class ExtraFlagsDeflate(KaitaiStruct):

        class CompressionStrengths(Enum):
            best = 2
            fast = 4
        SEQ_FIELDS = ["compression_strength"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['compression_strength']['start'] = self._io.pos()
            self.compression_strength = KaitaiStream.resolve_enum(self._root.ExtraFlagsDeflate.CompressionStrengths, self._io.read_u1())
            self._debug['compression_strength']['end'] = self._io.pos()


    class Subfields(KaitaiStruct):
        """Container for many subfields, constrained by size of stream.
        """
        SEQ_FIELDS = ["entries"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entries']['start'] = self._io.pos()
            self.entries = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['entries']:
                    self._debug['entries']['arr'] = []
                self._debug['entries']['arr'].append({'start': self._io.pos()})
                _t_entries = self._root.Subfield(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Subfield(KaitaiStruct):
        """Every subfield follows typical [TLV scheme](https://en.wikipedia.org/wiki/Type-length-value):
        
        * `id` serves role of "T"ype
        * `len_data` serves role of "L"ength
        * `data` serves role of "V"alue
        
        This way it's possible to for arbitrary parser to skip over
        subfields it does not support.
        """
        SEQ_FIELDS = ["id", "len_data", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['id']['start'] = self._io.pos()
            self.id = self._io.read_u2le()
            self._debug['id']['end'] = self._io.pos()
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = self._io.read_u2le()
            self._debug['len_data']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes(self.len_data)
            self._debug['data']['end'] = self._io.pos()


    class Extras(KaitaiStruct):
        SEQ_FIELDS = ["len_subfields", "subfields"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_subfields']['start'] = self._io.pos()
            self.len_subfields = self._io.read_u2le()
            self._debug['len_subfields']['end'] = self._io.pos()
            self._debug['subfields']['start'] = self._io.pos()
            self._raw_subfields = self._io.read_bytes(self.len_subfields)
            io = KaitaiStream(BytesIO(self._raw_subfields))
            self.subfields = self._root.Subfields(io, self, self._root)
            self.subfields._read()
            self._debug['subfields']['end'] = self._io.pos()



