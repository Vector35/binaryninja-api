# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class BlenderBlend(KaitaiStruct):
    """Blender is an open source suite for 3D modelling, sculpting,
    animation, compositing, rendering, preparation of assets for its own
    game engine and exporting to others, etc. `.blend` is its own binary
    format that saves whole state of suite: current scene, animations,
    all software settings, extensions, etc.
    
    Internally, .blend format is a hybrid semi-self-descriptive
    format. On top level, it contains a simple header and a sequence of
    file blocks, which more or less follow typical [TLV
    pattern](https://en.wikipedia.org/wiki/Type-length-value). Pre-last
    block would be a structure with code `DNA1`, which is a essentially
    a machine-readable schema of all other structures used in this file.
    """

    class PtrSize(Enum):
        bits_64 = 45
        bits_32 = 95

    class Endian(Enum):
        be = 86
        le = 118
    SEQ_FIELDS = ["hdr", "blocks"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['hdr']['start'] = self._io.pos()
        self.hdr = self._root.Header(self._io, self, self._root)
        self.hdr._read()
        self._debug['hdr']['end'] = self._io.pos()
        self._debug['blocks']['start'] = self._io.pos()
        self.blocks = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['blocks']:
                self._debug['blocks']['arr'] = []
            self._debug['blocks']['arr'].append({'start': self._io.pos()})
            _t_blocks = self._root.FileBlock(self._io, self, self._root)
            _t_blocks._read()
            self.blocks.append(_t_blocks)
            self._debug['blocks']['arr'][len(self.blocks) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['blocks']['end'] = self._io.pos()

    class DnaStruct(KaitaiStruct):
        """DNA struct contains a `type` (type name), which is specified as
        an index in types table, and sequence of fields.
        """
        SEQ_FIELDS = ["idx_type", "num_fields", "fields"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['idx_type']['start'] = self._io.pos()
            self.idx_type = self._io.read_u2le()
            self._debug['idx_type']['end'] = self._io.pos()
            self._debug['num_fields']['start'] = self._io.pos()
            self.num_fields = self._io.read_u2le()
            self._debug['num_fields']['end'] = self._io.pos()
            self._debug['fields']['start'] = self._io.pos()
            self.fields = [None] * (self.num_fields)
            for i in range(self.num_fields):
                if not 'arr' in self._debug['fields']:
                    self._debug['fields']['arr'] = []
                self._debug['fields']['arr'].append({'start': self._io.pos()})
                _t_fields = self._root.DnaField(self._io, self, self._root)
                _t_fields._read()
                self.fields[i] = _t_fields
                self._debug['fields']['arr'][i]['end'] = self._io.pos()

            self._debug['fields']['end'] = self._io.pos()

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type if hasattr(self, '_m_type') else None

            self._m_type = self._parent.types[self.idx_type]
            return self._m_type if hasattr(self, '_m_type') else None


    class FileBlock(KaitaiStruct):
        SEQ_FIELDS = ["code", "len_body", "mem_addr", "sdna_index", "count", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = (self._io.read_bytes(4)).decode(u"ASCII")
            self._debug['code']['end'] = self._io.pos()
            self._debug['len_body']['start'] = self._io.pos()
            self.len_body = self._io.read_u4le()
            self._debug['len_body']['end'] = self._io.pos()
            self._debug['mem_addr']['start'] = self._io.pos()
            self.mem_addr = self._io.read_bytes(self._root.hdr.psize)
            self._debug['mem_addr']['end'] = self._io.pos()
            self._debug['sdna_index']['start'] = self._io.pos()
            self.sdna_index = self._io.read_u4le()
            self._debug['sdna_index']['end'] = self._io.pos()
            self._debug['count']['start'] = self._io.pos()
            self.count = self._io.read_u4le()
            self._debug['count']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.code
            if _on == u"DNA1":
                self._raw_body = self._io.read_bytes(self.len_body)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Dna1Body(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.len_body)
            self._debug['body']['end'] = self._io.pos()

        @property
        def sdna_struct(self):
            if hasattr(self, '_m_sdna_struct'):
                return self._m_sdna_struct if hasattr(self, '_m_sdna_struct') else None

            if self.sdna_index != 0:
                self._m_sdna_struct = self._root.sdna_structs[self.sdna_index]

            return self._m_sdna_struct if hasattr(self, '_m_sdna_struct') else None


    class Dna1Body(KaitaiStruct):
        """DNA1, also known as "Structure DNA", is a special block in
        .blend file, which contains machine-readable specifications of
        all other structures used in this .blend file.
        
        Effectively, this block contains:
        
        * a sequence of "names" (strings which represent field names)
        * a sequence of "types" (strings which represent type name)
        * a sequence of "type lengths"
        * a sequence of "structs" (which describe contents of every
          structure, referring to types and names by index)
        
        .. seealso::
           Source - https://en.blender.org/index.php/Dev:Source/Architecture/File_Format#Structure_DNA
        """
        SEQ_FIELDS = ["id", "name_magic", "num_names", "names", "padding_1", "type_magic", "num_types", "types", "padding_2", "tlen_magic", "lengths", "padding_3", "strc_magic", "num_structs", "structs"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['id']['start'] = self._io.pos()
            self.id = self._io.ensure_fixed_contents(b"\x53\x44\x4E\x41")
            self._debug['id']['end'] = self._io.pos()
            self._debug['name_magic']['start'] = self._io.pos()
            self.name_magic = self._io.ensure_fixed_contents(b"\x4E\x41\x4D\x45")
            self._debug['name_magic']['end'] = self._io.pos()
            self._debug['num_names']['start'] = self._io.pos()
            self.num_names = self._io.read_u4le()
            self._debug['num_names']['end'] = self._io.pos()
            self._debug['names']['start'] = self._io.pos()
            self.names = [None] * (self.num_names)
            for i in range(self.num_names):
                if not 'arr' in self._debug['names']:
                    self._debug['names']['arr'] = []
                self._debug['names']['arr'].append({'start': self._io.pos()})
                self.names[i] = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
                self._debug['names']['arr'][i]['end'] = self._io.pos()

            self._debug['names']['end'] = self._io.pos()
            self._debug['padding_1']['start'] = self._io.pos()
            self.padding_1 = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self._debug['padding_1']['end'] = self._io.pos()
            self._debug['type_magic']['start'] = self._io.pos()
            self.type_magic = self._io.ensure_fixed_contents(b"\x54\x59\x50\x45")
            self._debug['type_magic']['end'] = self._io.pos()
            self._debug['num_types']['start'] = self._io.pos()
            self.num_types = self._io.read_u4le()
            self._debug['num_types']['end'] = self._io.pos()
            self._debug['types']['start'] = self._io.pos()
            self.types = [None] * (self.num_types)
            for i in range(self.num_types):
                if not 'arr' in self._debug['types']:
                    self._debug['types']['arr'] = []
                self._debug['types']['arr'].append({'start': self._io.pos()})
                self.types[i] = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
                self._debug['types']['arr'][i]['end'] = self._io.pos()

            self._debug['types']['end'] = self._io.pos()
            self._debug['padding_2']['start'] = self._io.pos()
            self.padding_2 = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self._debug['padding_2']['end'] = self._io.pos()
            self._debug['tlen_magic']['start'] = self._io.pos()
            self.tlen_magic = self._io.ensure_fixed_contents(b"\x54\x4C\x45\x4E")
            self._debug['tlen_magic']['end'] = self._io.pos()
            self._debug['lengths']['start'] = self._io.pos()
            self.lengths = [None] * (self.num_types)
            for i in range(self.num_types):
                if not 'arr' in self._debug['lengths']:
                    self._debug['lengths']['arr'] = []
                self._debug['lengths']['arr'].append({'start': self._io.pos()})
                self.lengths[i] = self._io.read_u2le()
                self._debug['lengths']['arr'][i]['end'] = self._io.pos()

            self._debug['lengths']['end'] = self._io.pos()
            self._debug['padding_3']['start'] = self._io.pos()
            self.padding_3 = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self._debug['padding_3']['end'] = self._io.pos()
            self._debug['strc_magic']['start'] = self._io.pos()
            self.strc_magic = self._io.ensure_fixed_contents(b"\x53\x54\x52\x43")
            self._debug['strc_magic']['end'] = self._io.pos()
            self._debug['num_structs']['start'] = self._io.pos()
            self.num_structs = self._io.read_u4le()
            self._debug['num_structs']['end'] = self._io.pos()
            self._debug['structs']['start'] = self._io.pos()
            self.structs = [None] * (self.num_structs)
            for i in range(self.num_structs):
                if not 'arr' in self._debug['structs']:
                    self._debug['structs']['arr'] = []
                self._debug['structs']['arr'].append({'start': self._io.pos()})
                _t_structs = self._root.DnaStruct(self._io, self, self._root)
                _t_structs._read()
                self.structs[i] = _t_structs
                self._debug['structs']['arr'][i]['end'] = self._io.pos()

            self._debug['structs']['end'] = self._io.pos()


    class Header(KaitaiStruct):
        SEQ_FIELDS = ["magic", "ptr_size_id", "endian", "version"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x42\x4C\x45\x4E\x44\x45\x52")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['ptr_size_id']['start'] = self._io.pos()
            self.ptr_size_id = KaitaiStream.resolve_enum(self._root.PtrSize, self._io.read_u1())
            self._debug['ptr_size_id']['end'] = self._io.pos()
            self._debug['endian']['start'] = self._io.pos()
            self.endian = KaitaiStream.resolve_enum(self._root.Endian, self._io.read_u1())
            self._debug['endian']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = (self._io.read_bytes(3)).decode(u"ASCII")
            self._debug['version']['end'] = self._io.pos()

        @property
        def psize(self):
            """Number of bytes that a pointer occupies."""
            if hasattr(self, '_m_psize'):
                return self._m_psize if hasattr(self, '_m_psize') else None

            self._m_psize = (8 if self.ptr_size_id == self._root.PtrSize.bits_64 else 4)
            return self._m_psize if hasattr(self, '_m_psize') else None


    class DnaField(KaitaiStruct):
        SEQ_FIELDS = ["idx_type", "idx_name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['idx_type']['start'] = self._io.pos()
            self.idx_type = self._io.read_u2le()
            self._debug['idx_type']['end'] = self._io.pos()
            self._debug['idx_name']['start'] = self._io.pos()
            self.idx_name = self._io.read_u2le()
            self._debug['idx_name']['end'] = self._io.pos()

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type if hasattr(self, '_m_type') else None

            self._m_type = self._parent._parent.types[self.idx_type]
            return self._m_type if hasattr(self, '_m_type') else None

        @property
        def name(self):
            if hasattr(self, '_m_name'):
                return self._m_name if hasattr(self, '_m_name') else None

            self._m_name = self._parent._parent.names[self.idx_name]
            return self._m_name if hasattr(self, '_m_name') else None


    @property
    def sdna_structs(self):
        if hasattr(self, '_m_sdna_structs'):
            return self._m_sdna_structs if hasattr(self, '_m_sdna_structs') else None

        self._m_sdna_structs = self.blocks[(len(self.blocks) - 2)].body.structs
        return self._m_sdna_structs if hasattr(self, '_m_sdna_structs') else None


