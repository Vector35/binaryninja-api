# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Ines(KaitaiStruct):
    """
    .. seealso::
       Source - https://wiki.nesdev.com/w/index.php/INES
    """
    SEQ_FIELDS = ["header", "trainer", "prg_rom", "chr_rom", "playchoice10", "title"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self._raw_header = self._io.read_bytes(16)
        io = KaitaiStream(BytesIO(self._raw_header))
        self.header = self._root.Header(io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        if self.header.f6.trainer:
            self._debug['trainer']['start'] = self._io.pos()
            self.trainer = self._io.read_bytes(512)
            self._debug['trainer']['end'] = self._io.pos()

        self._debug['prg_rom']['start'] = self._io.pos()
        self.prg_rom = self._io.read_bytes((self.header.len_prg_rom * 16384))
        self._debug['prg_rom']['end'] = self._io.pos()
        self._debug['chr_rom']['start'] = self._io.pos()
        self.chr_rom = self._io.read_bytes((self.header.len_chr_rom * 8192))
        self._debug['chr_rom']['end'] = self._io.pos()
        if self.header.f7.playchoice10:
            self._debug['playchoice10']['start'] = self._io.pos()
            self.playchoice10 = self._root.Playchoice10(self._io, self, self._root)
            self.playchoice10._read()
            self._debug['playchoice10']['end'] = self._io.pos()

        if not (self._io.is_eof()):
            self._debug['title']['start'] = self._io.pos()
            self.title = (self._io.read_bytes_full()).decode(u"ASCII")
            self._debug['title']['end'] = self._io.pos()


    class Header(KaitaiStruct):
        SEQ_FIELDS = ["magic", "len_prg_rom", "len_chr_rom", "f6", "f7", "len_prg_ram", "f9", "f10", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x4E\x45\x53\x1A")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['len_prg_rom']['start'] = self._io.pos()
            self.len_prg_rom = self._io.read_u1()
            self._debug['len_prg_rom']['end'] = self._io.pos()
            self._debug['len_chr_rom']['start'] = self._io.pos()
            self.len_chr_rom = self._io.read_u1()
            self._debug['len_chr_rom']['end'] = self._io.pos()
            self._debug['f6']['start'] = self._io.pos()
            self._raw_f6 = self._io.read_bytes(1)
            io = KaitaiStream(BytesIO(self._raw_f6))
            self.f6 = self._root.Header.F6(io, self, self._root)
            self.f6._read()
            self._debug['f6']['end'] = self._io.pos()
            self._debug['f7']['start'] = self._io.pos()
            self._raw_f7 = self._io.read_bytes(1)
            io = KaitaiStream(BytesIO(self._raw_f7))
            self.f7 = self._root.Header.F7(io, self, self._root)
            self.f7._read()
            self._debug['f7']['end'] = self._io.pos()
            self._debug['len_prg_ram']['start'] = self._io.pos()
            self.len_prg_ram = self._io.read_u1()
            self._debug['len_prg_ram']['end'] = self._io.pos()
            self._debug['f9']['start'] = self._io.pos()
            self._raw_f9 = self._io.read_bytes(1)
            io = KaitaiStream(BytesIO(self._raw_f9))
            self.f9 = self._root.Header.F9(io, self, self._root)
            self.f9._read()
            self._debug['f9']['end'] = self._io.pos()
            self._debug['f10']['start'] = self._io.pos()
            self._raw_f10 = self._io.read_bytes(1)
            io = KaitaiStream(BytesIO(self._raw_f10))
            self.f10 = self._root.Header.F10(io, self, self._root)
            self.f10._read()
            self._debug['f10']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00")
            self._debug['reserved']['end'] = self._io.pos()

        class F6(KaitaiStruct):
            """
            .. seealso::
               Source - https://wiki.nesdev.com/w/index.php/INES#Flags_6
            """

            class Mirroring(Enum):
                horizontal = 0
                vertical = 1
            SEQ_FIELDS = ["lower_mapper", "four_screen", "trainer", "has_battery_ram", "mirroring"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['lower_mapper']['start'] = self._io.pos()
                self.lower_mapper = self._io.read_bits_int(4)
                self._debug['lower_mapper']['end'] = self._io.pos()
                self._debug['four_screen']['start'] = self._io.pos()
                self.four_screen = self._io.read_bits_int(1) != 0
                self._debug['four_screen']['end'] = self._io.pos()
                self._debug['trainer']['start'] = self._io.pos()
                self.trainer = self._io.read_bits_int(1) != 0
                self._debug['trainer']['end'] = self._io.pos()
                self._debug['has_battery_ram']['start'] = self._io.pos()
                self.has_battery_ram = self._io.read_bits_int(1) != 0
                self._debug['has_battery_ram']['end'] = self._io.pos()
                self._debug['mirroring']['start'] = self._io.pos()
                self.mirroring = KaitaiStream.resolve_enum(self._root.Header.F6.Mirroring, self._io.read_bits_int(1))
                self._debug['mirroring']['end'] = self._io.pos()


        class F7(KaitaiStruct):
            """
            .. seealso::
               Source - https://wiki.nesdev.com/w/index.php/INES#Flags_7
            """
            SEQ_FIELDS = ["upper_mapper", "format", "playchoice10", "vs_unisystem"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['upper_mapper']['start'] = self._io.pos()
                self.upper_mapper = self._io.read_bits_int(4)
                self._debug['upper_mapper']['end'] = self._io.pos()
                self._debug['format']['start'] = self._io.pos()
                self.format = self._io.read_bits_int(2)
                self._debug['format']['end'] = self._io.pos()
                self._debug['playchoice10']['start'] = self._io.pos()
                self.playchoice10 = self._io.read_bits_int(1) != 0
                self._debug['playchoice10']['end'] = self._io.pos()
                self._debug['vs_unisystem']['start'] = self._io.pos()
                self.vs_unisystem = self._io.read_bits_int(1) != 0
                self._debug['vs_unisystem']['end'] = self._io.pos()


        class F9(KaitaiStruct):
            """
            .. seealso::
               Source - https://wiki.nesdev.com/w/index.php/INES#Flags_9
            """

            class TvSystem(Enum):
                ntsc = 0
                pal = 1
            SEQ_FIELDS = ["reserved", "tv_system"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bits_int(7)
                self._debug['reserved']['end'] = self._io.pos()
                self._debug['tv_system']['start'] = self._io.pos()
                self.tv_system = KaitaiStream.resolve_enum(self._root.Header.F9.TvSystem, self._io.read_bits_int(1))
                self._debug['tv_system']['end'] = self._io.pos()


        class F10(KaitaiStruct):
            """
            .. seealso::
               Source - https://wiki.nesdev.com/w/index.php/INES#Flags_10
            """

            class TvSystem(Enum):
                ntsc = 0
                dual1 = 1
                pal = 2
                dual2 = 3
            SEQ_FIELDS = ["reserved1", "bus_conflict", "prg_ram", "reserved2", "tv_system"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.read_bits_int(2)
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['bus_conflict']['start'] = self._io.pos()
                self.bus_conflict = self._io.read_bits_int(1) != 0
                self._debug['bus_conflict']['end'] = self._io.pos()
                self._debug['prg_ram']['start'] = self._io.pos()
                self.prg_ram = self._io.read_bits_int(1) != 0
                self._debug['prg_ram']['end'] = self._io.pos()
                self._debug['reserved2']['start'] = self._io.pos()
                self.reserved2 = self._io.read_bits_int(2)
                self._debug['reserved2']['end'] = self._io.pos()
                self._debug['tv_system']['start'] = self._io.pos()
                self.tv_system = KaitaiStream.resolve_enum(self._root.Header.F10.TvSystem, self._io.read_bits_int(2))
                self._debug['tv_system']['end'] = self._io.pos()


        @property
        def mapper(self):
            """
            .. seealso::
               Source - https://wiki.nesdev.com/w/index.php/Mapper
            """
            if hasattr(self, '_m_mapper'):
                return self._m_mapper if hasattr(self, '_m_mapper') else None

            self._m_mapper = (self.f6.lower_mapper | (self.f7.upper_mapper << 4))
            return self._m_mapper if hasattr(self, '_m_mapper') else None


    class Playchoice10(KaitaiStruct):
        """
        .. seealso::
           Source - http://wiki.nesdev.com/w/index.php/PC10_ROM-Images
        """
        SEQ_FIELDS = ["inst_rom", "prom"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['inst_rom']['start'] = self._io.pos()
            self.inst_rom = self._io.read_bytes(8192)
            self._debug['inst_rom']['end'] = self._io.pos()
            self._debug['prom']['start'] = self._io.pos()
            self.prom = self._root.Playchoice10.Prom(self._io, self, self._root)
            self.prom._read()
            self._debug['prom']['end'] = self._io.pos()

        class Prom(KaitaiStruct):
            SEQ_FIELDS = ["data", "counter_out"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['data']['start'] = self._io.pos()
                self.data = self._io.read_bytes(16)
                self._debug['data']['end'] = self._io.pos()
                self._debug['counter_out']['start'] = self._io.pos()
                self.counter_out = self._io.read_bytes(16)
                self._debug['counter_out']['end'] = self._io.pos()




