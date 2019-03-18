from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Elf(KaitaiStruct):
    """
    .. seealso::
       Source - https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h;hb=HEAD
    """

    class Endian(Enum):
        le = 1
        be = 2

    class ShType(Enum):
        null_type = 0
        progbits = 1
        symtab = 2
        strtab = 3
        rela = 4
        hash = 5
        dynamic = 6
        note = 7
        nobits = 8
        rel = 9
        shlib = 10
        dynsym = 11
        init_array = 14
        fini_array = 15
        preinit_array = 16
        group = 17
        symtab_shndx = 18
        sunw_capchain = 1879048175
        sunw_capinfo = 1879048176
        sunw_symsort = 1879048177
        sunw_tlssort = 1879048178
        sunw_ldynsym = 1879048179
        sunw_dof = 1879048180
        sunw_cap = 1879048181
        sunw_signature = 1879048182
        sunw_annotate = 1879048183
        sunw_debugstr = 1879048184
        sunw_debug = 1879048185
        sunw_move = 1879048186
        sunw_comdat = 1879048187
        sunw_syminfo = 1879048188
        sunw_verdef = 1879048189
        sunw_verneed = 1879048190
        sunw_versym = 1879048191
        sparc_gotdata = 1879048192
        arm_exidx = 1879048193
        arm_preemptmap = 1879048194
        arm_attributes = 1879048195

    class OsAbi(Enum):
        system_v = 0
        hp_ux = 1
        netbsd = 2
        gnu = 3
        solaris = 6
        aix = 7
        irix = 8
        freebsd = 9
        tru64 = 10
        modesto = 11
        openbsd = 12
        openvms = 13
        nsk = 14
        aros = 15
        fenixos = 16
        cloudabi = 17
        openvos = 18

    class Machine(Enum):
        not_set = 0
        sparc = 2
        x86 = 3
        mips = 8
        powerpc = 20
        arm = 40
        superh = 42
        ia_64 = 50
        x86_64 = 62
        aarch64 = 183
        riscv = 243
        bpf = 247

    class DynamicArrayTags(Enum):
        null = 0
        needed = 1
        pltrelsz = 2
        pltgot = 3
        hash = 4
        strtab = 5
        symtab = 6
        rela = 7
        relasz = 8
        relaent = 9
        strsz = 10
        syment = 11
        init = 12
        fini = 13
        soname = 14
        rpath = 15
        symbolic = 16
        rel = 17
        relsz = 18
        relent = 19
        pltrel = 20
        debug = 21
        textrel = 22
        jmprel = 23
        bind_now = 24
        init_array = 25
        fini_array = 26
        init_arraysz = 27
        fini_arraysz = 28
        runpath = 29
        flags = 30
        preinit_array = 32
        preinit_arraysz = 33
        maxpostags = 34
        sunw_auxiliary = 1610612749
        sunw_filter = 1610612750
        sunw_cap = 1610612752
        sunw_symtab = 1610612753
        sunw_symsz = 1610612754
        sunw_sortent = 1610612755
        sunw_symsort = 1610612756
        sunw_symsortsz = 1610612757
        sunw_tlssort = 1610612758
        sunw_tlssortsz = 1610612759
        sunw_capinfo = 1610612760
        sunw_strpad = 1610612761
        sunw_capchain = 1610612762
        sunw_ldmach = 1610612763
        sunw_capchainent = 1610612765
        sunw_capchainsz = 1610612767
        hios = 1879044096
        valrnglo = 1879047424
        gnu_prelinked = 1879047669
        gnu_conflictsz = 1879047670
        gnu_liblistsz = 1879047671
        checksum = 1879047672
        pltpadsz = 1879047673
        moveent = 1879047674
        movesz = 1879047675
        feature_1 = 1879047676
        posflag_1 = 1879047677
        syminsz = 1879047678
        valrnghi = 1879047679
        addrrnglo = 1879047680
        gnu_hash = 1879047925
        tlsdesc_plt = 1879047926
        tlsdesc_got = 1879047927
        gnu_conflict = 1879047928
        gnu_liblist = 1879047929
        config = 1879047930
        depaudit = 1879047931
        audit = 1879047932
        pltpad = 1879047933
        movetab = 1879047934
        addrrnghi = 1879047935
        versym = 1879048176
        relacount = 1879048185
        relcount = 1879048186
        flags_1 = 1879048187
        verdef = 1879048188
        verdefnum = 1879048189
        verneed = 1879048190
        verneednum = 1879048191
        loproc = 1879048192
        sparc_register = 1879048193
        auxiliary = 2147483645
        used = 2147483646
        hiproc = 2147483647

    class Bits(Enum):
        b32 = 1
        b64 = 2

    class PhType(Enum):
        null_type = 0
        load = 1
        dynamic = 2
        interp = 3
        note = 4
        shlib = 5
        phdr = 6
        tls = 7
        gnu_eh_frame = 1685382480
        gnu_stack = 1685382481
        gnu_relro = 1685382482
        pax_flags = 1694766464
        hios = 1879048191
        arm_exidx = 1879048193

    class ObjType(Enum):
        relocatable = 1
        executable = 2
        shared = 3
        core = 4
    SEQ_FIELDS = ["magic", "bits", "endian", "ei_version", "abi", "abi_version", "pad", "header"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x7F\x45\x4C\x46")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['bits']['start'] = self._io.pos()
        self.bits = KaitaiStream.resolve_enum(self._root.Bits, self._io.read_u1())
        self._debug['bits']['end'] = self._io.pos()
        self._debug['endian']['start'] = self._io.pos()
        self.endian = KaitaiStream.resolve_enum(self._root.Endian, self._io.read_u1())
        self._debug['endian']['end'] = self._io.pos()
        self._debug['ei_version']['start'] = self._io.pos()
        self.ei_version = self._io.read_u1()
        self._debug['ei_version']['end'] = self._io.pos()
        self._debug['abi']['start'] = self._io.pos()
        self.abi = KaitaiStream.resolve_enum(self._root.OsAbi, self._io.read_u1())
        self._debug['abi']['end'] = self._io.pos()
        self._debug['abi_version']['start'] = self._io.pos()
        self.abi_version = self._io.read_u1()
        self._debug['abi_version']['end'] = self._io.pos()
        self._debug['pad']['start'] = self._io.pos()
        self.pad = self._io.read_bytes(7)
        self._debug['pad']['end'] = self._io.pos()
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.EndianElf(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()

    class PhdrTypeFlags(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, value, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.value = value
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def read(self):
            if hasattr(self, '_m_read'):
                return self._m_read if hasattr(self, '_m_read') else None

            self._m_read = (self.value & 4) != 0
            return self._m_read if hasattr(self, '_m_read') else None

        @property
        def write(self):
            if hasattr(self, '_m_write'):
                return self._m_write if hasattr(self, '_m_write') else None

            self._m_write = (self.value & 2) != 0
            return self._m_write if hasattr(self, '_m_write') else None

        @property
        def execute(self):
            if hasattr(self, '_m_execute'):
                return self._m_execute if hasattr(self, '_m_execute') else None

            self._m_execute = (self.value & 1) != 0
            return self._m_execute if hasattr(self, '_m_execute') else None

        @property
        def mask_proc(self):
            if hasattr(self, '_m_mask_proc'):
                return self._m_mask_proc if hasattr(self, '_m_mask_proc') else None

            self._m_mask_proc = (self.value & 4026531840) != 0
            return self._m_mask_proc if hasattr(self, '_m_mask_proc') else None


    class SectionHeaderFlags(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, value, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.value = value
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def merge(self):
            """might be merged."""
            if hasattr(self, '_m_merge'):
                return self._m_merge if hasattr(self, '_m_merge') else None

            self._m_merge = (self.value & 16) != 0
            return self._m_merge if hasattr(self, '_m_merge') else None

        @property
        def mask_os(self):
            """OS-specific."""
            if hasattr(self, '_m_mask_os'):
                return self._m_mask_os if hasattr(self, '_m_mask_os') else None

            self._m_mask_os = (self.value & 267386880) != 0
            return self._m_mask_os if hasattr(self, '_m_mask_os') else None

        @property
        def exclude(self):
            """section is excluded unless referenced or allocated (Solaris)."""
            if hasattr(self, '_m_exclude'):
                return self._m_exclude if hasattr(self, '_m_exclude') else None

            self._m_exclude = (self.value & 134217728) != 0
            return self._m_exclude if hasattr(self, '_m_exclude') else None

        @property
        def mask_proc(self):
            """Processor-specific."""
            if hasattr(self, '_m_mask_proc'):
                return self._m_mask_proc if hasattr(self, '_m_mask_proc') else None

            self._m_mask_proc = (self.value & 4026531840) != 0
            return self._m_mask_proc if hasattr(self, '_m_mask_proc') else None

        @property
        def strings(self):
            """contains nul-terminated strings."""
            if hasattr(self, '_m_strings'):
                return self._m_strings if hasattr(self, '_m_strings') else None

            self._m_strings = (self.value & 32) != 0
            return self._m_strings if hasattr(self, '_m_strings') else None

        @property
        def os_non_conforming(self):
            """non-standard OS specific handling required."""
            if hasattr(self, '_m_os_non_conforming'):
                return self._m_os_non_conforming if hasattr(self, '_m_os_non_conforming') else None

            self._m_os_non_conforming = (self.value & 256) != 0
            return self._m_os_non_conforming if hasattr(self, '_m_os_non_conforming') else None

        @property
        def alloc(self):
            """occupies memory during execution."""
            if hasattr(self, '_m_alloc'):
                return self._m_alloc if hasattr(self, '_m_alloc') else None

            self._m_alloc = (self.value & 2) != 0
            return self._m_alloc if hasattr(self, '_m_alloc') else None

        @property
        def exec_instr(self):
            """executable."""
            if hasattr(self, '_m_exec_instr'):
                return self._m_exec_instr if hasattr(self, '_m_exec_instr') else None

            self._m_exec_instr = (self.value & 4) != 0
            return self._m_exec_instr if hasattr(self, '_m_exec_instr') else None

        @property
        def info_link(self):
            """'sh_info' contains SHT index."""
            if hasattr(self, '_m_info_link'):
                return self._m_info_link if hasattr(self, '_m_info_link') else None

            self._m_info_link = (self.value & 64) != 0
            return self._m_info_link if hasattr(self, '_m_info_link') else None

        @property
        def write(self):
            """writable."""
            if hasattr(self, '_m_write'):
                return self._m_write if hasattr(self, '_m_write') else None

            self._m_write = (self.value & 1) != 0
            return self._m_write if hasattr(self, '_m_write') else None

        @property
        def link_order(self):
            """preserve order after combining."""
            if hasattr(self, '_m_link_order'):
                return self._m_link_order if hasattr(self, '_m_link_order') else None

            self._m_link_order = (self.value & 128) != 0
            return self._m_link_order if hasattr(self, '_m_link_order') else None

        @property
        def ordered(self):
            """special ordering requirement (Solaris)."""
            if hasattr(self, '_m_ordered'):
                return self._m_ordered if hasattr(self, '_m_ordered') else None

            self._m_ordered = (self.value & 67108864) != 0
            return self._m_ordered if hasattr(self, '_m_ordered') else None

        @property
        def tls(self):
            """section hold thread-local data."""
            if hasattr(self, '_m_tls'):
                return self._m_tls if hasattr(self, '_m_tls') else None

            self._m_tls = (self.value & 1024) != 0
            return self._m_tls if hasattr(self, '_m_tls') else None

        @property
        def group(self):
            """section is member of a group."""
            if hasattr(self, '_m_group'):
                return self._m_group if hasattr(self, '_m_group') else None

            self._m_group = (self.value & 512) != 0
            return self._m_group if hasattr(self, '_m_group') else None


    class DtFlag1Values(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, value, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.value = value
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def singleton(self):
            """Singleton symbols are used."""
            if hasattr(self, '_m_singleton'):
                return self._m_singleton if hasattr(self, '_m_singleton') else None

            self._m_singleton = (self.value & 33554432) != 0
            return self._m_singleton if hasattr(self, '_m_singleton') else None

        @property
        def ignmuldef(self):
            if hasattr(self, '_m_ignmuldef'):
                return self._m_ignmuldef if hasattr(self, '_m_ignmuldef') else None

            self._m_ignmuldef = (self.value & 262144) != 0
            return self._m_ignmuldef if hasattr(self, '_m_ignmuldef') else None

        @property
        def loadfltr(self):
            """Trigger filtee loading at runtime."""
            if hasattr(self, '_m_loadfltr'):
                return self._m_loadfltr if hasattr(self, '_m_loadfltr') else None

            self._m_loadfltr = (self.value & 16) != 0
            return self._m_loadfltr if hasattr(self, '_m_loadfltr') else None

        @property
        def initfirst(self):
            """Set RTLD_INITFIRST for this object."""
            if hasattr(self, '_m_initfirst'):
                return self._m_initfirst if hasattr(self, '_m_initfirst') else None

            self._m_initfirst = (self.value & 32) != 0
            return self._m_initfirst if hasattr(self, '_m_initfirst') else None

        @property
        def symintpose(self):
            """Object has individual interposers."""
            if hasattr(self, '_m_symintpose'):
                return self._m_symintpose if hasattr(self, '_m_symintpose') else None

            self._m_symintpose = (self.value & 8388608) != 0
            return self._m_symintpose if hasattr(self, '_m_symintpose') else None

        @property
        def noreloc(self):
            if hasattr(self, '_m_noreloc'):
                return self._m_noreloc if hasattr(self, '_m_noreloc') else None

            self._m_noreloc = (self.value & 4194304) != 0
            return self._m_noreloc if hasattr(self, '_m_noreloc') else None

        @property
        def confalt(self):
            """Configuration alternative created."""
            if hasattr(self, '_m_confalt'):
                return self._m_confalt if hasattr(self, '_m_confalt') else None

            self._m_confalt = (self.value & 8192) != 0
            return self._m_confalt if hasattr(self, '_m_confalt') else None

        @property
        def dispreldne(self):
            """Disp reloc applied at build time."""
            if hasattr(self, '_m_dispreldne'):
                return self._m_dispreldne if hasattr(self, '_m_dispreldne') else None

            self._m_dispreldne = (self.value & 32768) != 0
            return self._m_dispreldne if hasattr(self, '_m_dispreldne') else None

        @property
        def rtld_global(self):
            """Set RTLD_GLOBAL for this object."""
            if hasattr(self, '_m_rtld_global'):
                return self._m_rtld_global if hasattr(self, '_m_rtld_global') else None

            self._m_rtld_global = (self.value & 2) != 0
            return self._m_rtld_global if hasattr(self, '_m_rtld_global') else None

        @property
        def nodelete(self):
            """Set RTLD_NODELETE for this object."""
            if hasattr(self, '_m_nodelete'):
                return self._m_nodelete if hasattr(self, '_m_nodelete') else None

            self._m_nodelete = (self.value & 8) != 0
            return self._m_nodelete if hasattr(self, '_m_nodelete') else None

        @property
        def trans(self):
            if hasattr(self, '_m_trans'):
                return self._m_trans if hasattr(self, '_m_trans') else None

            self._m_trans = (self.value & 512) != 0
            return self._m_trans if hasattr(self, '_m_trans') else None

        @property
        def origin(self):
            """$ORIGIN must be handled."""
            if hasattr(self, '_m_origin'):
                return self._m_origin if hasattr(self, '_m_origin') else None

            self._m_origin = (self.value & 128) != 0
            return self._m_origin if hasattr(self, '_m_origin') else None

        @property
        def now(self):
            """Set RTLD_NOW for this object."""
            if hasattr(self, '_m_now'):
                return self._m_now if hasattr(self, '_m_now') else None

            self._m_now = (self.value & 1) != 0
            return self._m_now if hasattr(self, '_m_now') else None

        @property
        def nohdr(self):
            if hasattr(self, '_m_nohdr'):
                return self._m_nohdr if hasattr(self, '_m_nohdr') else None

            self._m_nohdr = (self.value & 1048576) != 0
            return self._m_nohdr if hasattr(self, '_m_nohdr') else None

        @property
        def endfiltee(self):
            """Filtee terminates filters search."""
            if hasattr(self, '_m_endfiltee'):
                return self._m_endfiltee if hasattr(self, '_m_endfiltee') else None

            self._m_endfiltee = (self.value & 16384) != 0
            return self._m_endfiltee if hasattr(self, '_m_endfiltee') else None

        @property
        def nodirect(self):
            """Object has no-direct binding."""
            if hasattr(self, '_m_nodirect'):
                return self._m_nodirect if hasattr(self, '_m_nodirect') else None

            self._m_nodirect = (self.value & 131072) != 0
            return self._m_nodirect if hasattr(self, '_m_nodirect') else None

        @property
        def globaudit(self):
            """Global auditing required."""
            if hasattr(self, '_m_globaudit'):
                return self._m_globaudit if hasattr(self, '_m_globaudit') else None

            self._m_globaudit = (self.value & 16777216) != 0
            return self._m_globaudit if hasattr(self, '_m_globaudit') else None

        @property
        def noksyms(self):
            if hasattr(self, '_m_noksyms'):
                return self._m_noksyms if hasattr(self, '_m_noksyms') else None

            self._m_noksyms = (self.value & 524288) != 0
            return self._m_noksyms if hasattr(self, '_m_noksyms') else None

        @property
        def interpose(self):
            """Object is used to interpose."""
            if hasattr(self, '_m_interpose'):
                return self._m_interpose if hasattr(self, '_m_interpose') else None

            self._m_interpose = (self.value & 1024) != 0
            return self._m_interpose if hasattr(self, '_m_interpose') else None

        @property
        def nodump(self):
            """Object can't be dldump'ed."""
            if hasattr(self, '_m_nodump'):
                return self._m_nodump if hasattr(self, '_m_nodump') else None

            self._m_nodump = (self.value & 4096) != 0
            return self._m_nodump if hasattr(self, '_m_nodump') else None

        @property
        def disprelpnd(self):
            """Disp reloc applied at run-time."""
            if hasattr(self, '_m_disprelpnd'):
                return self._m_disprelpnd if hasattr(self, '_m_disprelpnd') else None

            self._m_disprelpnd = (self.value & 65536) != 0
            return self._m_disprelpnd if hasattr(self, '_m_disprelpnd') else None

        @property
        def noopen(self):
            """Set RTLD_NOOPEN for this object."""
            if hasattr(self, '_m_noopen'):
                return self._m_noopen if hasattr(self, '_m_noopen') else None

            self._m_noopen = (self.value & 64) != 0
            return self._m_noopen if hasattr(self, '_m_noopen') else None

        @property
        def stub(self):
            if hasattr(self, '_m_stub'):
                return self._m_stub if hasattr(self, '_m_stub') else None

            self._m_stub = (self.value & 67108864) != 0
            return self._m_stub if hasattr(self, '_m_stub') else None

        @property
        def direct(self):
            """Direct binding enabled."""
            if hasattr(self, '_m_direct'):
                return self._m_direct if hasattr(self, '_m_direct') else None

            self._m_direct = (self.value & 256) != 0
            return self._m_direct if hasattr(self, '_m_direct') else None

        @property
        def edited(self):
            """Object is modified after built."""
            if hasattr(self, '_m_edited'):
                return self._m_edited if hasattr(self, '_m_edited') else None

            self._m_edited = (self.value & 2097152) != 0
            return self._m_edited if hasattr(self, '_m_edited') else None

        @property
        def group(self):
            """Set RTLD_GROUP for this object."""
            if hasattr(self, '_m_group'):
                return self._m_group if hasattr(self, '_m_group') else None

            self._m_group = (self.value & 4) != 0
            return self._m_group if hasattr(self, '_m_group') else None

        @property
        def pie(self):
            if hasattr(self, '_m_pie'):
                return self._m_pie if hasattr(self, '_m_pie') else None

            self._m_pie = (self.value & 134217728) != 0
            return self._m_pie if hasattr(self, '_m_pie') else None

        @property
        def nodeflib(self):
            """Ignore default lib search path."""
            if hasattr(self, '_m_nodeflib'):
                return self._m_nodeflib if hasattr(self, '_m_nodeflib') else None

            self._m_nodeflib = (self.value & 2048) != 0
            return self._m_nodeflib if hasattr(self, '_m_nodeflib') else None


    class EndianElf(KaitaiStruct):
        SEQ_FIELDS = ["e_type", "machine", "e_version", "entry_point", "program_header_offset", "section_header_offset", "flags", "e_ehsize", "program_header_entry_size", "qty_program_header", "section_header_entry_size", "qty_section_header", "section_names_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            _on = self._root.endian
            if _on == self._root.Endian.le:
                self._is_le = True
            elif _on == self._root.Endian.be:
                self._is_le = False

            if self._is_le == True:
                self._read_le()
            elif self._is_le == False:
                self._read_be()
            else:
                raise Exception("Unable to decide endianness")

        def _read_le(self):
            self._debug['e_type']['start'] = self._io.pos()
            self.e_type = KaitaiStream.resolve_enum(self._root.ObjType, self._io.read_u2le())
            self._debug['e_type']['end'] = self._io.pos()
            self._debug['machine']['start'] = self._io.pos()
            self.machine = KaitaiStream.resolve_enum(self._root.Machine, self._io.read_u2le())
            self._debug['machine']['end'] = self._io.pos()
            self._debug['e_version']['start'] = self._io.pos()
            self.e_version = self._io.read_u4le()
            self._debug['e_version']['end'] = self._io.pos()
            self._debug['entry_point']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.entry_point = self._io.read_u4le()
            elif _on == self._root.Bits.b64:
                self.entry_point = self._io.read_u8le()
            self._debug['entry_point']['end'] = self._io.pos()
            self._debug['program_header_offset']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.program_header_offset = self._io.read_u4le()
            elif _on == self._root.Bits.b64:
                self.program_header_offset = self._io.read_u8le()
            self._debug['program_header_offset']['end'] = self._io.pos()
            self._debug['section_header_offset']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.section_header_offset = self._io.read_u4le()
            elif _on == self._root.Bits.b64:
                self.section_header_offset = self._io.read_u8le()
            self._debug['section_header_offset']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes(4)
            self._debug['flags']['end'] = self._io.pos()
            self._debug['e_ehsize']['start'] = self._io.pos()
            self.e_ehsize = self._io.read_u2le()
            self._debug['e_ehsize']['end'] = self._io.pos()
            self._debug['program_header_entry_size']['start'] = self._io.pos()
            self.program_header_entry_size = self._io.read_u2le()
            self._debug['program_header_entry_size']['end'] = self._io.pos()
            self._debug['qty_program_header']['start'] = self._io.pos()
            self.qty_program_header = self._io.read_u2le()
            self._debug['qty_program_header']['end'] = self._io.pos()
            self._debug['section_header_entry_size']['start'] = self._io.pos()
            self.section_header_entry_size = self._io.read_u2le()
            self._debug['section_header_entry_size']['end'] = self._io.pos()
            self._debug['qty_section_header']['start'] = self._io.pos()
            self.qty_section_header = self._io.read_u2le()
            self._debug['qty_section_header']['end'] = self._io.pos()
            self._debug['section_names_idx']['start'] = self._io.pos()
            self.section_names_idx = self._io.read_u2le()
            self._debug['section_names_idx']['end'] = self._io.pos()

        def _read_be(self):
            self._debug['e_type']['start'] = self._io.pos()
            self.e_type = KaitaiStream.resolve_enum(self._root.ObjType, self._io.read_u2be())
            self._debug['e_type']['end'] = self._io.pos()
            self._debug['machine']['start'] = self._io.pos()
            self.machine = KaitaiStream.resolve_enum(self._root.Machine, self._io.read_u2be())
            self._debug['machine']['end'] = self._io.pos()
            self._debug['e_version']['start'] = self._io.pos()
            self.e_version = self._io.read_u4be()
            self._debug['e_version']['end'] = self._io.pos()
            self._debug['entry_point']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.entry_point = self._io.read_u4be()
            elif _on == self._root.Bits.b64:
                self.entry_point = self._io.read_u8be()
            self._debug['entry_point']['end'] = self._io.pos()
            self._debug['program_header_offset']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.program_header_offset = self._io.read_u4be()
            elif _on == self._root.Bits.b64:
                self.program_header_offset = self._io.read_u8be()
            self._debug['program_header_offset']['end'] = self._io.pos()
            self._debug['section_header_offset']['start'] = self._io.pos()
            _on = self._root.bits
            if _on == self._root.Bits.b32:
                self.section_header_offset = self._io.read_u4be()
            elif _on == self._root.Bits.b64:
                self.section_header_offset = self._io.read_u8be()
            self._debug['section_header_offset']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes(4)
            self._debug['flags']['end'] = self._io.pos()
            self._debug['e_ehsize']['start'] = self._io.pos()
            self.e_ehsize = self._io.read_u2be()
            self._debug['e_ehsize']['end'] = self._io.pos()
            self._debug['program_header_entry_size']['start'] = self._io.pos()
            self.program_header_entry_size = self._io.read_u2be()
            self._debug['program_header_entry_size']['end'] = self._io.pos()
            self._debug['qty_program_header']['start'] = self._io.pos()
            self.qty_program_header = self._io.read_u2be()
            self._debug['qty_program_header']['end'] = self._io.pos()
            self._debug['section_header_entry_size']['start'] = self._io.pos()
            self.section_header_entry_size = self._io.read_u2be()
            self._debug['section_header_entry_size']['end'] = self._io.pos()
            self._debug['qty_section_header']['start'] = self._io.pos()
            self.qty_section_header = self._io.read_u2be()
            self._debug['qty_section_header']['end'] = self._io.pos()
            self._debug['section_names_idx']['start'] = self._io.pos()
            self.section_names_idx = self._io.read_u2be()
            self._debug['section_names_idx']['end'] = self._io.pos()

        class DynsymSectionEntry64(KaitaiStruct):
            SEQ_FIELDS = ["name_offset", "info", "other", "shndx", "value", "size"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['name_offset']['start'] = self._io.pos()
                self.name_offset = self._io.read_u4le()
                self._debug['name_offset']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_u1()
                self._debug['info']['end'] = self._io.pos()
                self._debug['other']['start'] = self._io.pos()
                self.other = self._io.read_u1()
                self._debug['other']['end'] = self._io.pos()
                self._debug['shndx']['start'] = self._io.pos()
                self.shndx = self._io.read_u2le()
                self._debug['shndx']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_u8le()
                self._debug['value']['end'] = self._io.pos()
                self._debug['size']['start'] = self._io.pos()
                self.size = self._io.read_u8le()
                self._debug['size']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['name_offset']['start'] = self._io.pos()
                self.name_offset = self._io.read_u4be()
                self._debug['name_offset']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_u1()
                self._debug['info']['end'] = self._io.pos()
                self._debug['other']['start'] = self._io.pos()
                self.other = self._io.read_u1()
                self._debug['other']['end'] = self._io.pos()
                self._debug['shndx']['start'] = self._io.pos()
                self.shndx = self._io.read_u2be()
                self._debug['shndx']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_u8be()
                self._debug['value']['end'] = self._io.pos()
                self._debug['size']['start'] = self._io.pos()
                self.size = self._io.read_u8be()
                self._debug['size']['end'] = self._io.pos()


        class ProgramHeader(KaitaiStruct):
            SEQ_FIELDS = ["type", "flags64", "offset", "vaddr", "paddr", "filesz", "memsz", "flags32", "align"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.PhType, self._io.read_u4le())
                self._debug['type']['end'] = self._io.pos()
                if self._root.bits == self._root.Bits.b64:
                    self._debug['flags64']['start'] = self._io.pos()
                    self.flags64 = self._io.read_u4le()
                    self._debug['flags64']['end'] = self._io.pos()

                self._debug['offset']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.offset = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.offset = self._io.read_u8le()
                self._debug['offset']['end'] = self._io.pos()
                self._debug['vaddr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.vaddr = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.vaddr = self._io.read_u8le()
                self._debug['vaddr']['end'] = self._io.pos()
                self._debug['paddr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.paddr = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.paddr = self._io.read_u8le()
                self._debug['paddr']['end'] = self._io.pos()
                self._debug['filesz']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.filesz = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.filesz = self._io.read_u8le()
                self._debug['filesz']['end'] = self._io.pos()
                self._debug['memsz']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.memsz = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.memsz = self._io.read_u8le()
                self._debug['memsz']['end'] = self._io.pos()
                if self._root.bits == self._root.Bits.b32:
                    self._debug['flags32']['start'] = self._io.pos()
                    self.flags32 = self._io.read_u4le()
                    self._debug['flags32']['end'] = self._io.pos()

                self._debug['align']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.align = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.align = self._io.read_u8le()
                self._debug['align']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.PhType, self._io.read_u4be())
                self._debug['type']['end'] = self._io.pos()
                if self._root.bits == self._root.Bits.b64:
                    self._debug['flags64']['start'] = self._io.pos()
                    self.flags64 = self._io.read_u4be()
                    self._debug['flags64']['end'] = self._io.pos()

                self._debug['offset']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.offset = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.offset = self._io.read_u8be()
                self._debug['offset']['end'] = self._io.pos()
                self._debug['vaddr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.vaddr = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.vaddr = self._io.read_u8be()
                self._debug['vaddr']['end'] = self._io.pos()
                self._debug['paddr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.paddr = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.paddr = self._io.read_u8be()
                self._debug['paddr']['end'] = self._io.pos()
                self._debug['filesz']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.filesz = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.filesz = self._io.read_u8be()
                self._debug['filesz']['end'] = self._io.pos()
                self._debug['memsz']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.memsz = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.memsz = self._io.read_u8be()
                self._debug['memsz']['end'] = self._io.pos()
                if self._root.bits == self._root.Bits.b32:
                    self._debug['flags32']['start'] = self._io.pos()
                    self.flags32 = self._io.read_u4be()
                    self._debug['flags32']['end'] = self._io.pos()

                self._debug['align']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.align = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.align = self._io.read_u8be()
                self._debug['align']['end'] = self._io.pos()

            @property
            def dynamic(self):
                if hasattr(self, '_m_dynamic'):
                    return self._m_dynamic if hasattr(self, '_m_dynamic') else None

                if self.type == self._root.PhType.dynamic:
                    io = self._root._io
                    _pos = io.pos()
                    io.seek(self.offset)
                    self._debug['_m_dynamic']['start'] = io.pos()
                    if self._is_le:
                        self._raw__m_dynamic = io.read_bytes(self.filesz)
                        io = KaitaiStream(BytesIO(self._raw__m_dynamic))
                        self._m_dynamic = self._root.EndianElf.DynamicSection(io, self, self._root, self._is_le)
                        self._m_dynamic._read()
                    else:
                        self._raw__m_dynamic = io.read_bytes(self.filesz)
                        io = KaitaiStream(BytesIO(self._raw__m_dynamic))
                        self._m_dynamic = self._root.EndianElf.DynamicSection(io, self, self._root, self._is_le)
                        self._m_dynamic._read()
                    self._debug['_m_dynamic']['end'] = io.pos()
                    io.seek(_pos)

                return self._m_dynamic if hasattr(self, '_m_dynamic') else None

            @property
            def flags_obj(self):
                if hasattr(self, '_m_flags_obj'):
                    return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None

                self._debug['_m_flags_obj']['start'] = self._io.pos()
                if self._is_le:
                    self._m_flags_obj = self._root.PhdrTypeFlags((self.flags64 | self.flags32), self._io, self, self._root)
                    self._m_flags_obj._read()
                else:
                    self._m_flags_obj = self._root.PhdrTypeFlags((self.flags64 | self.flags32), self._io, self, self._root)
                    self._m_flags_obj._read()
                self._debug['_m_flags_obj']['end'] = self._io.pos()
                return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None


        class DynamicSectionEntry(KaitaiStruct):
            SEQ_FIELDS = ["tag", "value_or_ptr"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['tag']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.tag = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.tag = self._io.read_u8le()
                self._debug['tag']['end'] = self._io.pos()
                self._debug['value_or_ptr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.value_or_ptr = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.value_or_ptr = self._io.read_u8le()
                self._debug['value_or_ptr']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['tag']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.tag = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.tag = self._io.read_u8be()
                self._debug['tag']['end'] = self._io.pos()
                self._debug['value_or_ptr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.value_or_ptr = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.value_or_ptr = self._io.read_u8be()
                self._debug['value_or_ptr']['end'] = self._io.pos()

            @property
            def tag_enum(self):
                if hasattr(self, '_m_tag_enum'):
                    return self._m_tag_enum if hasattr(self, '_m_tag_enum') else None

                self._m_tag_enum = KaitaiStream.resolve_enum(self._root.DynamicArrayTags, self.tag)
                return self._m_tag_enum if hasattr(self, '_m_tag_enum') else None

            @property
            def flag_1_values(self):
                if hasattr(self, '_m_flag_1_values'):
                    return self._m_flag_1_values if hasattr(self, '_m_flag_1_values') else None

                if self.tag_enum == self._root.DynamicArrayTags.flags_1:
                    self._debug['_m_flag_1_values']['start'] = self._io.pos()
                    if self._is_le:
                        self._m_flag_1_values = self._root.DtFlag1Values(self.value_or_ptr, self._io, self, self._root)
                        self._m_flag_1_values._read()
                    else:
                        self._m_flag_1_values = self._root.DtFlag1Values(self.value_or_ptr, self._io, self, self._root)
                        self._m_flag_1_values._read()
                    self._debug['_m_flag_1_values']['end'] = self._io.pos()

                return self._m_flag_1_values if hasattr(self, '_m_flag_1_values') else None


        class SectionHeader(KaitaiStruct):
            SEQ_FIELDS = ["ofs_name", "type", "flags", "addr", "ofs_body", "len_body", "linked_section_idx", "info", "align", "entry_size"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['ofs_name']['start'] = self._io.pos()
                self.ofs_name = self._io.read_u4le()
                self._debug['ofs_name']['end'] = self._io.pos()
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.ShType, self._io.read_u4le())
                self._debug['type']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.flags = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.flags = self._io.read_u8le()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['addr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.addr = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.addr = self._io.read_u8le()
                self._debug['addr']['end'] = self._io.pos()
                self._debug['ofs_body']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.ofs_body = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.ofs_body = self._io.read_u8le()
                self._debug['ofs_body']['end'] = self._io.pos()
                self._debug['len_body']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.len_body = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.len_body = self._io.read_u8le()
                self._debug['len_body']['end'] = self._io.pos()
                self._debug['linked_section_idx']['start'] = self._io.pos()
                self.linked_section_idx = self._io.read_u4le()
                self._debug['linked_section_idx']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_bytes(4)
                self._debug['info']['end'] = self._io.pos()
                self._debug['align']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.align = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.align = self._io.read_u8le()
                self._debug['align']['end'] = self._io.pos()
                self._debug['entry_size']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.entry_size = self._io.read_u4le()
                elif _on == self._root.Bits.b64:
                    self.entry_size = self._io.read_u8le()
                self._debug['entry_size']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['ofs_name']['start'] = self._io.pos()
                self.ofs_name = self._io.read_u4be()
                self._debug['ofs_name']['end'] = self._io.pos()
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.ShType, self._io.read_u4be())
                self._debug['type']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.flags = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.flags = self._io.read_u8be()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['addr']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.addr = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.addr = self._io.read_u8be()
                self._debug['addr']['end'] = self._io.pos()
                self._debug['ofs_body']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.ofs_body = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.ofs_body = self._io.read_u8be()
                self._debug['ofs_body']['end'] = self._io.pos()
                self._debug['len_body']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.len_body = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.len_body = self._io.read_u8be()
                self._debug['len_body']['end'] = self._io.pos()
                self._debug['linked_section_idx']['start'] = self._io.pos()
                self.linked_section_idx = self._io.read_u4be()
                self._debug['linked_section_idx']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_bytes(4)
                self._debug['info']['end'] = self._io.pos()
                self._debug['align']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.align = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.align = self._io.read_u8be()
                self._debug['align']['end'] = self._io.pos()
                self._debug['entry_size']['start'] = self._io.pos()
                _on = self._root.bits
                if _on == self._root.Bits.b32:
                    self.entry_size = self._io.read_u4be()
                elif _on == self._root.Bits.b64:
                    self.entry_size = self._io.read_u8be()
                self._debug['entry_size']['end'] = self._io.pos()

            @property
            def body(self):
                if hasattr(self, '_m_body'):
                    return self._m_body if hasattr(self, '_m_body') else None

                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_body)
                self._debug['_m_body']['start'] = io.pos()
                if self._is_le:
                    _on = self.type
                    if _on == self._root.ShType.strtab:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynamic:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.DynamicSection(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynsym:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.DynsymSection(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynstr:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                        self._m_body._read()
                    else:
                        self._m_body = io.read_bytes(self.len_body)
                else:
                    _on = self.type
                    if _on == self._root.ShType.strtab:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynamic:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.DynamicSection(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynsym:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.DynsymSection(io, self, self._root, self._is_le)
                        self._m_body._read()
                    elif _on == self._root.ShType.dynstr:
                        self._raw__m_body = io.read_bytes(self.len_body)
                        io = KaitaiStream(BytesIO(self._raw__m_body))
                        self._m_body = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                        self._m_body._read()
                    else:
                        self._m_body = io.read_bytes(self.len_body)
                self._debug['_m_body']['end'] = io.pos()
                io.seek(_pos)
                return self._m_body if hasattr(self, '_m_body') else None

            @property
            def name(self):
                if hasattr(self, '_m_name'):
                    return self._m_name if hasattr(self, '_m_name') else None

                io = self._root.header.strings._io
                _pos = io.pos()
                io.seek(self.ofs_name)
                self._debug['_m_name']['start'] = io.pos()
                if self._is_le:
                    self._m_name = (io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
                else:
                    self._m_name = (io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
                self._debug['_m_name']['end'] = io.pos()
                io.seek(_pos)
                return self._m_name if hasattr(self, '_m_name') else None

            @property
            def flags_obj(self):
                if hasattr(self, '_m_flags_obj'):
                    return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None

                self._debug['_m_flags_obj']['start'] = self._io.pos()
                if self._is_le:
                    self._m_flags_obj = self._root.SectionHeaderFlags(self.flags, self._io, self, self._root)
                    self._m_flags_obj._read()
                else:
                    self._m_flags_obj = self._root.SectionHeaderFlags(self.flags, self._io, self, self._root)
                    self._m_flags_obj._read()
                self._debug['_m_flags_obj']['end'] = self._io.pos()
                return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None


        class DynamicSection(KaitaiStruct):
            SEQ_FIELDS = ["entries"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    _t_entries = self._root.EndianElf.DynamicSectionEntry(self._io, self, self._root, self._is_le)
                    _t_entries._read()
                    self.entries.append(_t_entries)
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    _t_entries = self._root.EndianElf.DynamicSectionEntry(self._io, self, self._root, self._is_le)
                    _t_entries._read()
                    self.entries.append(_t_entries)
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()


        class DynsymSection(KaitaiStruct):
            SEQ_FIELDS = ["entries"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    _on = self._root.bits
                    if _on == self._root.Bits.b32:
                        if not 'arr' in self._debug['entries']:
                            self._debug['entries']['arr'] = []
                        self._debug['entries']['arr'].append({'start': self._io.pos()})
                        _t_entries = self._root.EndianElf.DynsymSectionEntry32(self._io, self, self._root, self._is_le)
                        _t_entries._read()
                        self.entries.append(_t_entries)
                        self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    elif _on == self._root.Bits.b64:
                        if not 'arr' in self._debug['entries']:
                            self._debug['entries']['arr'] = []
                        self._debug['entries']['arr'].append({'start': self._io.pos()})
                        _t_entries = self._root.EndianElf.DynsymSectionEntry64(self._io, self, self._root, self._is_le)
                        _t_entries._read()
                        self.entries.append(_t_entries)
                        self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    _on = self._root.bits
                    if _on == self._root.Bits.b32:
                        if not 'arr' in self._debug['entries']:
                            self._debug['entries']['arr'] = []
                        self._debug['entries']['arr'].append({'start': self._io.pos()})
                        _t_entries = self._root.EndianElf.DynsymSectionEntry32(self._io, self, self._root, self._is_le)
                        _t_entries._read()
                        self.entries.append(_t_entries)
                        self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    elif _on == self._root.Bits.b64:
                        if not 'arr' in self._debug['entries']:
                            self._debug['entries']['arr'] = []
                        self._debug['entries']['arr'].append({'start': self._io.pos()})
                        _t_entries = self._root.EndianElf.DynsymSectionEntry64(self._io, self, self._root, self._is_le)
                        _t_entries._read()
                        self.entries.append(_t_entries)
                        self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()


        class DynsymSectionEntry32(KaitaiStruct):
            SEQ_FIELDS = ["name_offset", "value", "size", "info", "other", "shndx"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['name_offset']['start'] = self._io.pos()
                self.name_offset = self._io.read_u4le()
                self._debug['name_offset']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_u4le()
                self._debug['value']['end'] = self._io.pos()
                self._debug['size']['start'] = self._io.pos()
                self.size = self._io.read_u4le()
                self._debug['size']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_u1()
                self._debug['info']['end'] = self._io.pos()
                self._debug['other']['start'] = self._io.pos()
                self.other = self._io.read_u1()
                self._debug['other']['end'] = self._io.pos()
                self._debug['shndx']['start'] = self._io.pos()
                self.shndx = self._io.read_u2le()
                self._debug['shndx']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['name_offset']['start'] = self._io.pos()
                self.name_offset = self._io.read_u4be()
                self._debug['name_offset']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_u4be()
                self._debug['value']['end'] = self._io.pos()
                self._debug['size']['start'] = self._io.pos()
                self.size = self._io.read_u4be()
                self._debug['size']['end'] = self._io.pos()
                self._debug['info']['start'] = self._io.pos()
                self.info = self._io.read_u1()
                self._debug['info']['end'] = self._io.pos()
                self._debug['other']['start'] = self._io.pos()
                self.other = self._io.read_u1()
                self._debug['other']['end'] = self._io.pos()
                self._debug['shndx']['start'] = self._io.pos()
                self.shndx = self._io.read_u2be()
                self._debug['shndx']['end'] = self._io.pos()


        class StringsStruct(KaitaiStruct):
            SEQ_FIELDS = ["entries"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    self.entries.append((self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII"))
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['entries']['start'] = self._io.pos()
                self.entries = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['entries']:
                        self._debug['entries']['arr'] = []
                    self._debug['entries']['arr'].append({'start': self._io.pos()})
                    self.entries.append((self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII"))
                    self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['entries']['end'] = self._io.pos()


        @property
        def program_headers(self):
            if hasattr(self, '_m_program_headers'):
                return self._m_program_headers if hasattr(self, '_m_program_headers') else None

            _pos = self._io.pos()
            self._io.seek(self.program_header_offset)
            self._debug['_m_program_headers']['start'] = self._io.pos()
            if self._is_le:
                self._raw__m_program_headers = [None] * (self.qty_program_header)
                self._m_program_headers = [None] * (self.qty_program_header)
                for i in range(self.qty_program_header):
                    if not 'arr' in self._debug['_m_program_headers']:
                        self._debug['_m_program_headers']['arr'] = []
                    self._debug['_m_program_headers']['arr'].append({'start': self._io.pos()})
                    self._raw__m_program_headers[i] = self._io.read_bytes(self.program_header_entry_size)
                    io = KaitaiStream(BytesIO(self._raw__m_program_headers[i]))
                    _t__m_program_headers = self._root.EndianElf.ProgramHeader(io, self, self._root, self._is_le)
                    _t__m_program_headers._read()
                    self._m_program_headers[i] = _t__m_program_headers
                    self._debug['_m_program_headers']['arr'][i]['end'] = self._io.pos()

            else:
                self._raw__m_program_headers = [None] * (self.qty_program_header)
                self._m_program_headers = [None] * (self.qty_program_header)
                for i in range(self.qty_program_header):
                    if not 'arr' in self._debug['_m_program_headers']:
                        self._debug['_m_program_headers']['arr'] = []
                    self._debug['_m_program_headers']['arr'].append({'start': self._io.pos()})
                    self._raw__m_program_headers[i] = self._io.read_bytes(self.program_header_entry_size)
                    io = KaitaiStream(BytesIO(self._raw__m_program_headers[i]))
                    _t__m_program_headers = self._root.EndianElf.ProgramHeader(io, self, self._root, self._is_le)
                    _t__m_program_headers._read()
                    self._m_program_headers[i] = _t__m_program_headers
                    self._debug['_m_program_headers']['arr'][i]['end'] = self._io.pos()

            self._debug['_m_program_headers']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_program_headers if hasattr(self, '_m_program_headers') else None

        @property
        def section_headers(self):
            if hasattr(self, '_m_section_headers'):
                return self._m_section_headers if hasattr(self, '_m_section_headers') else None

            _pos = self._io.pos()
            self._io.seek(self.section_header_offset)
            self._debug['_m_section_headers']['start'] = self._io.pos()
            if self._is_le:
                self._raw__m_section_headers = [None] * (self.qty_section_header)
                self._m_section_headers = [None] * (self.qty_section_header)
                for i in range(self.qty_section_header):
                    if not 'arr' in self._debug['_m_section_headers']:
                        self._debug['_m_section_headers']['arr'] = []
                    self._debug['_m_section_headers']['arr'].append({'start': self._io.pos()})
                    self._raw__m_section_headers[i] = self._io.read_bytes(self.section_header_entry_size)
                    io = KaitaiStream(BytesIO(self._raw__m_section_headers[i]))
                    _t__m_section_headers = self._root.EndianElf.SectionHeader(io, self, self._root, self._is_le)
                    _t__m_section_headers._read()
                    self._m_section_headers[i] = _t__m_section_headers
                    self._debug['_m_section_headers']['arr'][i]['end'] = self._io.pos()

            else:
                self._raw__m_section_headers = [None] * (self.qty_section_header)
                self._m_section_headers = [None] * (self.qty_section_header)
                for i in range(self.qty_section_header):
                    if not 'arr' in self._debug['_m_section_headers']:
                        self._debug['_m_section_headers']['arr'] = []
                    self._debug['_m_section_headers']['arr'].append({'start': self._io.pos()})
                    self._raw__m_section_headers[i] = self._io.read_bytes(self.section_header_entry_size)
                    io = KaitaiStream(BytesIO(self._raw__m_section_headers[i]))
                    _t__m_section_headers = self._root.EndianElf.SectionHeader(io, self, self._root, self._is_le)
                    _t__m_section_headers._read()
                    self._m_section_headers[i] = _t__m_section_headers
                    self._debug['_m_section_headers']['arr'][i]['end'] = self._io.pos()

            self._debug['_m_section_headers']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_section_headers if hasattr(self, '_m_section_headers') else None

        @property
        def strings(self):
            if hasattr(self, '_m_strings'):
                return self._m_strings if hasattr(self, '_m_strings') else None

            _pos = self._io.pos()
            self._io.seek(self.section_headers[self.section_names_idx].ofs_body)
            self._debug['_m_strings']['start'] = self._io.pos()
            if self._is_le:
                self._raw__m_strings = self._io.read_bytes(self.section_headers[self.section_names_idx].len_body)
                io = KaitaiStream(BytesIO(self._raw__m_strings))
                self._m_strings = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                self._m_strings._read()
            else:
                self._raw__m_strings = self._io.read_bytes(self.section_headers[self.section_names_idx].len_body)
                io = KaitaiStream(BytesIO(self._raw__m_strings))
                self._m_strings = self._root.EndianElf.StringsStruct(io, self, self._root, self._is_le)
                self._m_strings._read()
            self._debug['_m_strings']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_strings if hasattr(self, '_m_strings') else None



