# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MachO(KaitaiStruct):

    class MagicType(Enum):
        fat_le = 3199925962
        fat_be = 3405691582
        macho_le_x86 = 3472551422
        macho_le_x64 = 3489328638
        macho_be_x86 = 4277009102
        macho_be_x64 = 4277009103

    class CpuType(Enum):
        vax = 1
        romp = 2
        ns32032 = 4
        ns32332 = 5
        i386 = 7
        mips = 8
        ns32532 = 9
        hppa = 11
        arm = 12
        mc88000 = 13
        sparc = 14
        i860 = 15
        i860_little = 16
        rs6000 = 17
        powerpc = 18
        abi64 = 16777216
        x86_64 = 16777223
        arm64 = 16777228
        powerpc64 = 16777234
        any = 4294967295

    class FileType(Enum):
        object = 1
        execute = 2
        fvmlib = 3
        core = 4
        preload = 5
        dylib = 6
        dylinker = 7
        bundle = 8
        dylib_stub = 9
        dsym = 10
        kext_bundle = 11

    class LoadCommandType(Enum):
        segment = 1
        symtab = 2
        symseg = 3
        thread = 4
        unix_thread = 5
        load_fvm_lib = 6
        id_fvm_lib = 7
        ident = 8
        fvm_file = 9
        prepage = 10
        dysymtab = 11
        load_dylib = 12
        id_dylib = 13
        load_dylinker = 14
        id_dylinker = 15
        prebound_dylib = 16
        routines = 17
        sub_framework = 18
        sub_umbrella = 19
        sub_client = 20
        sub_library = 21
        twolevel_hints = 22
        prebind_cksum = 23
        segment_64 = 25
        routines_64 = 26
        uuid = 27
        code_signature = 29
        segment_split_info = 30
        lazy_load_dylib = 32
        encryption_info = 33
        dyld_info = 34
        version_min_macosx = 36
        version_min_iphoneos = 37
        function_starts = 38
        dyld_environment = 39
        data_in_code = 41
        source_version = 42
        dylib_code_sign_drs = 43
        encryption_info_64 = 44
        linker_option = 45
        linker_optimization_hint = 46
        version_min_tvos = 47
        version_min_watchos = 48
        req_dyld = 2147483648
        load_weak_dylib = 2147483672
        rpath = 2147483676
        reexport_dylib = 2147483679
        dyld_info_only = 2147483682
        load_upward_dylib = 2147483683
        main = 2147483688
    SEQ_FIELDS = ["magic", "header", "load_commands"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = KaitaiStream.resolve_enum(self._root.MagicType, self._io.read_u4be())
        self._debug['magic']['end'] = self._io.pos()
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.MachHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['load_commands']['start'] = self._io.pos()
        self.load_commands = [None] * (self.header.ncmds)
        for i in range(self.header.ncmds):
            if not 'arr' in self._debug['load_commands']:
                self._debug['load_commands']['arr'] = []
            self._debug['load_commands']['arr'].append({'start': self._io.pos()})
            _t_load_commands = self._root.LoadCommand(self._io, self, self._root)
            _t_load_commands._read()
            self.load_commands[i] = _t_load_commands
            self._debug['load_commands']['arr'][i]['end'] = self._io.pos()

        self._debug['load_commands']['end'] = self._io.pos()

    class RpathCommand(KaitaiStruct):
        SEQ_FIELDS = ["path_offset", "path"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['path_offset']['start'] = self._io.pos()
            self.path_offset = self._io.read_u4le()
            self._debug['path_offset']['end'] = self._io.pos()
            self._debug['path']['start'] = self._io.pos()
            self.path = (self._io.read_bytes_term(0, False, True, True)).decode(u"utf-8")
            self._debug['path']['end'] = self._io.pos()


    class Uleb128(KaitaiStruct):
        SEQ_FIELDS = ["b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['b1']['start'] = self._io.pos()
            self.b1 = self._io.read_u1()
            self._debug['b1']['end'] = self._io.pos()
            if (self.b1 & 128) != 0:
                self._debug['b2']['start'] = self._io.pos()
                self.b2 = self._io.read_u1()
                self._debug['b2']['end'] = self._io.pos()

            if (self.b2 & 128) != 0:
                self._debug['b3']['start'] = self._io.pos()
                self.b3 = self._io.read_u1()
                self._debug['b3']['end'] = self._io.pos()

            if (self.b3 & 128) != 0:
                self._debug['b4']['start'] = self._io.pos()
                self.b4 = self._io.read_u1()
                self._debug['b4']['end'] = self._io.pos()

            if (self.b4 & 128) != 0:
                self._debug['b5']['start'] = self._io.pos()
                self.b5 = self._io.read_u1()
                self._debug['b5']['end'] = self._io.pos()

            if (self.b5 & 128) != 0:
                self._debug['b6']['start'] = self._io.pos()
                self.b6 = self._io.read_u1()
                self._debug['b6']['end'] = self._io.pos()

            if (self.b6 & 128) != 0:
                self._debug['b7']['start'] = self._io.pos()
                self.b7 = self._io.read_u1()
                self._debug['b7']['end'] = self._io.pos()

            if (self.b7 & 128) != 0:
                self._debug['b8']['start'] = self._io.pos()
                self.b8 = self._io.read_u1()
                self._debug['b8']['end'] = self._io.pos()

            if (self.b8 & 128) != 0:
                self._debug['b9']['start'] = self._io.pos()
                self.b9 = self._io.read_u1()
                self._debug['b9']['end'] = self._io.pos()

            if (self.b9 & 128) != 0:
                self._debug['b10']['start'] = self._io.pos()
                self.b10 = self._io.read_u1()
                self._debug['b10']['end'] = self._io.pos()


        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = (((self.b1 % 128) << 0) + (0 if (self.b1 & 128) == 0 else (((self.b2 % 128) << 7) + (0 if (self.b2 & 128) == 0 else (((self.b3 % 128) << 14) + (0 if (self.b3 & 128) == 0 else (((self.b4 % 128) << 21) + (0 if (self.b4 & 128) == 0 else (((self.b5 % 128) << 28) + (0 if (self.b5 & 128) == 0 else (((self.b6 % 128) << 35) + (0 if (self.b6 & 128) == 0 else (((self.b7 % 128) << 42) + (0 if (self.b7 & 128) == 0 else (((self.b8 % 128) << 49) + (0 if (self.b8 & 128) == 0 else (((self.b9 % 128) << 56) + (0 if (self.b8 & 128) == 0 else ((self.b10 % 128) << 63)))))))))))))))))))
            return self._m_value if hasattr(self, '_m_value') else None


    class SourceVersionCommand(KaitaiStruct):
        SEQ_FIELDS = ["version"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u8le()
            self._debug['version']['end'] = self._io.pos()


    class CsBlob(KaitaiStruct):

        class CsMagic(Enum):
            blob_wrapper = 4208855809
            requirement = 4208856064
            requirements = 4208856065
            code_directory = 4208856066
            embedded_signature = 4208856256
            detached_signature = 4208856257
            entitlement = 4208882033
        SEQ_FIELDS = ["magic", "length", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = KaitaiStream.resolve_enum(self._root.CsBlob.CsMagic, self._io.read_u4be())
            self._debug['magic']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u4be()
            self._debug['length']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.magic
            if _on == self._root.CsBlob.CsMagic.requirement:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.Requirement(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.code_directory:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.CodeDirectory(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.entitlement:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.Entitlement(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.requirements:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.Requirements(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.blob_wrapper:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.BlobWrapper(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.embedded_signature:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.SuperBlob(io, self, self._root)
                self.body._read()
            elif _on == self._root.CsBlob.CsMagic.detached_signature:
                self._raw_body = self._io.read_bytes((self.length - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CsBlob.SuperBlob(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes((self.length - 8))
            self._debug['body']['end'] = self._io.pos()

        class Entitlement(KaitaiStruct):
            SEQ_FIELDS = ["data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['data']['start'] = self._io.pos()
                self.data = self._io.read_bytes_full()
                self._debug['data']['end'] = self._io.pos()


        class CodeDirectory(KaitaiStruct):
            SEQ_FIELDS = ["version", "flags", "hash_offset", "ident_offset", "n_special_slots", "n_code_slots", "code_limit", "hash_size", "hash_type", "spare1", "page_size", "spare2", "scatter_offset", "team_id_offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['version']['start'] = self._io.pos()
                self.version = self._io.read_u4be()
                self._debug['version']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._io.read_u4be()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['hash_offset']['start'] = self._io.pos()
                self.hash_offset = self._io.read_u4be()
                self._debug['hash_offset']['end'] = self._io.pos()
                self._debug['ident_offset']['start'] = self._io.pos()
                self.ident_offset = self._io.read_u4be()
                self._debug['ident_offset']['end'] = self._io.pos()
                self._debug['n_special_slots']['start'] = self._io.pos()
                self.n_special_slots = self._io.read_u4be()
                self._debug['n_special_slots']['end'] = self._io.pos()
                self._debug['n_code_slots']['start'] = self._io.pos()
                self.n_code_slots = self._io.read_u4be()
                self._debug['n_code_slots']['end'] = self._io.pos()
                self._debug['code_limit']['start'] = self._io.pos()
                self.code_limit = self._io.read_u4be()
                self._debug['code_limit']['end'] = self._io.pos()
                self._debug['hash_size']['start'] = self._io.pos()
                self.hash_size = self._io.read_u1()
                self._debug['hash_size']['end'] = self._io.pos()
                self._debug['hash_type']['start'] = self._io.pos()
                self.hash_type = self._io.read_u1()
                self._debug['hash_type']['end'] = self._io.pos()
                self._debug['spare1']['start'] = self._io.pos()
                self.spare1 = self._io.read_u1()
                self._debug['spare1']['end'] = self._io.pos()
                self._debug['page_size']['start'] = self._io.pos()
                self.page_size = self._io.read_u1()
                self._debug['page_size']['end'] = self._io.pos()
                self._debug['spare2']['start'] = self._io.pos()
                self.spare2 = self._io.read_u4be()
                self._debug['spare2']['end'] = self._io.pos()
                if self.version >= 131328:
                    self._debug['scatter_offset']['start'] = self._io.pos()
                    self.scatter_offset = self._io.read_u4be()
                    self._debug['scatter_offset']['end'] = self._io.pos()

                if self.version >= 131584:
                    self._debug['team_id_offset']['start'] = self._io.pos()
                    self.team_id_offset = self._io.read_u4be()
                    self._debug['team_id_offset']['end'] = self._io.pos()


            @property
            def ident(self):
                if hasattr(self, '_m_ident'):
                    return self._m_ident if hasattr(self, '_m_ident') else None

                _pos = self._io.pos()
                self._io.seek((self.ident_offset - 8))
                self._debug['_m_ident']['start'] = self._io.pos()
                self._m_ident = (self._io.read_bytes_term(0, False, True, True)).decode(u"utf-8")
                self._debug['_m_ident']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_ident if hasattr(self, '_m_ident') else None

            @property
            def team_id(self):
                if hasattr(self, '_m_team_id'):
                    return self._m_team_id if hasattr(self, '_m_team_id') else None

                _pos = self._io.pos()
                self._io.seek((self.team_id_offset - 8))
                self._debug['_m_team_id']['start'] = self._io.pos()
                self._m_team_id = (self._io.read_bytes_term(0, False, True, True)).decode(u"utf-8")
                self._debug['_m_team_id']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_team_id if hasattr(self, '_m_team_id') else None

            @property
            def hashes(self):
                if hasattr(self, '_m_hashes'):
                    return self._m_hashes if hasattr(self, '_m_hashes') else None

                _pos = self._io.pos()
                self._io.seek(((self.hash_offset - 8) - (self.hash_size * self.n_special_slots)))
                self._debug['_m_hashes']['start'] = self._io.pos()
                self._m_hashes = [None] * ((self.n_special_slots + self.n_code_slots))
                for i in range((self.n_special_slots + self.n_code_slots)):
                    if not 'arr' in self._debug['_m_hashes']:
                        self._debug['_m_hashes']['arr'] = []
                    self._debug['_m_hashes']['arr'].append({'start': self._io.pos()})
                    self._m_hashes[i] = self._io.read_bytes(self.hash_size)
                    self._debug['_m_hashes']['arr'][i]['end'] = self._io.pos()

                self._debug['_m_hashes']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_hashes if hasattr(self, '_m_hashes') else None


        class Data(KaitaiStruct):
            SEQ_FIELDS = ["length", "value", "padding"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['length']['start'] = self._io.pos()
                self.length = self._io.read_u4be()
                self._debug['length']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_bytes(self.length)
                self._debug['value']['end'] = self._io.pos()
                self._debug['padding']['start'] = self._io.pos()
                self.padding = self._io.read_bytes((4 - (self.length & 3)))
                self._debug['padding']['end'] = self._io.pos()


        class SuperBlob(KaitaiStruct):
            SEQ_FIELDS = ["count", "blobs"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['count']['start'] = self._io.pos()
                self.count = self._io.read_u4be()
                self._debug['count']['end'] = self._io.pos()
                self._debug['blobs']['start'] = self._io.pos()
                self.blobs = [None] * (self.count)
                for i in range(self.count):
                    if not 'arr' in self._debug['blobs']:
                        self._debug['blobs']['arr'] = []
                    self._debug['blobs']['arr'].append({'start': self._io.pos()})
                    _t_blobs = self._root.CsBlob.BlobIndex(self._io, self, self._root)
                    _t_blobs._read()
                    self.blobs[i] = _t_blobs
                    self._debug['blobs']['arr'][i]['end'] = self._io.pos()

                self._debug['blobs']['end'] = self._io.pos()


        class Expr(KaitaiStruct):

            class OpEnum(Enum):
                false = 0
                true = 1
                ident = 2
                apple_anchor = 3
                anchor_hash = 4
                info_key_value = 5
                and_op = 6
                or_op = 7
                cd_hash = 8
                not_op = 9
                info_key_field = 10
                cert_field = 11
                trusted_cert = 12
                trusted_certs = 13
                cert_generic = 14
                apple_generic_anchor = 15
                entitlement_field = 16

            class CertSlot(Enum):
                left_cert = 0
                anchor_cert = 4294967295
            SEQ_FIELDS = ["op", "data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['op']['start'] = self._io.pos()
                self.op = KaitaiStream.resolve_enum(self._root.CsBlob.Expr.OpEnum, self._io.read_u4be())
                self._debug['op']['end'] = self._io.pos()
                self._debug['data']['start'] = self._io.pos()
                _on = self.op
                if _on == self._root.CsBlob.Expr.OpEnum.ident:
                    self.data = self._root.CsBlob.Expr.IdentExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.or_op:
                    self.data = self._root.CsBlob.Expr.OrExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.info_key_value:
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.anchor_hash:
                    self.data = self._root.CsBlob.Expr.AnchorHashExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.info_key_field:
                    self.data = self._root.CsBlob.Expr.InfoKeyFieldExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.not_op:
                    self.data = self._root.CsBlob.Expr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.entitlement_field:
                    self.data = self._root.CsBlob.Expr.EntitlementFieldExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.trusted_cert:
                    self.data = self._root.CsBlob.Expr.CertSlotExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.and_op:
                    self.data = self._root.CsBlob.Expr.AndExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.cert_generic:
                    self.data = self._root.CsBlob.Expr.CertGenericExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.cert_field:
                    self.data = self._root.CsBlob.Expr.CertFieldExpr(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.cd_hash:
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                elif _on == self._root.CsBlob.Expr.OpEnum.apple_generic_anchor:
                    self.data = self._root.CsBlob.Expr.AppleGenericAnchorExpr(self._io, self, self._root)
                    self.data._read()
                self._debug['data']['end'] = self._io.pos()

            class InfoKeyFieldExpr(KaitaiStruct):
                SEQ_FIELDS = ["data", "match"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()
                    self._debug['match']['start'] = self._io.pos()
                    self.match = self._root.CsBlob.Match(self._io, self, self._root)
                    self.match._read()
                    self._debug['match']['end'] = self._io.pos()


            class CertSlotExpr(KaitaiStruct):
                SEQ_FIELDS = ["value"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['value']['start'] = self._io.pos()
                    self.value = KaitaiStream.resolve_enum(self._root.CsBlob.Expr.CertSlot, self._io.read_u4be())
                    self._debug['value']['end'] = self._io.pos()


            class CertGenericExpr(KaitaiStruct):
                SEQ_FIELDS = ["cert_slot", "data", "match"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['cert_slot']['start'] = self._io.pos()
                    self.cert_slot = KaitaiStream.resolve_enum(self._root.CsBlob.Expr.CertSlot, self._io.read_u4be())
                    self._debug['cert_slot']['end'] = self._io.pos()
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()
                    self._debug['match']['start'] = self._io.pos()
                    self.match = self._root.CsBlob.Match(self._io, self, self._root)
                    self.match._read()
                    self._debug['match']['end'] = self._io.pos()


            class IdentExpr(KaitaiStruct):
                SEQ_FIELDS = ["identifier"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['identifier']['start'] = self._io.pos()
                    self.identifier = self._root.CsBlob.Data(self._io, self, self._root)
                    self.identifier._read()
                    self._debug['identifier']['end'] = self._io.pos()


            class CertFieldExpr(KaitaiStruct):
                SEQ_FIELDS = ["cert_slot", "data", "match"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['cert_slot']['start'] = self._io.pos()
                    self.cert_slot = KaitaiStream.resolve_enum(self._root.CsBlob.Expr.CertSlot, self._io.read_u4be())
                    self._debug['cert_slot']['end'] = self._io.pos()
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()
                    self._debug['match']['start'] = self._io.pos()
                    self.match = self._root.CsBlob.Match(self._io, self, self._root)
                    self.match._read()
                    self._debug['match']['end'] = self._io.pos()


            class AnchorHashExpr(KaitaiStruct):
                SEQ_FIELDS = ["cert_slot", "data"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['cert_slot']['start'] = self._io.pos()
                    self.cert_slot = KaitaiStream.resolve_enum(self._root.CsBlob.Expr.CertSlot, self._io.read_u4be())
                    self._debug['cert_slot']['end'] = self._io.pos()
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()


            class AppleGenericAnchorExpr(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                @property
                def value(self):
                    if hasattr(self, '_m_value'):
                        return self._m_value if hasattr(self, '_m_value') else None

                    self._m_value = u"anchor apple generic"
                    return self._m_value if hasattr(self, '_m_value') else None


            class EntitlementFieldExpr(KaitaiStruct):
                SEQ_FIELDS = ["data", "match"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()
                    self._debug['match']['start'] = self._io.pos()
                    self.match = self._root.CsBlob.Match(self._io, self, self._root)
                    self.match._read()
                    self._debug['match']['end'] = self._io.pos()


            class AndExpr(KaitaiStruct):
                SEQ_FIELDS = ["left", "right"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['left']['start'] = self._io.pos()
                    self.left = self._root.CsBlob.Expr(self._io, self, self._root)
                    self.left._read()
                    self._debug['left']['end'] = self._io.pos()
                    self._debug['right']['start'] = self._io.pos()
                    self.right = self._root.CsBlob.Expr(self._io, self, self._root)
                    self.right._read()
                    self._debug['right']['end'] = self._io.pos()


            class OrExpr(KaitaiStruct):
                SEQ_FIELDS = ["left", "right"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['left']['start'] = self._io.pos()
                    self.left = self._root.CsBlob.Expr(self._io, self, self._root)
                    self.left._read()
                    self._debug['left']['end'] = self._io.pos()
                    self._debug['right']['start'] = self._io.pos()
                    self.right = self._root.CsBlob.Expr(self._io, self, self._root)
                    self.right._read()
                    self._debug['right']['end'] = self._io.pos()



        class BlobIndex(KaitaiStruct):

            class CsslotType(Enum):
                code_directory = 0
                info_slot = 1
                requirements = 2
                resource_dir = 3
                application = 4
                entitlements = 5
                alternate_code_directories = 4096
                signature_slot = 65536
            SEQ_FIELDS = ["type", "offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.CsBlob.BlobIndex.CsslotType, self._io.read_u4be())
                self._debug['type']['end'] = self._io.pos()
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_u4be()
                self._debug['offset']['end'] = self._io.pos()

            @property
            def blob(self):
                if hasattr(self, '_m_blob'):
                    return self._m_blob if hasattr(self, '_m_blob') else None

                io = self._parent._io
                _pos = io.pos()
                io.seek((self.offset - 8))
                self._debug['_m_blob']['start'] = io.pos()
                self._raw__m_blob = io.read_bytes_full()
                io = KaitaiStream(BytesIO(self._raw__m_blob))
                self._m_blob = self._root.CsBlob(io, self, self._root)
                self._m_blob._read()
                self._debug['_m_blob']['end'] = io.pos()
                io.seek(_pos)
                return self._m_blob if hasattr(self, '_m_blob') else None


        class Match(KaitaiStruct):

            class Op(Enum):
                exists = 0
                equal = 1
                contains = 2
                begins_with = 3
                ends_with = 4
                less_than = 5
                greater_than = 6
                less_equal = 7
                greater_equal = 8
            SEQ_FIELDS = ["match_op", "data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['match_op']['start'] = self._io.pos()
                self.match_op = KaitaiStream.resolve_enum(self._root.CsBlob.Match.Op, self._io.read_u4be())
                self._debug['match_op']['end'] = self._io.pos()
                if self.match_op != self._root.CsBlob.Match.Op.exists:
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._root.CsBlob.Data(self._io, self, self._root)
                    self.data._read()
                    self._debug['data']['end'] = self._io.pos()



        class Requirement(KaitaiStruct):
            SEQ_FIELDS = ["kind", "expr"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['kind']['start'] = self._io.pos()
                self.kind = self._io.read_u4be()
                self._debug['kind']['end'] = self._io.pos()
                self._debug['expr']['start'] = self._io.pos()
                self.expr = self._root.CsBlob.Expr(self._io, self, self._root)
                self.expr._read()
                self._debug['expr']['end'] = self._io.pos()


        class Requirements(KaitaiStruct):
            SEQ_FIELDS = ["count", "items"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['count']['start'] = self._io.pos()
                self.count = self._io.read_u4be()
                self._debug['count']['end'] = self._io.pos()
                self._debug['items']['start'] = self._io.pos()
                self.items = [None] * (self.count)
                for i in range(self.count):
                    if not 'arr' in self._debug['items']:
                        self._debug['items']['arr'] = []
                    self._debug['items']['arr'].append({'start': self._io.pos()})
                    _t_items = self._root.CsBlob.RequirementsBlobIndex(self._io, self, self._root)
                    _t_items._read()
                    self.items[i] = _t_items
                    self._debug['items']['arr'][i]['end'] = self._io.pos()

                self._debug['items']['end'] = self._io.pos()


        class BlobWrapper(KaitaiStruct):
            SEQ_FIELDS = ["data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['data']['start'] = self._io.pos()
                self.data = self._io.read_bytes_full()
                self._debug['data']['end'] = self._io.pos()


        class RequirementsBlobIndex(KaitaiStruct):

            class RequirementType(Enum):
                host = 1
                guest = 2
                designated = 3
                library = 4
            SEQ_FIELDS = ["type", "offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['type']['start'] = self._io.pos()
                self.type = KaitaiStream.resolve_enum(self._root.CsBlob.RequirementsBlobIndex.RequirementType, self._io.read_u4be())
                self._debug['type']['end'] = self._io.pos()
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_u4be()
                self._debug['offset']['end'] = self._io.pos()

            @property
            def value(self):
                if hasattr(self, '_m_value'):
                    return self._m_value if hasattr(self, '_m_value') else None

                _pos = self._io.pos()
                self._io.seek((self.offset - 8))
                self._debug['_m_value']['start'] = self._io.pos()
                self._m_value = self._root.CsBlob(self._io, self, self._root)
                self._m_value._read()
                self._debug['_m_value']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_value if hasattr(self, '_m_value') else None



    class RoutinesCommand(KaitaiStruct):
        SEQ_FIELDS = ["init_address", "init_module", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['init_address']['start'] = self._io.pos()
            self.init_address = self._io.read_u4le()
            self._debug['init_address']['end'] = self._io.pos()
            self._debug['init_module']['start'] = self._io.pos()
            self.init_module = self._io.read_u4le()
            self._debug['init_module']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(24)
            self._debug['reserved']['end'] = self._io.pos()


    class MachoFlags(KaitaiStruct):
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
        def subsections_via_symbols(self):
            """safe to divide up the sections into sub-sections via symbols for dead code stripping."""
            if hasattr(self, '_m_subsections_via_symbols'):
                return self._m_subsections_via_symbols if hasattr(self, '_m_subsections_via_symbols') else None

            self._m_subsections_via_symbols = (self.value & 8192) != 0
            return self._m_subsections_via_symbols if hasattr(self, '_m_subsections_via_symbols') else None

        @property
        def dead_strippable_dylib(self):
            if hasattr(self, '_m_dead_strippable_dylib'):
                return self._m_dead_strippable_dylib if hasattr(self, '_m_dead_strippable_dylib') else None

            self._m_dead_strippable_dylib = (self.value & 4194304) != 0
            return self._m_dead_strippable_dylib if hasattr(self, '_m_dead_strippable_dylib') else None

        @property
        def weak_defines(self):
            """the final linked image contains external weak symbols."""
            if hasattr(self, '_m_weak_defines'):
                return self._m_weak_defines if hasattr(self, '_m_weak_defines') else None

            self._m_weak_defines = (self.value & 32768) != 0
            return self._m_weak_defines if hasattr(self, '_m_weak_defines') else None

        @property
        def prebound(self):
            """the file has its dynamic undefined references prebound."""
            if hasattr(self, '_m_prebound'):
                return self._m_prebound if hasattr(self, '_m_prebound') else None

            self._m_prebound = (self.value & 16) != 0
            return self._m_prebound if hasattr(self, '_m_prebound') else None

        @property
        def all_mods_bound(self):
            """indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set."""
            if hasattr(self, '_m_all_mods_bound'):
                return self._m_all_mods_bound if hasattr(self, '_m_all_mods_bound') else None

            self._m_all_mods_bound = (self.value & 4096) != 0
            return self._m_all_mods_bound if hasattr(self, '_m_all_mods_bound') else None

        @property
        def has_tlv_descriptors(self):
            if hasattr(self, '_m_has_tlv_descriptors'):
                return self._m_has_tlv_descriptors if hasattr(self, '_m_has_tlv_descriptors') else None

            self._m_has_tlv_descriptors = (self.value & 8388608) != 0
            return self._m_has_tlv_descriptors if hasattr(self, '_m_has_tlv_descriptors') else None

        @property
        def force_flat(self):
            """the executable is forcing all images to use flat name space bindings."""
            if hasattr(self, '_m_force_flat'):
                return self._m_force_flat if hasattr(self, '_m_force_flat') else None

            self._m_force_flat = (self.value & 256) != 0
            return self._m_force_flat if hasattr(self, '_m_force_flat') else None

        @property
        def root_safe(self):
            """When this bit is set, the binary declares it is safe for use in processes with uid zero."""
            if hasattr(self, '_m_root_safe'):
                return self._m_root_safe if hasattr(self, '_m_root_safe') else None

            self._m_root_safe = (self.value & 262144) != 0
            return self._m_root_safe if hasattr(self, '_m_root_safe') else None

        @property
        def no_undefs(self):
            """the object file has no undefined references."""
            if hasattr(self, '_m_no_undefs'):
                return self._m_no_undefs if hasattr(self, '_m_no_undefs') else None

            self._m_no_undefs = (self.value & 1) != 0
            return self._m_no_undefs if hasattr(self, '_m_no_undefs') else None

        @property
        def setuid_safe(self):
            """When this bit is set, the binary declares it is safe for use in processes when issetugid() is true."""
            if hasattr(self, '_m_setuid_safe'):
                return self._m_setuid_safe if hasattr(self, '_m_setuid_safe') else None

            self._m_setuid_safe = (self.value & 524288) != 0
            return self._m_setuid_safe if hasattr(self, '_m_setuid_safe') else None

        @property
        def no_heap_execution(self):
            if hasattr(self, '_m_no_heap_execution'):
                return self._m_no_heap_execution if hasattr(self, '_m_no_heap_execution') else None

            self._m_no_heap_execution = (self.value & 16777216) != 0
            return self._m_no_heap_execution if hasattr(self, '_m_no_heap_execution') else None

        @property
        def no_reexported_dylibs(self):
            """When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported."""
            if hasattr(self, '_m_no_reexported_dylibs'):
                return self._m_no_reexported_dylibs if hasattr(self, '_m_no_reexported_dylibs') else None

            self._m_no_reexported_dylibs = (self.value & 1048576) != 0
            return self._m_no_reexported_dylibs if hasattr(self, '_m_no_reexported_dylibs') else None

        @property
        def no_multi_defs(self):
            """this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used."""
            if hasattr(self, '_m_no_multi_defs'):
                return self._m_no_multi_defs if hasattr(self, '_m_no_multi_defs') else None

            self._m_no_multi_defs = (self.value & 512) != 0
            return self._m_no_multi_defs if hasattr(self, '_m_no_multi_defs') else None

        @property
        def app_extension_safe(self):
            if hasattr(self, '_m_app_extension_safe'):
                return self._m_app_extension_safe if hasattr(self, '_m_app_extension_safe') else None

            self._m_app_extension_safe = (self.value & 33554432) != 0
            return self._m_app_extension_safe if hasattr(self, '_m_app_extension_safe') else None

        @property
        def prebindable(self):
            """the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set."""
            if hasattr(self, '_m_prebindable'):
                return self._m_prebindable if hasattr(self, '_m_prebindable') else None

            self._m_prebindable = (self.value & 2048) != 0
            return self._m_prebindable if hasattr(self, '_m_prebindable') else None

        @property
        def incr_link(self):
            """the object file is the output of an incremental link against a base file and can't be link edited again."""
            if hasattr(self, '_m_incr_link'):
                return self._m_incr_link if hasattr(self, '_m_incr_link') else None

            self._m_incr_link = (self.value & 2) != 0
            return self._m_incr_link if hasattr(self, '_m_incr_link') else None

        @property
        def bind_at_load(self):
            """the object file's undefined references are bound by the dynamic linker when loaded."""
            if hasattr(self, '_m_bind_at_load'):
                return self._m_bind_at_load if hasattr(self, '_m_bind_at_load') else None

            self._m_bind_at_load = (self.value & 8) != 0
            return self._m_bind_at_load if hasattr(self, '_m_bind_at_load') else None

        @property
        def canonical(self):
            """the binary has been canonicalized via the unprebind operation."""
            if hasattr(self, '_m_canonical'):
                return self._m_canonical if hasattr(self, '_m_canonical') else None

            self._m_canonical = (self.value & 16384) != 0
            return self._m_canonical if hasattr(self, '_m_canonical') else None

        @property
        def two_level(self):
            """the image is using two-level name space bindings."""
            if hasattr(self, '_m_two_level'):
                return self._m_two_level if hasattr(self, '_m_two_level') else None

            self._m_two_level = (self.value & 128) != 0
            return self._m_two_level if hasattr(self, '_m_two_level') else None

        @property
        def split_segs(self):
            """the file has its read-only and read-write segments split."""
            if hasattr(self, '_m_split_segs'):
                return self._m_split_segs if hasattr(self, '_m_split_segs') else None

            self._m_split_segs = (self.value & 32) != 0
            return self._m_split_segs if hasattr(self, '_m_split_segs') else None

        @property
        def lazy_init(self):
            """the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)."""
            if hasattr(self, '_m_lazy_init'):
                return self._m_lazy_init if hasattr(self, '_m_lazy_init') else None

            self._m_lazy_init = (self.value & 64) != 0
            return self._m_lazy_init if hasattr(self, '_m_lazy_init') else None

        @property
        def allow_stack_execution(self):
            """When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes."""
            if hasattr(self, '_m_allow_stack_execution'):
                return self._m_allow_stack_execution if hasattr(self, '_m_allow_stack_execution') else None

            self._m_allow_stack_execution = (self.value & 131072) != 0
            return self._m_allow_stack_execution if hasattr(self, '_m_allow_stack_execution') else None

        @property
        def binds_to_weak(self):
            """the final linked image uses weak symbols."""
            if hasattr(self, '_m_binds_to_weak'):
                return self._m_binds_to_weak if hasattr(self, '_m_binds_to_weak') else None

            self._m_binds_to_weak = (self.value & 65536) != 0
            return self._m_binds_to_weak if hasattr(self, '_m_binds_to_weak') else None

        @property
        def no_fix_prebinding(self):
            """do not have dyld notify the prebinding agent about this executable."""
            if hasattr(self, '_m_no_fix_prebinding'):
                return self._m_no_fix_prebinding if hasattr(self, '_m_no_fix_prebinding') else None

            self._m_no_fix_prebinding = (self.value & 1024) != 0
            return self._m_no_fix_prebinding if hasattr(self, '_m_no_fix_prebinding') else None

        @property
        def dyld_link(self):
            """the object file is input for the dynamic linker and can't be staticly link edited again."""
            if hasattr(self, '_m_dyld_link'):
                return self._m_dyld_link if hasattr(self, '_m_dyld_link') else None

            self._m_dyld_link = (self.value & 4) != 0
            return self._m_dyld_link if hasattr(self, '_m_dyld_link') else None

        @property
        def pie(self):
            """When this bit is set, the OS will load the main executable at a random address. Only used in MH_EXECUTE filetypes."""
            if hasattr(self, '_m_pie'):
                return self._m_pie if hasattr(self, '_m_pie') else None

            self._m_pie = (self.value & 2097152) != 0
            return self._m_pie if hasattr(self, '_m_pie') else None


    class RoutinesCommand64(KaitaiStruct):
        SEQ_FIELDS = ["init_address", "init_module", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['init_address']['start'] = self._io.pos()
            self.init_address = self._io.read_u8le()
            self._debug['init_address']['end'] = self._io.pos()
            self._debug['init_module']['start'] = self._io.pos()
            self.init_module = self._io.read_u8le()
            self._debug['init_module']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(48)
            self._debug['reserved']['end'] = self._io.pos()


    class LinkerOptionCommand(KaitaiStruct):
        SEQ_FIELDS = ["num_strings", "strings"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_strings']['start'] = self._io.pos()
            self.num_strings = self._io.read_u4le()
            self._debug['num_strings']['end'] = self._io.pos()
            self._debug['strings']['start'] = self._io.pos()
            self.strings = [None] * (self.num_strings)
            for i in range(self.num_strings):
                if not 'arr' in self._debug['strings']:
                    self._debug['strings']['arr'] = []
                self._debug['strings']['arr'].append({'start': self._io.pos()})
                self.strings[i] = (self._io.read_bytes_term(0, False, True, True)).decode(u"utf-8")
                self._debug['strings']['arr'][i]['end'] = self._io.pos()

            self._debug['strings']['end'] = self._io.pos()


    class SegmentCommand64(KaitaiStruct):
        SEQ_FIELDS = ["segname", "vmaddr", "vmsize", "fileoff", "filesize", "maxprot", "initprot", "nsects", "flags", "sections"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['segname']['start'] = self._io.pos()
            self.segname = (KaitaiStream.bytes_strip_right(self._io.read_bytes(16), 0)).decode(u"ascii")
            self._debug['segname']['end'] = self._io.pos()
            self._debug['vmaddr']['start'] = self._io.pos()
            self.vmaddr = self._io.read_u8le()
            self._debug['vmaddr']['end'] = self._io.pos()
            self._debug['vmsize']['start'] = self._io.pos()
            self.vmsize = self._io.read_u8le()
            self._debug['vmsize']['end'] = self._io.pos()
            self._debug['fileoff']['start'] = self._io.pos()
            self.fileoff = self._io.read_u8le()
            self._debug['fileoff']['end'] = self._io.pos()
            self._debug['filesize']['start'] = self._io.pos()
            self.filesize = self._io.read_u8le()
            self._debug['filesize']['end'] = self._io.pos()
            self._debug['maxprot']['start'] = self._io.pos()
            self.maxprot = self._root.VmProt(self._io, self, self._root)
            self.maxprot._read()
            self._debug['maxprot']['end'] = self._io.pos()
            self._debug['initprot']['start'] = self._io.pos()
            self.initprot = self._root.VmProt(self._io, self, self._root)
            self.initprot._read()
            self._debug['initprot']['end'] = self._io.pos()
            self._debug['nsects']['start'] = self._io.pos()
            self.nsects = self._io.read_u4le()
            self._debug['nsects']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['sections']['start'] = self._io.pos()
            self.sections = [None] * (self.nsects)
            for i in range(self.nsects):
                if not 'arr' in self._debug['sections']:
                    self._debug['sections']['arr'] = []
                self._debug['sections']['arr'].append({'start': self._io.pos()})
                _t_sections = self._root.SegmentCommand64.Section64(self._io, self, self._root)
                _t_sections._read()
                self.sections[i] = _t_sections
                self._debug['sections']['arr'][i]['end'] = self._io.pos()

            self._debug['sections']['end'] = self._io.pos()

        class Section64(KaitaiStruct):
            SEQ_FIELDS = ["sect_name", "seg_name", "addr", "size", "offset", "align", "reloff", "nreloc", "flags", "reserved1", "reserved2", "reserved3"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['sect_name']['start'] = self._io.pos()
                self.sect_name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(16), 0)).decode(u"ascii")
                self._debug['sect_name']['end'] = self._io.pos()
                self._debug['seg_name']['start'] = self._io.pos()
                self.seg_name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(16), 0)).decode(u"ascii")
                self._debug['seg_name']['end'] = self._io.pos()
                self._debug['addr']['start'] = self._io.pos()
                self.addr = self._io.read_u8le()
                self._debug['addr']['end'] = self._io.pos()
                self._debug['size']['start'] = self._io.pos()
                self.size = self._io.read_u8le()
                self._debug['size']['end'] = self._io.pos()
                self._debug['offset']['start'] = self._io.pos()
                self.offset = self._io.read_u4le()
                self._debug['offset']['end'] = self._io.pos()
                self._debug['align']['start'] = self._io.pos()
                self.align = self._io.read_u4le()
                self._debug['align']['end'] = self._io.pos()
                self._debug['reloff']['start'] = self._io.pos()
                self.reloff = self._io.read_u4le()
                self._debug['reloff']['end'] = self._io.pos()
                self._debug['nreloc']['start'] = self._io.pos()
                self.nreloc = self._io.read_u4le()
                self._debug['nreloc']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._io.read_u4le()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.read_u4le()
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['reserved2']['start'] = self._io.pos()
                self.reserved2 = self._io.read_u4le()
                self._debug['reserved2']['end'] = self._io.pos()
                self._debug['reserved3']['start'] = self._io.pos()
                self.reserved3 = self._io.read_u4le()
                self._debug['reserved3']['end'] = self._io.pos()

            class CfStringList(KaitaiStruct):
                SEQ_FIELDS = ["items"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['items']['start'] = self._io.pos()
                    self.items = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['items']:
                            self._debug['items']['arr'] = []
                        self._debug['items']['arr'].append({'start': self._io.pos()})
                        _t_items = self._root.SegmentCommand64.Section64.CfString(self._io, self, self._root)
                        _t_items._read()
                        self.items.append(_t_items)
                        self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['items']['end'] = self._io.pos()


            class CfString(KaitaiStruct):
                SEQ_FIELDS = ["isa", "info", "data", "length"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['isa']['start'] = self._io.pos()
                    self.isa = self._io.read_u8le()
                    self._debug['isa']['end'] = self._io.pos()
                    self._debug['info']['start'] = self._io.pos()
                    self.info = self._io.read_u8le()
                    self._debug['info']['end'] = self._io.pos()
                    self._debug['data']['start'] = self._io.pos()
                    self.data = self._io.read_u8le()
                    self._debug['data']['end'] = self._io.pos()
                    self._debug['length']['start'] = self._io.pos()
                    self.length = self._io.read_u8le()
                    self._debug['length']['end'] = self._io.pos()


            class EhFrameItem(KaitaiStruct):
                SEQ_FIELDS = ["length", "length64", "id", "body"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['length']['start'] = self._io.pos()
                    self.length = self._io.read_u4le()
                    self._debug['length']['end'] = self._io.pos()
                    if self.length == 4294967295:
                        self._debug['length64']['start'] = self._io.pos()
                        self.length64 = self._io.read_u8le()
                        self._debug['length64']['end'] = self._io.pos()

                    self._debug['id']['start'] = self._io.pos()
                    self.id = self._io.read_u4le()
                    self._debug['id']['end'] = self._io.pos()
                    if self.length > 0:
                        self._debug['body']['start'] = self._io.pos()
                        _on = self.id
                        if _on == 0:
                            self._raw_body = self._io.read_bytes((self.length - 4))
                            io = KaitaiStream(BytesIO(self._raw_body))
                            self.body = self._root.SegmentCommand64.Section64.EhFrameItem.Cie(io, self, self._root)
                            self.body._read()
                        else:
                            self.body = self._io.read_bytes((self.length - 4))
                        self._debug['body']['end'] = self._io.pos()


                class CharChain(KaitaiStruct):
                    SEQ_FIELDS = ["chr", "next"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['chr']['start'] = self._io.pos()
                        self.chr = self._io.read_u1()
                        self._debug['chr']['end'] = self._io.pos()
                        if self.chr != 0:
                            self._debug['next']['start'] = self._io.pos()
                            self.next = self._root.SegmentCommand64.Section64.EhFrameItem.CharChain(self._io, self, self._root)
                            self.next._read()
                            self._debug['next']['end'] = self._io.pos()



                class Cie(KaitaiStruct):
                    SEQ_FIELDS = ["version", "aug_str", "code_alignment_factor", "data_alignment_factor", "return_address_register", "augmentation"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['version']['start'] = self._io.pos()
                        self.version = self._io.read_u1()
                        self._debug['version']['end'] = self._io.pos()
                        self._debug['aug_str']['start'] = self._io.pos()
                        self.aug_str = self._root.SegmentCommand64.Section64.EhFrameItem.CharChain(self._io, self, self._root)
                        self.aug_str._read()
                        self._debug['aug_str']['end'] = self._io.pos()
                        self._debug['code_alignment_factor']['start'] = self._io.pos()
                        self.code_alignment_factor = self._root.Uleb128(self._io, self, self._root)
                        self.code_alignment_factor._read()
                        self._debug['code_alignment_factor']['end'] = self._io.pos()
                        self._debug['data_alignment_factor']['start'] = self._io.pos()
                        self.data_alignment_factor = self._root.Uleb128(self._io, self, self._root)
                        self.data_alignment_factor._read()
                        self._debug['data_alignment_factor']['end'] = self._io.pos()
                        self._debug['return_address_register']['start'] = self._io.pos()
                        self.return_address_register = self._io.read_u1()
                        self._debug['return_address_register']['end'] = self._io.pos()
                        if self.aug_str.chr == 122:
                            self._debug['augmentation']['start'] = self._io.pos()
                            self.augmentation = self._root.SegmentCommand64.Section64.EhFrameItem.AugmentationEntry(self._io, self, self._root)
                            self.augmentation._read()
                            self._debug['augmentation']['end'] = self._io.pos()



                class AugmentationEntry(KaitaiStruct):
                    SEQ_FIELDS = ["length", "fde_pointer_encoding"]
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        self._debug['length']['start'] = self._io.pos()
                        self.length = self._root.Uleb128(self._io, self, self._root)
                        self.length._read()
                        self._debug['length']['end'] = self._io.pos()
                        if self._parent.aug_str.next.chr == 82:
                            self._debug['fde_pointer_encoding']['start'] = self._io.pos()
                            self.fde_pointer_encoding = self._io.read_u1()
                            self._debug['fde_pointer_encoding']['end'] = self._io.pos()




            class EhFrame(KaitaiStruct):
                SEQ_FIELDS = ["items"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['items']['start'] = self._io.pos()
                    self.items = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['items']:
                            self._debug['items']['arr'] = []
                        self._debug['items']['arr'].append({'start': self._io.pos()})
                        _t_items = self._root.SegmentCommand64.Section64.EhFrameItem(self._io, self, self._root)
                        _t_items._read()
                        self.items.append(_t_items)
                        self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['items']['end'] = self._io.pos()


            class PointerList(KaitaiStruct):
                SEQ_FIELDS = ["items"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['items']['start'] = self._io.pos()
                    self.items = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['items']:
                            self._debug['items']['arr'] = []
                        self._debug['items']['arr'].append({'start': self._io.pos()})
                        self.items.append(self._io.read_u8le())
                        self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['items']['end'] = self._io.pos()


            class StringList(KaitaiStruct):
                SEQ_FIELDS = ["strings"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['strings']['start'] = self._io.pos()
                    self.strings = []
                    i = 0
                    while not self._io.is_eof():
                        if not 'arr' in self._debug['strings']:
                            self._debug['strings']['arr'] = []
                        self._debug['strings']['arr'].append({'start': self._io.pos()})
                        self.strings.append((self._io.read_bytes_term(0, False, True, True)).decode(u"ascii"))
                        self._debug['strings']['arr'][len(self.strings) - 1]['end'] = self._io.pos()
                        i += 1

                    self._debug['strings']['end'] = self._io.pos()


            @property
            def data(self):
                if hasattr(self, '_m_data'):
                    return self._m_data if hasattr(self, '_m_data') else None

                io = self._root._io
                _pos = io.pos()
                io.seek(self.offset)
                self._debug['_m_data']['start'] = io.pos()
                _on = self.sect_name
                if _on == u"__objc_nlclslist":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_methname":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.StringList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__nl_symbol_ptr":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__la_symbol_ptr":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_selrefs":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__cstring":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.StringList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_classlist":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_protolist":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_imageinfo":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_methtype":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.StringList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__cfstring":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.CfStringList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_classrefs":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_protorefs":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_classname":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.StringList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__got":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__eh_frame":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.EhFrame(io, self, self._root)
                    self._m_data._read()
                elif _on == u"__objc_superrefs":
                    self._raw__m_data = io.read_bytes(self.size)
                    io = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = self._root.SegmentCommand64.Section64.PointerList(io, self, self._root)
                    self._m_data._read()
                else:
                    self._m_data = io.read_bytes(self.size)
                self._debug['_m_data']['end'] = io.pos()
                io.seek(_pos)
                return self._m_data if hasattr(self, '_m_data') else None



    class VmProt(KaitaiStruct):
        SEQ_FIELDS = ["strip_read", "is_mask", "reserved0", "copy", "no_change", "execute", "write", "read", "reserved1"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['strip_read']['start'] = self._io.pos()
            self.strip_read = self._io.read_bits_int(1) != 0
            self._debug['strip_read']['end'] = self._io.pos()
            self._debug['is_mask']['start'] = self._io.pos()
            self.is_mask = self._io.read_bits_int(1) != 0
            self._debug['is_mask']['end'] = self._io.pos()
            self._debug['reserved0']['start'] = self._io.pos()
            self.reserved0 = self._io.read_bits_int(1) != 0
            self._debug['reserved0']['end'] = self._io.pos()
            self._debug['copy']['start'] = self._io.pos()
            self.copy = self._io.read_bits_int(1) != 0
            self._debug['copy']['end'] = self._io.pos()
            self._debug['no_change']['start'] = self._io.pos()
            self.no_change = self._io.read_bits_int(1) != 0
            self._debug['no_change']['end'] = self._io.pos()
            self._debug['execute']['start'] = self._io.pos()
            self.execute = self._io.read_bits_int(1) != 0
            self._debug['execute']['end'] = self._io.pos()
            self._debug['write']['start'] = self._io.pos()
            self.write = self._io.read_bits_int(1) != 0
            self._debug['write']['end'] = self._io.pos()
            self._debug['read']['start'] = self._io.pos()
            self.read = self._io.read_bits_int(1) != 0
            self._debug['read']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(24)
            self._debug['reserved1']['end'] = self._io.pos()


    class DysymtabCommand(KaitaiStruct):
        SEQ_FIELDS = ["i_local_sym", "n_local_sym", "i_ext_def_sym", "n_ext_def_sym", "i_undef_sym", "n_undef_sym", "toc_off", "n_toc", "mod_tab_off", "n_mod_tab", "ext_ref_sym_off", "n_ext_ref_syms", "indirect_sym_off", "n_indirect_syms", "ext_rel_off", "n_ext_rel", "loc_rel_off", "n_loc_rel"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['i_local_sym']['start'] = self._io.pos()
            self.i_local_sym = self._io.read_u4le()
            self._debug['i_local_sym']['end'] = self._io.pos()
            self._debug['n_local_sym']['start'] = self._io.pos()
            self.n_local_sym = self._io.read_u4le()
            self._debug['n_local_sym']['end'] = self._io.pos()
            self._debug['i_ext_def_sym']['start'] = self._io.pos()
            self.i_ext_def_sym = self._io.read_u4le()
            self._debug['i_ext_def_sym']['end'] = self._io.pos()
            self._debug['n_ext_def_sym']['start'] = self._io.pos()
            self.n_ext_def_sym = self._io.read_u4le()
            self._debug['n_ext_def_sym']['end'] = self._io.pos()
            self._debug['i_undef_sym']['start'] = self._io.pos()
            self.i_undef_sym = self._io.read_u4le()
            self._debug['i_undef_sym']['end'] = self._io.pos()
            self._debug['n_undef_sym']['start'] = self._io.pos()
            self.n_undef_sym = self._io.read_u4le()
            self._debug['n_undef_sym']['end'] = self._io.pos()
            self._debug['toc_off']['start'] = self._io.pos()
            self.toc_off = self._io.read_u4le()
            self._debug['toc_off']['end'] = self._io.pos()
            self._debug['n_toc']['start'] = self._io.pos()
            self.n_toc = self._io.read_u4le()
            self._debug['n_toc']['end'] = self._io.pos()
            self._debug['mod_tab_off']['start'] = self._io.pos()
            self.mod_tab_off = self._io.read_u4le()
            self._debug['mod_tab_off']['end'] = self._io.pos()
            self._debug['n_mod_tab']['start'] = self._io.pos()
            self.n_mod_tab = self._io.read_u4le()
            self._debug['n_mod_tab']['end'] = self._io.pos()
            self._debug['ext_ref_sym_off']['start'] = self._io.pos()
            self.ext_ref_sym_off = self._io.read_u4le()
            self._debug['ext_ref_sym_off']['end'] = self._io.pos()
            self._debug['n_ext_ref_syms']['start'] = self._io.pos()
            self.n_ext_ref_syms = self._io.read_u4le()
            self._debug['n_ext_ref_syms']['end'] = self._io.pos()
            self._debug['indirect_sym_off']['start'] = self._io.pos()
            self.indirect_sym_off = self._io.read_u4le()
            self._debug['indirect_sym_off']['end'] = self._io.pos()
            self._debug['n_indirect_syms']['start'] = self._io.pos()
            self.n_indirect_syms = self._io.read_u4le()
            self._debug['n_indirect_syms']['end'] = self._io.pos()
            self._debug['ext_rel_off']['start'] = self._io.pos()
            self.ext_rel_off = self._io.read_u4le()
            self._debug['ext_rel_off']['end'] = self._io.pos()
            self._debug['n_ext_rel']['start'] = self._io.pos()
            self.n_ext_rel = self._io.read_u4le()
            self._debug['n_ext_rel']['end'] = self._io.pos()
            self._debug['loc_rel_off']['start'] = self._io.pos()
            self.loc_rel_off = self._io.read_u4le()
            self._debug['loc_rel_off']['end'] = self._io.pos()
            self._debug['n_loc_rel']['start'] = self._io.pos()
            self.n_loc_rel = self._io.read_u4le()
            self._debug['n_loc_rel']['end'] = self._io.pos()

        @property
        def indirect_symbols(self):
            if hasattr(self, '_m_indirect_symbols'):
                return self._m_indirect_symbols if hasattr(self, '_m_indirect_symbols') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.indirect_sym_off)
            self._debug['_m_indirect_symbols']['start'] = io.pos()
            self._m_indirect_symbols = [None] * (self.n_indirect_syms)
            for i in range(self.n_indirect_syms):
                if not 'arr' in self._debug['_m_indirect_symbols']:
                    self._debug['_m_indirect_symbols']['arr'] = []
                self._debug['_m_indirect_symbols']['arr'].append({'start': io.pos()})
                self._m_indirect_symbols[i] = io.read_u4le()
                self._debug['_m_indirect_symbols']['arr'][i]['end'] = io.pos()

            self._debug['_m_indirect_symbols']['end'] = io.pos()
            io.seek(_pos)
            return self._m_indirect_symbols if hasattr(self, '_m_indirect_symbols') else None


    class MachHeader(KaitaiStruct):
        SEQ_FIELDS = ["cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds", "flags", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['cputype']['start'] = self._io.pos()
            self.cputype = KaitaiStream.resolve_enum(self._root.CpuType, self._io.read_u4le())
            self._debug['cputype']['end'] = self._io.pos()
            self._debug['cpusubtype']['start'] = self._io.pos()
            self.cpusubtype = self._io.read_u4le()
            self._debug['cpusubtype']['end'] = self._io.pos()
            self._debug['filetype']['start'] = self._io.pos()
            self.filetype = KaitaiStream.resolve_enum(self._root.FileType, self._io.read_u4le())
            self._debug['filetype']['end'] = self._io.pos()
            self._debug['ncmds']['start'] = self._io.pos()
            self.ncmds = self._io.read_u4le()
            self._debug['ncmds']['end'] = self._io.pos()
            self._debug['sizeofcmds']['start'] = self._io.pos()
            self.sizeofcmds = self._io.read_u4le()
            self._debug['sizeofcmds']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            if  ((self._root.magic == self._root.MagicType.macho_be_x64) or (self._root.magic == self._root.MagicType.macho_le_x64)) :
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_u4le()
                self._debug['reserved']['end'] = self._io.pos()


        @property
        def flags_obj(self):
            if hasattr(self, '_m_flags_obj'):
                return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None

            self._debug['_m_flags_obj']['start'] = self._io.pos()
            self._m_flags_obj = self._root.MachoFlags(self.flags, self._io, self, self._root)
            self._m_flags_obj._read()
            self._debug['_m_flags_obj']['end'] = self._io.pos()
            return self._m_flags_obj if hasattr(self, '_m_flags_obj') else None


    class LinkeditDataCommand(KaitaiStruct):
        SEQ_FIELDS = ["data_off", "data_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['data_off']['start'] = self._io.pos()
            self.data_off = self._io.read_u4le()
            self._debug['data_off']['end'] = self._io.pos()
            self._debug['data_size']['start'] = self._io.pos()
            self.data_size = self._io.read_u4le()
            self._debug['data_size']['end'] = self._io.pos()


    class SubCommand(KaitaiStruct):
        SEQ_FIELDS = ["name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.LcStr(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()


    class TwolevelHintsCommand(KaitaiStruct):
        SEQ_FIELDS = ["offset", "num_hints"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4le()
            self._debug['offset']['end'] = self._io.pos()
            self._debug['num_hints']['start'] = self._io.pos()
            self.num_hints = self._io.read_u4le()
            self._debug['num_hints']['end'] = self._io.pos()


    class Version(KaitaiStruct):
        SEQ_FIELDS = ["p1", "minor", "major", "release"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['p1']['start'] = self._io.pos()
            self.p1 = self._io.read_u1()
            self._debug['p1']['end'] = self._io.pos()
            self._debug['minor']['start'] = self._io.pos()
            self.minor = self._io.read_u1()
            self._debug['minor']['end'] = self._io.pos()
            self._debug['major']['start'] = self._io.pos()
            self.major = self._io.read_u1()
            self._debug['major']['end'] = self._io.pos()
            self._debug['release']['start'] = self._io.pos()
            self.release = self._io.read_u1()
            self._debug['release']['end'] = self._io.pos()


    class EncryptionInfoCommand(KaitaiStruct):
        SEQ_FIELDS = ["cryptoff", "cryptsize", "cryptid", "pad"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['cryptoff']['start'] = self._io.pos()
            self.cryptoff = self._io.read_u4le()
            self._debug['cryptoff']['end'] = self._io.pos()
            self._debug['cryptsize']['start'] = self._io.pos()
            self.cryptsize = self._io.read_u4le()
            self._debug['cryptsize']['end'] = self._io.pos()
            self._debug['cryptid']['start'] = self._io.pos()
            self.cryptid = self._io.read_u4le()
            self._debug['cryptid']['end'] = self._io.pos()
            if  ((self._root.magic == self._root.MagicType.macho_be_x64) or (self._root.magic == self._root.MagicType.macho_le_x64)) :
                self._debug['pad']['start'] = self._io.pos()
                self.pad = self._io.read_u4le()
                self._debug['pad']['end'] = self._io.pos()



    class CodeSignatureCommand(KaitaiStruct):
        SEQ_FIELDS = ["data_off", "data_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['data_off']['start'] = self._io.pos()
            self.data_off = self._io.read_u4le()
            self._debug['data_off']['end'] = self._io.pos()
            self._debug['data_size']['start'] = self._io.pos()
            self.data_size = self._io.read_u4le()
            self._debug['data_size']['end'] = self._io.pos()

        @property
        def code_signature(self):
            if hasattr(self, '_m_code_signature'):
                return self._m_code_signature if hasattr(self, '_m_code_signature') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.data_off)
            self._debug['_m_code_signature']['start'] = io.pos()
            self._raw__m_code_signature = io.read_bytes(self.data_size)
            io = KaitaiStream(BytesIO(self._raw__m_code_signature))
            self._m_code_signature = self._root.CsBlob(io, self, self._root)
            self._m_code_signature._read()
            self._debug['_m_code_signature']['end'] = io.pos()
            io.seek(_pos)
            return self._m_code_signature if hasattr(self, '_m_code_signature') else None


    class DyldInfoCommand(KaitaiStruct):

        class BindOpcode(Enum):
            done = 0
            set_dylib_ordinal_immediate = 16
            set_dylib_ordinal_uleb = 32
            set_dylib_special_immediate = 48
            set_symbol_trailing_flags_immediate = 64
            set_type_immediate = 80
            set_append_sleb = 96
            set_segment_and_offset_uleb = 112
            add_address_uleb = 128
            do_bind = 144
            do_bind_add_address_uleb = 160
            do_bind_add_address_immediate_scaled = 176
            do_bind_uleb_times_skipping_uleb = 192
        SEQ_FIELDS = ["rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off", "weak_bind_size", "lazy_bind_off", "lazy_bind_size", "export_off", "export_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['rebase_off']['start'] = self._io.pos()
            self.rebase_off = self._io.read_u4le()
            self._debug['rebase_off']['end'] = self._io.pos()
            self._debug['rebase_size']['start'] = self._io.pos()
            self.rebase_size = self._io.read_u4le()
            self._debug['rebase_size']['end'] = self._io.pos()
            self._debug['bind_off']['start'] = self._io.pos()
            self.bind_off = self._io.read_u4le()
            self._debug['bind_off']['end'] = self._io.pos()
            self._debug['bind_size']['start'] = self._io.pos()
            self.bind_size = self._io.read_u4le()
            self._debug['bind_size']['end'] = self._io.pos()
            self._debug['weak_bind_off']['start'] = self._io.pos()
            self.weak_bind_off = self._io.read_u4le()
            self._debug['weak_bind_off']['end'] = self._io.pos()
            self._debug['weak_bind_size']['start'] = self._io.pos()
            self.weak_bind_size = self._io.read_u4le()
            self._debug['weak_bind_size']['end'] = self._io.pos()
            self._debug['lazy_bind_off']['start'] = self._io.pos()
            self.lazy_bind_off = self._io.read_u4le()
            self._debug['lazy_bind_off']['end'] = self._io.pos()
            self._debug['lazy_bind_size']['start'] = self._io.pos()
            self.lazy_bind_size = self._io.read_u4le()
            self._debug['lazy_bind_size']['end'] = self._io.pos()
            self._debug['export_off']['start'] = self._io.pos()
            self.export_off = self._io.read_u4le()
            self._debug['export_off']['end'] = self._io.pos()
            self._debug['export_size']['start'] = self._io.pos()
            self.export_size = self._io.read_u4le()
            self._debug['export_size']['end'] = self._io.pos()

        class BindItem(KaitaiStruct):
            SEQ_FIELDS = ["opcode_and_immediate", "uleb", "skip", "symbol"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['opcode_and_immediate']['start'] = self._io.pos()
                self.opcode_and_immediate = self._io.read_u1()
                self._debug['opcode_and_immediate']['end'] = self._io.pos()
                if  ((self.opcode == self._root.DyldInfoCommand.BindOpcode.set_dylib_ordinal_uleb) or (self.opcode == self._root.DyldInfoCommand.BindOpcode.set_append_sleb) or (self.opcode == self._root.DyldInfoCommand.BindOpcode.set_segment_and_offset_uleb) or (self.opcode == self._root.DyldInfoCommand.BindOpcode.add_address_uleb) or (self.opcode == self._root.DyldInfoCommand.BindOpcode.do_bind_add_address_uleb) or (self.opcode == self._root.DyldInfoCommand.BindOpcode.do_bind_uleb_times_skipping_uleb)) :
                    self._debug['uleb']['start'] = self._io.pos()
                    self.uleb = self._root.Uleb128(self._io, self, self._root)
                    self.uleb._read()
                    self._debug['uleb']['end'] = self._io.pos()

                if self.opcode == self._root.DyldInfoCommand.BindOpcode.do_bind_uleb_times_skipping_uleb:
                    self._debug['skip']['start'] = self._io.pos()
                    self.skip = self._root.Uleb128(self._io, self, self._root)
                    self.skip._read()
                    self._debug['skip']['end'] = self._io.pos()

                if self.opcode == self._root.DyldInfoCommand.BindOpcode.set_symbol_trailing_flags_immediate:
                    self._debug['symbol']['start'] = self._io.pos()
                    self.symbol = (self._io.read_bytes_term(0, False, True, True)).decode(u"ascii")
                    self._debug['symbol']['end'] = self._io.pos()


            @property
            def opcode(self):
                if hasattr(self, '_m_opcode'):
                    return self._m_opcode if hasattr(self, '_m_opcode') else None

                self._m_opcode = KaitaiStream.resolve_enum(self._root.DyldInfoCommand.BindOpcode, (self.opcode_and_immediate & 240))
                return self._m_opcode if hasattr(self, '_m_opcode') else None

            @property
            def immediate(self):
                if hasattr(self, '_m_immediate'):
                    return self._m_immediate if hasattr(self, '_m_immediate') else None

                self._m_immediate = (self.opcode_and_immediate & 15)
                return self._m_immediate if hasattr(self, '_m_immediate') else None


        class RebaseData(KaitaiStruct):

            class Opcode(Enum):
                done = 0
                set_type_immediate = 16
                set_segment_and_offset_uleb = 32
                add_address_uleb = 48
                add_address_immediate_scaled = 64
                do_rebase_immediate_times = 80
                do_rebase_uleb_times = 96
                do_rebase_add_address_uleb = 112
                do_rebase_uleb_times_skipping_uleb = 128
            SEQ_FIELDS = ["items"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['items']['start'] = self._io.pos()
                self.items = []
                i = 0
                while True:
                    if not 'arr' in self._debug['items']:
                        self._debug['items']['arr'] = []
                    self._debug['items']['arr'].append({'start': self._io.pos()})
                    _t_items = self._root.DyldInfoCommand.RebaseData.RebaseItem(self._io, self, self._root)
                    _t_items._read()
                    _ = _t_items
                    self.items.append(_)
                    self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                    if _.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.done:
                        break
                    i += 1
                self._debug['items']['end'] = self._io.pos()

            class RebaseItem(KaitaiStruct):
                SEQ_FIELDS = ["opcode_and_immediate", "uleb", "skip"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['opcode_and_immediate']['start'] = self._io.pos()
                    self.opcode_and_immediate = self._io.read_u1()
                    self._debug['opcode_and_immediate']['end'] = self._io.pos()
                    if  ((self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.set_segment_and_offset_uleb) or (self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.add_address_uleb) or (self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.do_rebase_uleb_times) or (self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.do_rebase_add_address_uleb) or (self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.do_rebase_uleb_times_skipping_uleb)) :
                        self._debug['uleb']['start'] = self._io.pos()
                        self.uleb = self._root.Uleb128(self._io, self, self._root)
                        self.uleb._read()
                        self._debug['uleb']['end'] = self._io.pos()

                    if self.opcode == self._root.DyldInfoCommand.RebaseData.Opcode.do_rebase_uleb_times_skipping_uleb:
                        self._debug['skip']['start'] = self._io.pos()
                        self.skip = self._root.Uleb128(self._io, self, self._root)
                        self.skip._read()
                        self._debug['skip']['end'] = self._io.pos()


                @property
                def opcode(self):
                    if hasattr(self, '_m_opcode'):
                        return self._m_opcode if hasattr(self, '_m_opcode') else None

                    self._m_opcode = KaitaiStream.resolve_enum(self._root.DyldInfoCommand.RebaseData.Opcode, (self.opcode_and_immediate & 240))
                    return self._m_opcode if hasattr(self, '_m_opcode') else None

                @property
                def immediate(self):
                    if hasattr(self, '_m_immediate'):
                        return self._m_immediate if hasattr(self, '_m_immediate') else None

                    self._m_immediate = (self.opcode_and_immediate & 15)
                    return self._m_immediate if hasattr(self, '_m_immediate') else None



        class ExportNode(KaitaiStruct):
            SEQ_FIELDS = ["terminal_size", "children_count", "children", "terminal"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['terminal_size']['start'] = self._io.pos()
                self.terminal_size = self._root.Uleb128(self._io, self, self._root)
                self.terminal_size._read()
                self._debug['terminal_size']['end'] = self._io.pos()
                self._debug['children_count']['start'] = self._io.pos()
                self.children_count = self._io.read_u1()
                self._debug['children_count']['end'] = self._io.pos()
                self._debug['children']['start'] = self._io.pos()
                self.children = [None] * (self.children_count)
                for i in range(self.children_count):
                    if not 'arr' in self._debug['children']:
                        self._debug['children']['arr'] = []
                    self._debug['children']['arr'].append({'start': self._io.pos()})
                    _t_children = self._root.DyldInfoCommand.ExportNode.Child(self._io, self, self._root)
                    _t_children._read()
                    self.children[i] = _t_children
                    self._debug['children']['arr'][i]['end'] = self._io.pos()

                self._debug['children']['end'] = self._io.pos()
                self._debug['terminal']['start'] = self._io.pos()
                self.terminal = self._io.read_bytes(self.terminal_size.value)
                self._debug['terminal']['end'] = self._io.pos()

            class Child(KaitaiStruct):
                SEQ_FIELDS = ["name", "node_offset"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['name']['start'] = self._io.pos()
                    self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ascii")
                    self._debug['name']['end'] = self._io.pos()
                    self._debug['node_offset']['start'] = self._io.pos()
                    self.node_offset = self._root.Uleb128(self._io, self, self._root)
                    self.node_offset._read()
                    self._debug['node_offset']['end'] = self._io.pos()

                @property
                def value(self):
                    if hasattr(self, '_m_value'):
                        return self._m_value if hasattr(self, '_m_value') else None

                    _pos = self._io.pos()
                    self._io.seek(self.node_offset.value)
                    self._debug['_m_value']['start'] = self._io.pos()
                    self._m_value = self._root.DyldInfoCommand.ExportNode(self._io, self, self._root)
                    self._m_value._read()
                    self._debug['_m_value']['end'] = self._io.pos()
                    self._io.seek(_pos)
                    return self._m_value if hasattr(self, '_m_value') else None



        class BindData(KaitaiStruct):
            SEQ_FIELDS = ["items"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['items']['start'] = self._io.pos()
                self.items = []
                i = 0
                while True:
                    if not 'arr' in self._debug['items']:
                        self._debug['items']['arr'] = []
                    self._debug['items']['arr'].append({'start': self._io.pos()})
                    _t_items = self._root.DyldInfoCommand.BindItem(self._io, self, self._root)
                    _t_items._read()
                    _ = _t_items
                    self.items.append(_)
                    self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                    if _.opcode == self._root.DyldInfoCommand.BindOpcode.done:
                        break
                    i += 1
                self._debug['items']['end'] = self._io.pos()


        class LazyBindData(KaitaiStruct):
            SEQ_FIELDS = ["items"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['items']['start'] = self._io.pos()
                self.items = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['items']:
                        self._debug['items']['arr'] = []
                    self._debug['items']['arr'].append({'start': self._io.pos()})
                    _t_items = self._root.DyldInfoCommand.BindItem(self._io, self, self._root)
                    _t_items._read()
                    self.items.append(_t_items)
                    self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['items']['end'] = self._io.pos()


        @property
        def rebase(self):
            if hasattr(self, '_m_rebase'):
                return self._m_rebase if hasattr(self, '_m_rebase') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.rebase_off)
            self._debug['_m_rebase']['start'] = io.pos()
            self._raw__m_rebase = io.read_bytes(self.rebase_size)
            io = KaitaiStream(BytesIO(self._raw__m_rebase))
            self._m_rebase = self._root.DyldInfoCommand.RebaseData(io, self, self._root)
            self._m_rebase._read()
            self._debug['_m_rebase']['end'] = io.pos()
            io.seek(_pos)
            return self._m_rebase if hasattr(self, '_m_rebase') else None

        @property
        def bind(self):
            if hasattr(self, '_m_bind'):
                return self._m_bind if hasattr(self, '_m_bind') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.bind_off)
            self._debug['_m_bind']['start'] = io.pos()
            self._raw__m_bind = io.read_bytes(self.bind_size)
            io = KaitaiStream(BytesIO(self._raw__m_bind))
            self._m_bind = self._root.DyldInfoCommand.BindData(io, self, self._root)
            self._m_bind._read()
            self._debug['_m_bind']['end'] = io.pos()
            io.seek(_pos)
            return self._m_bind if hasattr(self, '_m_bind') else None

        @property
        def lazy_bind(self):
            if hasattr(self, '_m_lazy_bind'):
                return self._m_lazy_bind if hasattr(self, '_m_lazy_bind') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.lazy_bind_off)
            self._debug['_m_lazy_bind']['start'] = io.pos()
            self._raw__m_lazy_bind = io.read_bytes(self.lazy_bind_size)
            io = KaitaiStream(BytesIO(self._raw__m_lazy_bind))
            self._m_lazy_bind = self._root.DyldInfoCommand.LazyBindData(io, self, self._root)
            self._m_lazy_bind._read()
            self._debug['_m_lazy_bind']['end'] = io.pos()
            io.seek(_pos)
            return self._m_lazy_bind if hasattr(self, '_m_lazy_bind') else None

        @property
        def exports(self):
            if hasattr(self, '_m_exports'):
                return self._m_exports if hasattr(self, '_m_exports') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.export_off)
            self._debug['_m_exports']['start'] = io.pos()
            self._raw__m_exports = io.read_bytes(self.export_size)
            io = KaitaiStream(BytesIO(self._raw__m_exports))
            self._m_exports = self._root.DyldInfoCommand.ExportNode(io, self, self._root)
            self._m_exports._read()
            self._debug['_m_exports']['end'] = io.pos()
            io.seek(_pos)
            return self._m_exports if hasattr(self, '_m_exports') else None


    class DylinkerCommand(KaitaiStruct):
        SEQ_FIELDS = ["name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.LcStr(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()


    class DylibCommand(KaitaiStruct):
        SEQ_FIELDS = ["name_offset", "timestamp", "current_version", "compatibility_version", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_offset']['start'] = self._io.pos()
            self.name_offset = self._io.read_u4le()
            self._debug['name_offset']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_u4le()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['current_version']['start'] = self._io.pos()
            self.current_version = self._io.read_u4le()
            self._debug['current_version']['end'] = self._io.pos()
            self._debug['compatibility_version']['start'] = self._io.pos()
            self.compatibility_version = self._io.read_u4le()
            self._debug['compatibility_version']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"utf-8")
            self._debug['name']['end'] = self._io.pos()


    class LcStr(KaitaiStruct):
        SEQ_FIELDS = ["length", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u4le()
            self._debug['length']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
            self._debug['value']['end'] = self._io.pos()


    class LoadCommand(KaitaiStruct):
        SEQ_FIELDS = ["type", "size", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.LoadCommandType, self._io.read_u4le())
            self._debug['type']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.type
            if _on == self._root.LoadCommandType.id_dylinker:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylinkerCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.reexport_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.source_version:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SourceVersionCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.function_starts:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkeditDataCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.rpath:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RpathCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.sub_framework:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SubCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.routines:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RoutinesCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.sub_library:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SubCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.dyld_info_only:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DyldInfoCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.dyld_environment:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylinkerCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.load_dylinker:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylinkerCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.segment_split_info:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkeditDataCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.main:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.EntryPointCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.load_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.encryption_info:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.EncryptionInfoCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.dysymtab:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DysymtabCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.twolevel_hints:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.TwolevelHintsCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.encryption_info_64:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.EncryptionInfoCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.linker_option:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkerOptionCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.dyld_info:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DyldInfoCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.version_min_tvos:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.VersionMinCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.load_upward_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.segment_64:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SegmentCommand64(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.sub_umbrella:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SubCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.version_min_watchos:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.VersionMinCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.routines_64:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RoutinesCommand64(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.id_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.sub_client:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SubCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.dylib_code_sign_drs:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkeditDataCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.symtab:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SymtabCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.linker_optimization_hint:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkeditDataCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.data_in_code:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkeditDataCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.code_signature:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CodeSignatureCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.version_min_iphoneos:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.VersionMinCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.load_weak_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.lazy_load_dylib:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.DylibCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.uuid:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.UuidCommand(io, self, self._root)
                self.body._read()
            elif _on == self._root.LoadCommandType.version_min_macosx:
                self._raw_body = self._io.read_bytes((self.size - 8))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.VersionMinCommand(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes((self.size - 8))
            self._debug['body']['end'] = self._io.pos()


    class UuidCommand(KaitaiStruct):
        SEQ_FIELDS = ["uuid"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['uuid']['start'] = self._io.pos()
            self.uuid = self._io.read_bytes(16)
            self._debug['uuid']['end'] = self._io.pos()


    class SymtabCommand(KaitaiStruct):
        SEQ_FIELDS = ["sym_off", "n_syms", "str_off", "str_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sym_off']['start'] = self._io.pos()
            self.sym_off = self._io.read_u4le()
            self._debug['sym_off']['end'] = self._io.pos()
            self._debug['n_syms']['start'] = self._io.pos()
            self.n_syms = self._io.read_u4le()
            self._debug['n_syms']['end'] = self._io.pos()
            self._debug['str_off']['start'] = self._io.pos()
            self.str_off = self._io.read_u4le()
            self._debug['str_off']['end'] = self._io.pos()
            self._debug['str_size']['start'] = self._io.pos()
            self.str_size = self._io.read_u4le()
            self._debug['str_size']['end'] = self._io.pos()

        class StrTable(KaitaiStruct):
            SEQ_FIELDS = ["unknown", "items"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['unknown']['start'] = self._io.pos()
                self.unknown = self._io.read_u4le()
                self._debug['unknown']['end'] = self._io.pos()
                self._debug['items']['start'] = self._io.pos()
                self.items = []
                i = 0
                while True:
                    if not 'arr' in self._debug['items']:
                        self._debug['items']['arr'] = []
                    self._debug['items']['arr'].append({'start': self._io.pos()})
                    _ = (self._io.read_bytes_term(0, False, True, True)).decode(u"ascii")
                    self.items.append(_)
                    self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                    if _ == u"":
                        break
                    i += 1
                self._debug['items']['end'] = self._io.pos()


        class Nlist64(KaitaiStruct):
            SEQ_FIELDS = ["un", "type", "sect", "desc", "value"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['un']['start'] = self._io.pos()
                self.un = self._io.read_u4le()
                self._debug['un']['end'] = self._io.pos()
                self._debug['type']['start'] = self._io.pos()
                self.type = self._io.read_u1()
                self._debug['type']['end'] = self._io.pos()
                self._debug['sect']['start'] = self._io.pos()
                self.sect = self._io.read_u1()
                self._debug['sect']['end'] = self._io.pos()
                self._debug['desc']['start'] = self._io.pos()
                self.desc = self._io.read_u2le()
                self._debug['desc']['end'] = self._io.pos()
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_u8le()
                self._debug['value']['end'] = self._io.pos()


        @property
        def symbols(self):
            if hasattr(self, '_m_symbols'):
                return self._m_symbols if hasattr(self, '_m_symbols') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.sym_off)
            self._debug['_m_symbols']['start'] = io.pos()
            self._m_symbols = [None] * (self.n_syms)
            for i in range(self.n_syms):
                if not 'arr' in self._debug['_m_symbols']:
                    self._debug['_m_symbols']['arr'] = []
                self._debug['_m_symbols']['arr'].append({'start': io.pos()})
                _t__m_symbols = self._root.SymtabCommand.Nlist64(io, self, self._root)
                _t__m_symbols._read()
                self._m_symbols[i] = _t__m_symbols
                self._debug['_m_symbols']['arr'][i]['end'] = io.pos()

            self._debug['_m_symbols']['end'] = io.pos()
            io.seek(_pos)
            return self._m_symbols if hasattr(self, '_m_symbols') else None

        @property
        def strs(self):
            if hasattr(self, '_m_strs'):
                return self._m_strs if hasattr(self, '_m_strs') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.str_off)
            self._debug['_m_strs']['start'] = io.pos()
            self._raw__m_strs = io.read_bytes(self.str_size)
            io = KaitaiStream(BytesIO(self._raw__m_strs))
            self._m_strs = self._root.SymtabCommand.StrTable(io, self, self._root)
            self._m_strs._read()
            self._debug['_m_strs']['end'] = io.pos()
            io.seek(_pos)
            return self._m_strs if hasattr(self, '_m_strs') else None


    class VersionMinCommand(KaitaiStruct):
        SEQ_FIELDS = ["version", "sdk"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Version(self._io, self, self._root)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            self._debug['sdk']['start'] = self._io.pos()
            self.sdk = self._root.Version(self._io, self, self._root)
            self.sdk._read()
            self._debug['sdk']['end'] = self._io.pos()


    class EntryPointCommand(KaitaiStruct):
        SEQ_FIELDS = ["entry_off", "stack_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entry_off']['start'] = self._io.pos()
            self.entry_off = self._io.read_u8le()
            self._debug['entry_off']['end'] = self._io.pos()
            self._debug['stack_size']['start'] = self._io.pos()
            self.stack_size = self._io.read_u8le()
            self._debug['stack_size']['end'] = self._io.pos()



