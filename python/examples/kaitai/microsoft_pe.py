# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MicrosoftPe(KaitaiStruct):
    """
    .. seealso::
       Source - http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
    """

    class PeFormat(Enum):
        rom_image = 263
        pe32 = 267
        pe32_plus = 523
    SEQ_FIELDS = ["mz"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['mz']['start'] = self._io.pos()
        self.mz = self._root.MzPlaceholder(self._io, self, self._root)
        self.mz._read()
        self._debug['mz']['end'] = self._io.pos()

    class CertificateEntry(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-attribute-certificate-table-image-only
        """

        class CertificateRevision(Enum):
            revision_1_0 = 256
            revision_2_0 = 512

        class CertificateType(Enum):
            x509 = 1
            pkcs_signed_data = 2
            reserved_1 = 3
            ts_stack_signed = 4
        SEQ_FIELDS = ["length", "revision", "certificate_type", "certificate_bytes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u4le()
            self._debug['length']['end'] = self._io.pos()
            self._debug['revision']['start'] = self._io.pos()
            self.revision = KaitaiStream.resolve_enum(self._root.CertificateEntry.CertificateRevision, self._io.read_u2le())
            self._debug['revision']['end'] = self._io.pos()
            self._debug['certificate_type']['start'] = self._io.pos()
            self.certificate_type = KaitaiStream.resolve_enum(self._root.CertificateEntry.CertificateType, self._io.read_u2le())
            self._debug['certificate_type']['end'] = self._io.pos()
            self._debug['certificate_bytes']['start'] = self._io.pos()
            self.certificate_bytes = self._io.read_bytes((self.length - 8))
            self._debug['certificate_bytes']['end'] = self._io.pos()


    class OptionalHeaderWindows(KaitaiStruct):

        class SubsystemEnum(Enum):
            unknown = 0
            native = 1
            windows_gui = 2
            windows_cui = 3
            posix_cui = 7
            windows_ce_gui = 9
            efi_application = 10
            efi_boot_service_driver = 11
            efi_runtime_driver = 12
            efi_rom = 13
            xbox = 14
            windows_boot_application = 16
        SEQ_FIELDS = ["image_base_32", "image_base_64", "section_alignment", "file_alignment", "major_operating_system_version", "minor_operating_system_version", "major_image_version", "minor_image_version", "major_subsystem_version", "minor_subsystem_version", "win32_version_value", "size_of_image", "size_of_headers", "check_sum", "subsystem", "dll_characteristics", "size_of_stack_reserve_32", "size_of_stack_reserve_64", "size_of_stack_commit_32", "size_of_stack_commit_64", "size_of_heap_reserve_32", "size_of_heap_reserve_64", "size_of_heap_commit_32", "size_of_heap_commit_64", "loader_flags", "number_of_rva_and_sizes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if self._parent.std.format == self._root.PeFormat.pe32:
                self._debug['image_base_32']['start'] = self._io.pos()
                self.image_base_32 = self._io.read_u4le()
                self._debug['image_base_32']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32_plus:
                self._debug['image_base_64']['start'] = self._io.pos()
                self.image_base_64 = self._io.read_u8le()
                self._debug['image_base_64']['end'] = self._io.pos()

            self._debug['section_alignment']['start'] = self._io.pos()
            self.section_alignment = self._io.read_u4le()
            self._debug['section_alignment']['end'] = self._io.pos()
            self._debug['file_alignment']['start'] = self._io.pos()
            self.file_alignment = self._io.read_u4le()
            self._debug['file_alignment']['end'] = self._io.pos()
            self._debug['major_operating_system_version']['start'] = self._io.pos()
            self.major_operating_system_version = self._io.read_u2le()
            self._debug['major_operating_system_version']['end'] = self._io.pos()
            self._debug['minor_operating_system_version']['start'] = self._io.pos()
            self.minor_operating_system_version = self._io.read_u2le()
            self._debug['minor_operating_system_version']['end'] = self._io.pos()
            self._debug['major_image_version']['start'] = self._io.pos()
            self.major_image_version = self._io.read_u2le()
            self._debug['major_image_version']['end'] = self._io.pos()
            self._debug['minor_image_version']['start'] = self._io.pos()
            self.minor_image_version = self._io.read_u2le()
            self._debug['minor_image_version']['end'] = self._io.pos()
            self._debug['major_subsystem_version']['start'] = self._io.pos()
            self.major_subsystem_version = self._io.read_u2le()
            self._debug['major_subsystem_version']['end'] = self._io.pos()
            self._debug['minor_subsystem_version']['start'] = self._io.pos()
            self.minor_subsystem_version = self._io.read_u2le()
            self._debug['minor_subsystem_version']['end'] = self._io.pos()
            self._debug['win32_version_value']['start'] = self._io.pos()
            self.win32_version_value = self._io.read_u4le()
            self._debug['win32_version_value']['end'] = self._io.pos()
            self._debug['size_of_image']['start'] = self._io.pos()
            self.size_of_image = self._io.read_u4le()
            self._debug['size_of_image']['end'] = self._io.pos()
            self._debug['size_of_headers']['start'] = self._io.pos()
            self.size_of_headers = self._io.read_u4le()
            self._debug['size_of_headers']['end'] = self._io.pos()
            self._debug['check_sum']['start'] = self._io.pos()
            self.check_sum = self._io.read_u4le()
            self._debug['check_sum']['end'] = self._io.pos()
            self._debug['subsystem']['start'] = self._io.pos()
            self.subsystem = KaitaiStream.resolve_enum(self._root.OptionalHeaderWindows.SubsystemEnum, self._io.read_u2le())
            self._debug['subsystem']['end'] = self._io.pos()
            self._debug['dll_characteristics']['start'] = self._io.pos()
            self.dll_characteristics = self._io.read_u2le()
            self._debug['dll_characteristics']['end'] = self._io.pos()
            if self._parent.std.format == self._root.PeFormat.pe32:
                self._debug['size_of_stack_reserve_32']['start'] = self._io.pos()
                self.size_of_stack_reserve_32 = self._io.read_u4le()
                self._debug['size_of_stack_reserve_32']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32_plus:
                self._debug['size_of_stack_reserve_64']['start'] = self._io.pos()
                self.size_of_stack_reserve_64 = self._io.read_u8le()
                self._debug['size_of_stack_reserve_64']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32:
                self._debug['size_of_stack_commit_32']['start'] = self._io.pos()
                self.size_of_stack_commit_32 = self._io.read_u4le()
                self._debug['size_of_stack_commit_32']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32_plus:
                self._debug['size_of_stack_commit_64']['start'] = self._io.pos()
                self.size_of_stack_commit_64 = self._io.read_u8le()
                self._debug['size_of_stack_commit_64']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32:
                self._debug['size_of_heap_reserve_32']['start'] = self._io.pos()
                self.size_of_heap_reserve_32 = self._io.read_u4le()
                self._debug['size_of_heap_reserve_32']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32_plus:
                self._debug['size_of_heap_reserve_64']['start'] = self._io.pos()
                self.size_of_heap_reserve_64 = self._io.read_u8le()
                self._debug['size_of_heap_reserve_64']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32:
                self._debug['size_of_heap_commit_32']['start'] = self._io.pos()
                self.size_of_heap_commit_32 = self._io.read_u4le()
                self._debug['size_of_heap_commit_32']['end'] = self._io.pos()

            if self._parent.std.format == self._root.PeFormat.pe32_plus:
                self._debug['size_of_heap_commit_64']['start'] = self._io.pos()
                self.size_of_heap_commit_64 = self._io.read_u8le()
                self._debug['size_of_heap_commit_64']['end'] = self._io.pos()

            self._debug['loader_flags']['start'] = self._io.pos()
            self.loader_flags = self._io.read_u4le()
            self._debug['loader_flags']['end'] = self._io.pos()
            self._debug['number_of_rva_and_sizes']['start'] = self._io.pos()
            self.number_of_rva_and_sizes = self._io.read_u4le()
            self._debug['number_of_rva_and_sizes']['end'] = self._io.pos()


    class OptionalHeaderDataDirs(KaitaiStruct):
        SEQ_FIELDS = ["export_table", "import_table", "resource_table", "exception_table", "certificate_table", "base_relocation_table", "debug", "architecture", "global_ptr", "tls_table", "load_config_table", "bound_import", "iat", "delay_import_descriptor", "clr_runtime_header"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['export_table']['start'] = self._io.pos()
            self.export_table = self._root.DataDir(self._io, self, self._root)
            self.export_table._read()
            self._debug['export_table']['end'] = self._io.pos()
            self._debug['import_table']['start'] = self._io.pos()
            self.import_table = self._root.DataDir(self._io, self, self._root)
            self.import_table._read()
            self._debug['import_table']['end'] = self._io.pos()
            self._debug['resource_table']['start'] = self._io.pos()
            self.resource_table = self._root.DataDir(self._io, self, self._root)
            self.resource_table._read()
            self._debug['resource_table']['end'] = self._io.pos()
            self._debug['exception_table']['start'] = self._io.pos()
            self.exception_table = self._root.DataDir(self._io, self, self._root)
            self.exception_table._read()
            self._debug['exception_table']['end'] = self._io.pos()
            self._debug['certificate_table']['start'] = self._io.pos()
            self.certificate_table = self._root.DataDir(self._io, self, self._root)
            self.certificate_table._read()
            self._debug['certificate_table']['end'] = self._io.pos()
            self._debug['base_relocation_table']['start'] = self._io.pos()
            self.base_relocation_table = self._root.DataDir(self._io, self, self._root)
            self.base_relocation_table._read()
            self._debug['base_relocation_table']['end'] = self._io.pos()
            self._debug['debug']['start'] = self._io.pos()
            self.debug = self._root.DataDir(self._io, self, self._root)
            self.debug._read()
            self._debug['debug']['end'] = self._io.pos()
            self._debug['architecture']['start'] = self._io.pos()
            self.architecture = self._root.DataDir(self._io, self, self._root)
            self.architecture._read()
            self._debug['architecture']['end'] = self._io.pos()
            self._debug['global_ptr']['start'] = self._io.pos()
            self.global_ptr = self._root.DataDir(self._io, self, self._root)
            self.global_ptr._read()
            self._debug['global_ptr']['end'] = self._io.pos()
            self._debug['tls_table']['start'] = self._io.pos()
            self.tls_table = self._root.DataDir(self._io, self, self._root)
            self.tls_table._read()
            self._debug['tls_table']['end'] = self._io.pos()
            self._debug['load_config_table']['start'] = self._io.pos()
            self.load_config_table = self._root.DataDir(self._io, self, self._root)
            self.load_config_table._read()
            self._debug['load_config_table']['end'] = self._io.pos()
            self._debug['bound_import']['start'] = self._io.pos()
            self.bound_import = self._root.DataDir(self._io, self, self._root)
            self.bound_import._read()
            self._debug['bound_import']['end'] = self._io.pos()
            self._debug['iat']['start'] = self._io.pos()
            self.iat = self._root.DataDir(self._io, self, self._root)
            self.iat._read()
            self._debug['iat']['end'] = self._io.pos()
            self._debug['delay_import_descriptor']['start'] = self._io.pos()
            self.delay_import_descriptor = self._root.DataDir(self._io, self, self._root)
            self.delay_import_descriptor._read()
            self._debug['delay_import_descriptor']['end'] = self._io.pos()
            self._debug['clr_runtime_header']['start'] = self._io.pos()
            self.clr_runtime_header = self._root.DataDir(self._io, self, self._root)
            self.clr_runtime_header._read()
            self._debug['clr_runtime_header']['end'] = self._io.pos()


    class DataDir(KaitaiStruct):
        SEQ_FIELDS = ["virtual_address", "size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['virtual_address']['start'] = self._io.pos()
            self.virtual_address = self._io.read_u4le()
            self._debug['virtual_address']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()


    class CoffSymbol(KaitaiStruct):
        SEQ_FIELDS = ["name_annoying", "value", "section_number", "type", "storage_class", "number_of_aux_symbols"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_annoying']['start'] = self._io.pos()
            self._raw_name_annoying = self._io.read_bytes(8)
            io = KaitaiStream(BytesIO(self._raw_name_annoying))
            self.name_annoying = self._root.Annoyingstring(io, self, self._root)
            self.name_annoying._read()
            self._debug['name_annoying']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_u4le()
            self._debug['value']['end'] = self._io.pos()
            self._debug['section_number']['start'] = self._io.pos()
            self.section_number = self._io.read_u2le()
            self._debug['section_number']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u2le()
            self._debug['type']['end'] = self._io.pos()
            self._debug['storage_class']['start'] = self._io.pos()
            self.storage_class = self._io.read_u1()
            self._debug['storage_class']['end'] = self._io.pos()
            self._debug['number_of_aux_symbols']['start'] = self._io.pos()
            self.number_of_aux_symbols = self._io.read_u1()
            self._debug['number_of_aux_symbols']['end'] = self._io.pos()

        @property
        def section(self):
            if hasattr(self, '_m_section'):
                return self._m_section if hasattr(self, '_m_section') else None

            self._m_section = self._root.pe.sections[(self.section_number - 1)]
            return self._m_section if hasattr(self, '_m_section') else None

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            _pos = self._io.pos()
            self._io.seek((self.section.pointer_to_raw_data + self.value))
            self._debug['_m_data']['start'] = self._io.pos()
            self._m_data = self._io.read_bytes(1)
            self._debug['_m_data']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_data if hasattr(self, '_m_data') else None


    class PeHeader(KaitaiStruct):
        SEQ_FIELDS = ["pe_signature", "coff_hdr", "optional_hdr", "sections"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['pe_signature']['start'] = self._io.pos()
            self.pe_signature = self._io.ensure_fixed_contents(b"\x50\x45\x00\x00")
            self._debug['pe_signature']['end'] = self._io.pos()
            self._debug['coff_hdr']['start'] = self._io.pos()
            self.coff_hdr = self._root.CoffHeader(self._io, self, self._root)
            self.coff_hdr._read()
            self._debug['coff_hdr']['end'] = self._io.pos()
            self._debug['optional_hdr']['start'] = self._io.pos()
            self._raw_optional_hdr = self._io.read_bytes(self.coff_hdr.size_of_optional_header)
            io = KaitaiStream(BytesIO(self._raw_optional_hdr))
            self.optional_hdr = self._root.OptionalHeader(io, self, self._root)
            self.optional_hdr._read()
            self._debug['optional_hdr']['end'] = self._io.pos()
            self._debug['sections']['start'] = self._io.pos()
            self.sections = [None] * (self.coff_hdr.number_of_sections)
            for i in range(self.coff_hdr.number_of_sections):
                if not 'arr' in self._debug['sections']:
                    self._debug['sections']['arr'] = []
                self._debug['sections']['arr'].append({'start': self._io.pos()})
                _t_sections = self._root.Section(self._io, self, self._root)
                _t_sections._read()
                self.sections[i] = _t_sections
                self._debug['sections']['arr'][i]['end'] = self._io.pos()

            self._debug['sections']['end'] = self._io.pos()

        @property
        def certificate_table(self):
            if hasattr(self, '_m_certificate_table'):
                return self._m_certificate_table if hasattr(self, '_m_certificate_table') else None

            if self.optional_hdr.data_dirs.certificate_table.virtual_address != 0:
                _pos = self._io.pos()
                self._io.seek(self.optional_hdr.data_dirs.certificate_table.virtual_address)
                self._debug['_m_certificate_table']['start'] = self._io.pos()
                self._raw__m_certificate_table = self._io.read_bytes(self.optional_hdr.data_dirs.certificate_table.size)
                io = KaitaiStream(BytesIO(self._raw__m_certificate_table))
                self._m_certificate_table = self._root.CertificateTable(io, self, self._root)
                self._m_certificate_table._read()
                self._debug['_m_certificate_table']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_certificate_table if hasattr(self, '_m_certificate_table') else None


    class OptionalHeader(KaitaiStruct):
        SEQ_FIELDS = ["std", "windows", "data_dirs"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['std']['start'] = self._io.pos()
            self.std = self._root.OptionalHeaderStd(self._io, self, self._root)
            self.std._read()
            self._debug['std']['end'] = self._io.pos()
            self._debug['windows']['start'] = self._io.pos()
            self.windows = self._root.OptionalHeaderWindows(self._io, self, self._root)
            self.windows._read()
            self._debug['windows']['end'] = self._io.pos()
            self._debug['data_dirs']['start'] = self._io.pos()
            self.data_dirs = self._root.OptionalHeaderDataDirs(self._io, self, self._root)
            self.data_dirs._read()
            self._debug['data_dirs']['end'] = self._io.pos()


    class Section(KaitaiStruct):
        SEQ_FIELDS = ["name", "virtual_size", "virtual_address", "size_of_raw_data", "pointer_to_raw_data", "pointer_to_relocations", "pointer_to_linenumbers", "number_of_relocations", "number_of_linenumbers", "characteristics"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 0)).decode(u"UTF-8")
            self._debug['name']['end'] = self._io.pos()
            self._debug['virtual_size']['start'] = self._io.pos()
            self.virtual_size = self._io.read_u4le()
            self._debug['virtual_size']['end'] = self._io.pos()
            self._debug['virtual_address']['start'] = self._io.pos()
            self.virtual_address = self._io.read_u4le()
            self._debug['virtual_address']['end'] = self._io.pos()
            self._debug['size_of_raw_data']['start'] = self._io.pos()
            self.size_of_raw_data = self._io.read_u4le()
            self._debug['size_of_raw_data']['end'] = self._io.pos()
            self._debug['pointer_to_raw_data']['start'] = self._io.pos()
            self.pointer_to_raw_data = self._io.read_u4le()
            self._debug['pointer_to_raw_data']['end'] = self._io.pos()
            self._debug['pointer_to_relocations']['start'] = self._io.pos()
            self.pointer_to_relocations = self._io.read_u4le()
            self._debug['pointer_to_relocations']['end'] = self._io.pos()
            self._debug['pointer_to_linenumbers']['start'] = self._io.pos()
            self.pointer_to_linenumbers = self._io.read_u4le()
            self._debug['pointer_to_linenumbers']['end'] = self._io.pos()
            self._debug['number_of_relocations']['start'] = self._io.pos()
            self.number_of_relocations = self._io.read_u2le()
            self._debug['number_of_relocations']['end'] = self._io.pos()
            self._debug['number_of_linenumbers']['start'] = self._io.pos()
            self.number_of_linenumbers = self._io.read_u2le()
            self._debug['number_of_linenumbers']['end'] = self._io.pos()
            self._debug['characteristics']['start'] = self._io.pos()
            self.characteristics = self._io.read_u4le()
            self._debug['characteristics']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek(self.pointer_to_raw_data)
            self._debug['_m_body']['start'] = self._io.pos()
            self._m_body = self._io.read_bytes(self.size_of_raw_data)
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class CertificateTable(KaitaiStruct):
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
                _t_items = self._root.CertificateEntry(self._io, self, self._root)
                _t_items._read()
                self.items.append(_t_items)
                self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['items']['end'] = self._io.pos()


    class MzPlaceholder(KaitaiStruct):
        SEQ_FIELDS = ["magic", "data1", "ofs_pe"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x4D\x5A")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['data1']['start'] = self._io.pos()
            self.data1 = self._io.read_bytes(58)
            self._debug['data1']['end'] = self._io.pos()
            self._debug['ofs_pe']['start'] = self._io.pos()
            self.ofs_pe = self._io.read_u4le()
            self._debug['ofs_pe']['end'] = self._io.pos()


    class OptionalHeaderStd(KaitaiStruct):
        SEQ_FIELDS = ["format", "major_linker_version", "minor_linker_version", "size_of_code", "size_of_initialized_data", "size_of_uninitialized_data", "address_of_entry_point", "base_of_code", "base_of_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['format']['start'] = self._io.pos()
            self.format = KaitaiStream.resolve_enum(self._root.PeFormat, self._io.read_u2le())
            self._debug['format']['end'] = self._io.pos()
            self._debug['major_linker_version']['start'] = self._io.pos()
            self.major_linker_version = self._io.read_u1()
            self._debug['major_linker_version']['end'] = self._io.pos()
            self._debug['minor_linker_version']['start'] = self._io.pos()
            self.minor_linker_version = self._io.read_u1()
            self._debug['minor_linker_version']['end'] = self._io.pos()
            self._debug['size_of_code']['start'] = self._io.pos()
            self.size_of_code = self._io.read_u4le()
            self._debug['size_of_code']['end'] = self._io.pos()
            self._debug['size_of_initialized_data']['start'] = self._io.pos()
            self.size_of_initialized_data = self._io.read_u4le()
            self._debug['size_of_initialized_data']['end'] = self._io.pos()
            self._debug['size_of_uninitialized_data']['start'] = self._io.pos()
            self.size_of_uninitialized_data = self._io.read_u4le()
            self._debug['size_of_uninitialized_data']['end'] = self._io.pos()
            self._debug['address_of_entry_point']['start'] = self._io.pos()
            self.address_of_entry_point = self._io.read_u4le()
            self._debug['address_of_entry_point']['end'] = self._io.pos()
            self._debug['base_of_code']['start'] = self._io.pos()
            self.base_of_code = self._io.read_u4le()
            self._debug['base_of_code']['end'] = self._io.pos()
            if self.format == self._root.PeFormat.pe32:
                self._debug['base_of_data']['start'] = self._io.pos()
                self.base_of_data = self._io.read_u4le()
                self._debug['base_of_data']['end'] = self._io.pos()



    class CoffHeader(KaitaiStruct):
        """
        .. seealso::
           3.3. COFF File Header (Object and Image)
        """

        class MachineType(Enum):
            unknown = 0
            i386 = 332
            r4000 = 358
            wcemipsv2 = 361
            alpha = 388
            sh3 = 418
            sh3dsp = 419
            sh4 = 422
            sh5 = 424
            arm = 448
            thumb = 450
            armnt = 452
            am33 = 467
            powerpc = 496
            powerpcfp = 497
            ia64 = 512
            mips16 = 614
            mipsfpu = 870
            mipsfpu16 = 1126
            ebc = 3772
            riscv32 = 20530
            riscv64 = 20580
            riscv128 = 20776
            amd64 = 34404
            m32r = 36929
            arm64 = 43620
        SEQ_FIELDS = ["machine", "number_of_sections", "time_date_stamp", "pointer_to_symbol_table", "number_of_symbols", "size_of_optional_header", "characteristics"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['machine']['start'] = self._io.pos()
            self.machine = KaitaiStream.resolve_enum(self._root.CoffHeader.MachineType, self._io.read_u2le())
            self._debug['machine']['end'] = self._io.pos()
            self._debug['number_of_sections']['start'] = self._io.pos()
            self.number_of_sections = self._io.read_u2le()
            self._debug['number_of_sections']['end'] = self._io.pos()
            self._debug['time_date_stamp']['start'] = self._io.pos()
            self.time_date_stamp = self._io.read_u4le()
            self._debug['time_date_stamp']['end'] = self._io.pos()
            self._debug['pointer_to_symbol_table']['start'] = self._io.pos()
            self.pointer_to_symbol_table = self._io.read_u4le()
            self._debug['pointer_to_symbol_table']['end'] = self._io.pos()
            self._debug['number_of_symbols']['start'] = self._io.pos()
            self.number_of_symbols = self._io.read_u4le()
            self._debug['number_of_symbols']['end'] = self._io.pos()
            self._debug['size_of_optional_header']['start'] = self._io.pos()
            self.size_of_optional_header = self._io.read_u2le()
            self._debug['size_of_optional_header']['end'] = self._io.pos()
            self._debug['characteristics']['start'] = self._io.pos()
            self.characteristics = self._io.read_u2le()
            self._debug['characteristics']['end'] = self._io.pos()

        @property
        def symbol_table_size(self):
            if hasattr(self, '_m_symbol_table_size'):
                return self._m_symbol_table_size if hasattr(self, '_m_symbol_table_size') else None

            self._m_symbol_table_size = (self.number_of_symbols * 18)
            return self._m_symbol_table_size if hasattr(self, '_m_symbol_table_size') else None

        @property
        def symbol_name_table_offset(self):
            if hasattr(self, '_m_symbol_name_table_offset'):
                return self._m_symbol_name_table_offset if hasattr(self, '_m_symbol_name_table_offset') else None

            self._m_symbol_name_table_offset = (self.pointer_to_symbol_table + self.symbol_table_size)
            return self._m_symbol_name_table_offset if hasattr(self, '_m_symbol_name_table_offset') else None

        @property
        def symbol_name_table_size(self):
            if hasattr(self, '_m_symbol_name_table_size'):
                return self._m_symbol_name_table_size if hasattr(self, '_m_symbol_name_table_size') else None

            _pos = self._io.pos()
            self._io.seek(self.symbol_name_table_offset)
            self._debug['_m_symbol_name_table_size']['start'] = self._io.pos()
            self._m_symbol_name_table_size = self._io.read_u4le()
            self._debug['_m_symbol_name_table_size']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_symbol_name_table_size if hasattr(self, '_m_symbol_name_table_size') else None

        @property
        def symbol_table(self):
            if hasattr(self, '_m_symbol_table'):
                return self._m_symbol_table if hasattr(self, '_m_symbol_table') else None

            _pos = self._io.pos()
            self._io.seek(self.pointer_to_symbol_table)
            self._debug['_m_symbol_table']['start'] = self._io.pos()
            self._m_symbol_table = [None] * (self.number_of_symbols)
            for i in range(self.number_of_symbols):
                if not 'arr' in self._debug['_m_symbol_table']:
                    self._debug['_m_symbol_table']['arr'] = []
                self._debug['_m_symbol_table']['arr'].append({'start': self._io.pos()})
                _t__m_symbol_table = self._root.CoffSymbol(self._io, self, self._root)
                _t__m_symbol_table._read()
                self._m_symbol_table[i] = _t__m_symbol_table
                self._debug['_m_symbol_table']['arr'][i]['end'] = self._io.pos()

            self._debug['_m_symbol_table']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_symbol_table if hasattr(self, '_m_symbol_table') else None


    class Annoyingstring(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def name_from_offset(self):
            if hasattr(self, '_m_name_from_offset'):
                return self._m_name_from_offset if hasattr(self, '_m_name_from_offset') else None

            if self.name_zeroes == 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(((self._parent._parent.symbol_name_table_offset + self.name_offset) if self.name_zeroes == 0 else 0))
                self._debug['_m_name_from_offset']['start'] = io.pos()
                self._m_name_from_offset = (io.read_bytes_term(0, False, True, False)).decode(u"ascii")
                self._debug['_m_name_from_offset']['end'] = io.pos()
                io.seek(_pos)

            return self._m_name_from_offset if hasattr(self, '_m_name_from_offset') else None

        @property
        def name_offset(self):
            if hasattr(self, '_m_name_offset'):
                return self._m_name_offset if hasattr(self, '_m_name_offset') else None

            _pos = self._io.pos()
            self._io.seek(4)
            self._debug['_m_name_offset']['start'] = self._io.pos()
            self._m_name_offset = self._io.read_u4le()
            self._debug['_m_name_offset']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_name_offset if hasattr(self, '_m_name_offset') else None

        @property
        def name(self):
            if hasattr(self, '_m_name'):
                return self._m_name if hasattr(self, '_m_name') else None

            self._m_name = (self.name_from_offset if self.name_zeroes == 0 else self.name_from_short)
            return self._m_name if hasattr(self, '_m_name') else None

        @property
        def name_zeroes(self):
            if hasattr(self, '_m_name_zeroes'):
                return self._m_name_zeroes if hasattr(self, '_m_name_zeroes') else None

            _pos = self._io.pos()
            self._io.seek(0)
            self._debug['_m_name_zeroes']['start'] = self._io.pos()
            self._m_name_zeroes = self._io.read_u4le()
            self._debug['_m_name_zeroes']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_name_zeroes if hasattr(self, '_m_name_zeroes') else None

        @property
        def name_from_short(self):
            if hasattr(self, '_m_name_from_short'):
                return self._m_name_from_short if hasattr(self, '_m_name_from_short') else None

            if self.name_zeroes != 0:
                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_name_from_short']['start'] = self._io.pos()
                self._m_name_from_short = (self._io.read_bytes_term(0, False, True, False)).decode(u"ascii")
                self._debug['_m_name_from_short']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_name_from_short if hasattr(self, '_m_name_from_short') else None


    @property
    def pe(self):
        if hasattr(self, '_m_pe'):
            return self._m_pe if hasattr(self, '_m_pe') else None

        _pos = self._io.pos()
        self._io.seek(self.mz.ofs_pe)
        self._debug['_m_pe']['start'] = self._io.pos()
        self._m_pe = self._root.PeHeader(self._io, self, self._root)
        self._m_pe._read()
        self._debug['_m_pe']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_pe if hasattr(self, '_m_pe') else None


