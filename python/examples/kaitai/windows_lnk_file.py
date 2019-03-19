# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from windows_shell_items import WindowsShellItems
class WindowsLnkFile(KaitaiStruct):
    """Windows .lnk files (AKA "shell link" file) are most frequently used
    in Windows shell to create "shortcuts" to another files, usually for
    purposes of running a program from some other directory, sometimes
    with certain preconfigured arguments and some other options.
    
    .. seealso::
       Source - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
    """

    class WindowState(Enum):
        normal = 1
        maximized = 3
        min_no_active = 7

    class DriveTypes(Enum):
        unknown = 0
        no_root_dir = 1
        removable = 2
        fixed = 3
        remote = 4
        cdrom = 5
        ramdisk = 6
    SEQ_FIELDS = ["header", "target_id_list", "info", "name", "rel_path", "work_dir", "arguments", "icon_location"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.FileHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        if self.header.flags.has_link_target_id_list:
            self._debug['target_id_list']['start'] = self._io.pos()
            self.target_id_list = self._root.LinkTargetIdList(self._io, self, self._root)
            self.target_id_list._read()
            self._debug['target_id_list']['end'] = self._io.pos()

        if self.header.flags.has_link_info:
            self._debug['info']['start'] = self._io.pos()
            self.info = self._root.LinkInfo(self._io, self, self._root)
            self.info._read()
            self._debug['info']['end'] = self._io.pos()

        if self.header.flags.has_name:
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.StringData(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()

        if self.header.flags.has_rel_path:
            self._debug['rel_path']['start'] = self._io.pos()
            self.rel_path = self._root.StringData(self._io, self, self._root)
            self.rel_path._read()
            self._debug['rel_path']['end'] = self._io.pos()

        if self.header.flags.has_work_dir:
            self._debug['work_dir']['start'] = self._io.pos()
            self.work_dir = self._root.StringData(self._io, self, self._root)
            self.work_dir._read()
            self._debug['work_dir']['end'] = self._io.pos()

        if self.header.flags.has_arguments:
            self._debug['arguments']['start'] = self._io.pos()
            self.arguments = self._root.StringData(self._io, self, self._root)
            self.arguments._read()
            self._debug['arguments']['end'] = self._io.pos()

        if self.header.flags.has_icon_location:
            self._debug['icon_location']['start'] = self._io.pos()
            self.icon_location = self._root.StringData(self._io, self, self._root)
            self.icon_location._read()
            self._debug['icon_location']['end'] = self._io.pos()


    class LinkTargetIdList(KaitaiStruct):
        """
        .. seealso::
           Section 2.2 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
        """
        SEQ_FIELDS = ["len_id_list", "id_list"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_id_list']['start'] = self._io.pos()
            self.len_id_list = self._io.read_u2le()
            self._debug['len_id_list']['end'] = self._io.pos()
            self._debug['id_list']['start'] = self._io.pos()
            self._raw_id_list = self._io.read_bytes(self.len_id_list)
            io = KaitaiStream(BytesIO(self._raw_id_list))
            self.id_list = WindowsShellItems(io)
            self.id_list._read()
            self._debug['id_list']['end'] = self._io.pos()


    class StringData(KaitaiStruct):
        SEQ_FIELDS = ["chars_str", "str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chars_str']['start'] = self._io.pos()
            self.chars_str = self._io.read_u2le()
            self._debug['chars_str']['end'] = self._io.pos()
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes((self.chars_str * 2))).decode(u"UTF-16LE")
            self._debug['str']['end'] = self._io.pos()


    class LinkInfo(KaitaiStruct):
        """
        .. seealso::
           Section 2.3 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
        """
        SEQ_FIELDS = ["len_all", "all"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_all']['start'] = self._io.pos()
            self.len_all = self._io.read_u4le()
            self._debug['len_all']['end'] = self._io.pos()
            self._debug['all']['start'] = self._io.pos()
            self._raw_all = self._io.read_bytes((self.len_all - 4))
            io = KaitaiStream(BytesIO(self._raw_all))
            self.all = self._root.LinkInfo.All(io, self, self._root)
            self.all._read()
            self._debug['all']['end'] = self._io.pos()

        class VolumeIdBody(KaitaiStruct):
            """
            .. seealso::
               Section 2.3.1 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
            """
            SEQ_FIELDS = ["drive_type", "drive_serial_number", "ofs_volume_label", "ofs_volume_label_unicode"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['drive_type']['start'] = self._io.pos()
                self.drive_type = KaitaiStream.resolve_enum(self._root.DriveTypes, self._io.read_u4le())
                self._debug['drive_type']['end'] = self._io.pos()
                self._debug['drive_serial_number']['start'] = self._io.pos()
                self.drive_serial_number = self._io.read_u4le()
                self._debug['drive_serial_number']['end'] = self._io.pos()
                self._debug['ofs_volume_label']['start'] = self._io.pos()
                self.ofs_volume_label = self._io.read_u4le()
                self._debug['ofs_volume_label']['end'] = self._io.pos()
                if self.is_unicode:
                    self._debug['ofs_volume_label_unicode']['start'] = self._io.pos()
                    self.ofs_volume_label_unicode = self._io.read_u4le()
                    self._debug['ofs_volume_label_unicode']['end'] = self._io.pos()


            @property
            def is_unicode(self):
                if hasattr(self, '_m_is_unicode'):
                    return self._m_is_unicode if hasattr(self, '_m_is_unicode') else None

                self._m_is_unicode = self.ofs_volume_label == 20
                return self._m_is_unicode if hasattr(self, '_m_is_unicode') else None

            @property
            def volume_label_ansi(self):
                if hasattr(self, '_m_volume_label_ansi'):
                    return self._m_volume_label_ansi if hasattr(self, '_m_volume_label_ansi') else None

                if not (self.is_unicode):
                    _pos = self._io.pos()
                    self._io.seek((self.ofs_volume_label - 4))
                    self._debug['_m_volume_label_ansi']['start'] = self._io.pos()
                    self._m_volume_label_ansi = (self._io.read_bytes_term(0, False, True, True)).decode(u"cp437")
                    self._debug['_m_volume_label_ansi']['end'] = self._io.pos()
                    self._io.seek(_pos)

                return self._m_volume_label_ansi if hasattr(self, '_m_volume_label_ansi') else None


        class All(KaitaiStruct):
            """
            .. seealso::
               Section 2.3 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
            """
            SEQ_FIELDS = ["len_header", "header"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['len_header']['start'] = self._io.pos()
                self.len_header = self._io.read_u4le()
                self._debug['len_header']['end'] = self._io.pos()
                self._debug['header']['start'] = self._io.pos()
                self._raw_header = self._io.read_bytes((self.len_header - 8))
                io = KaitaiStream(BytesIO(self._raw_header))
                self.header = self._root.LinkInfo.Header(io, self, self._root)
                self.header._read()
                self._debug['header']['end'] = self._io.pos()

            @property
            def volume_id(self):
                if hasattr(self, '_m_volume_id'):
                    return self._m_volume_id if hasattr(self, '_m_volume_id') else None

                if self.header.flags.has_volume_id_and_local_base_path:
                    _pos = self._io.pos()
                    self._io.seek((self.header.ofs_volume_id - 4))
                    self._debug['_m_volume_id']['start'] = self._io.pos()
                    self._m_volume_id = self._root.LinkInfo.VolumeIdSpec(self._io, self, self._root)
                    self._m_volume_id._read()
                    self._debug['_m_volume_id']['end'] = self._io.pos()
                    self._io.seek(_pos)

                return self._m_volume_id if hasattr(self, '_m_volume_id') else None

            @property
            def local_base_path(self):
                if hasattr(self, '_m_local_base_path'):
                    return self._m_local_base_path if hasattr(self, '_m_local_base_path') else None

                if self.header.flags.has_volume_id_and_local_base_path:
                    _pos = self._io.pos()
                    self._io.seek((self.header.ofs_local_base_path - 4))
                    self._debug['_m_local_base_path']['start'] = self._io.pos()
                    self._m_local_base_path = self._io.read_bytes_term(0, False, True, True)
                    self._debug['_m_local_base_path']['end'] = self._io.pos()
                    self._io.seek(_pos)

                return self._m_local_base_path if hasattr(self, '_m_local_base_path') else None


        class VolumeIdSpec(KaitaiStruct):
            """
            .. seealso::
               Section 2.3.1 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
            """
            SEQ_FIELDS = ["len_all", "body"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['len_all']['start'] = self._io.pos()
                self.len_all = self._io.read_u4le()
                self._debug['len_all']['end'] = self._io.pos()
                self._debug['body']['start'] = self._io.pos()
                self._raw_body = self._io.read_bytes((self.len_all - 4))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.LinkInfo.VolumeIdBody(io, self, self._root)
                self.body._read()
                self._debug['body']['end'] = self._io.pos()


        class LinkInfoFlags(KaitaiStruct):
            """
            .. seealso::
               Section 2.3 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
            """
            SEQ_FIELDS = ["reserved1", "has_common_net_rel_link", "has_volume_id_and_local_base_path", "reserved2"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.read_bits_int(6)
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['has_common_net_rel_link']['start'] = self._io.pos()
                self.has_common_net_rel_link = self._io.read_bits_int(1) != 0
                self._debug['has_common_net_rel_link']['end'] = self._io.pos()
                self._debug['has_volume_id_and_local_base_path']['start'] = self._io.pos()
                self.has_volume_id_and_local_base_path = self._io.read_bits_int(1) != 0
                self._debug['has_volume_id_and_local_base_path']['end'] = self._io.pos()
                self._debug['reserved2']['start'] = self._io.pos()
                self.reserved2 = self._io.read_bits_int(24)
                self._debug['reserved2']['end'] = self._io.pos()


        class Header(KaitaiStruct):
            """
            .. seealso::
               Section 2.3 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
            """
            SEQ_FIELDS = ["flags", "ofs_volume_id", "ofs_local_base_path", "ofs_common_net_rel_link", "ofs_common_path_suffix", "ofs_local_base_path_unicode", "ofs_common_path_suffix_unicode"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._root.LinkInfo.LinkInfoFlags(self._io, self, self._root)
                self.flags._read()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['ofs_volume_id']['start'] = self._io.pos()
                self.ofs_volume_id = self._io.read_u4le()
                self._debug['ofs_volume_id']['end'] = self._io.pos()
                self._debug['ofs_local_base_path']['start'] = self._io.pos()
                self.ofs_local_base_path = self._io.read_u4le()
                self._debug['ofs_local_base_path']['end'] = self._io.pos()
                self._debug['ofs_common_net_rel_link']['start'] = self._io.pos()
                self.ofs_common_net_rel_link = self._io.read_u4le()
                self._debug['ofs_common_net_rel_link']['end'] = self._io.pos()
                self._debug['ofs_common_path_suffix']['start'] = self._io.pos()
                self.ofs_common_path_suffix = self._io.read_u4le()
                self._debug['ofs_common_path_suffix']['end'] = self._io.pos()
                if not (self._io.is_eof()):
                    self._debug['ofs_local_base_path_unicode']['start'] = self._io.pos()
                    self.ofs_local_base_path_unicode = self._io.read_u4le()
                    self._debug['ofs_local_base_path_unicode']['end'] = self._io.pos()

                if not (self._io.is_eof()):
                    self._debug['ofs_common_path_suffix_unicode']['start'] = self._io.pos()
                    self.ofs_common_path_suffix_unicode = self._io.read_u4le()
                    self._debug['ofs_common_path_suffix_unicode']['end'] = self._io.pos()




    class LinkFlags(KaitaiStruct):
        """
        .. seealso::
           Section 2.1.1 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
        """
        SEQ_FIELDS = ["is_unicode", "has_icon_location", "has_arguments", "has_work_dir", "has_rel_path", "has_name", "has_link_info", "has_link_target_id_list", "_unnamed8", "reserved", "keep_local_id_list_for_unc_target", "_unnamed11"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['is_unicode']['start'] = self._io.pos()
            self.is_unicode = self._io.read_bits_int(1) != 0
            self._debug['is_unicode']['end'] = self._io.pos()
            self._debug['has_icon_location']['start'] = self._io.pos()
            self.has_icon_location = self._io.read_bits_int(1) != 0
            self._debug['has_icon_location']['end'] = self._io.pos()
            self._debug['has_arguments']['start'] = self._io.pos()
            self.has_arguments = self._io.read_bits_int(1) != 0
            self._debug['has_arguments']['end'] = self._io.pos()
            self._debug['has_work_dir']['start'] = self._io.pos()
            self.has_work_dir = self._io.read_bits_int(1) != 0
            self._debug['has_work_dir']['end'] = self._io.pos()
            self._debug['has_rel_path']['start'] = self._io.pos()
            self.has_rel_path = self._io.read_bits_int(1) != 0
            self._debug['has_rel_path']['end'] = self._io.pos()
            self._debug['has_name']['start'] = self._io.pos()
            self.has_name = self._io.read_bits_int(1) != 0
            self._debug['has_name']['end'] = self._io.pos()
            self._debug['has_link_info']['start'] = self._io.pos()
            self.has_link_info = self._io.read_bits_int(1) != 0
            self._debug['has_link_info']['end'] = self._io.pos()
            self._debug['has_link_target_id_list']['start'] = self._io.pos()
            self.has_link_target_id_list = self._io.read_bits_int(1) != 0
            self._debug['has_link_target_id_list']['end'] = self._io.pos()
            self._debug['_unnamed8']['start'] = self._io.pos()
            self._unnamed8 = self._io.read_bits_int(16)
            self._debug['_unnamed8']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bits_int(5)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['keep_local_id_list_for_unc_target']['start'] = self._io.pos()
            self.keep_local_id_list_for_unc_target = self._io.read_bits_int(1) != 0
            self._debug['keep_local_id_list_for_unc_target']['end'] = self._io.pos()
            self._debug['_unnamed11']['start'] = self._io.pos()
            self._unnamed11 = self._io.read_bits_int(2)
            self._debug['_unnamed11']['end'] = self._io.pos()


    class FileHeader(KaitaiStruct):
        """
        .. seealso::
           Section 2.1 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
        """
        SEQ_FIELDS = ["len_header", "link_clsid", "flags", "file_attrs", "time_creation", "time_access", "time_write", "target_file_size", "icon_index", "show_command", "hotkey", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_header']['start'] = self._io.pos()
            self.len_header = self._io.ensure_fixed_contents(b"\x4C\x00\x00\x00")
            self._debug['len_header']['end'] = self._io.pos()
            self._debug['link_clsid']['start'] = self._io.pos()
            self.link_clsid = self._io.ensure_fixed_contents(b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46")
            self._debug['link_clsid']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self._raw_flags = self._io.read_bytes(4)
            io = KaitaiStream(BytesIO(self._raw_flags))
            self.flags = self._root.LinkFlags(io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['file_attrs']['start'] = self._io.pos()
            self.file_attrs = self._io.read_u4le()
            self._debug['file_attrs']['end'] = self._io.pos()
            self._debug['time_creation']['start'] = self._io.pos()
            self.time_creation = self._io.read_u8le()
            self._debug['time_creation']['end'] = self._io.pos()
            self._debug['time_access']['start'] = self._io.pos()
            self.time_access = self._io.read_u8le()
            self._debug['time_access']['end'] = self._io.pos()
            self._debug['time_write']['start'] = self._io.pos()
            self.time_write = self._io.read_u8le()
            self._debug['time_write']['end'] = self._io.pos()
            self._debug['target_file_size']['start'] = self._io.pos()
            self.target_file_size = self._io.read_u4le()
            self._debug['target_file_size']['end'] = self._io.pos()
            self._debug['icon_index']['start'] = self._io.pos()
            self.icon_index = self._io.read_s4le()
            self._debug['icon_index']['end'] = self._io.pos()
            self._debug['show_command']['start'] = self._io.pos()
            self.show_command = KaitaiStream.resolve_enum(self._root.WindowState, self._io.read_u4le())
            self._debug['show_command']['end'] = self._io.pos()
            self._debug['hotkey']['start'] = self._io.pos()
            self.hotkey = self._io.read_u2le()
            self._debug['hotkey']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.ensure_fixed_contents(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            self._debug['reserved']['end'] = self._io.pos()



