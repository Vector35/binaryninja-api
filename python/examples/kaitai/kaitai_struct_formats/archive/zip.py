from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Zip(KaitaiStruct):
    """
    .. seealso::
       Source - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    """

    class Compression(Enum):
        none = 0
        shrunk = 1
        reduced_1 = 2
        reduced_2 = 3
        reduced_3 = 4
        reduced_4 = 5
        imploded = 6
        deflated = 8
        enhanced_deflated = 9
        pkware_dcl_imploded = 10
        bzip2 = 12
        lzma = 14
        ibm_terse = 18
        ibm_lz77_z = 19
        ppmd = 98

    class ExtraCodes(Enum):
        zip64 = 1
        av_info = 7
        os2 = 9
        ntfs = 10
        openvms = 12
        pkware_unix = 13
        file_stream_and_fork_descriptors = 14
        patch_descriptor = 15
        pkcs7 = 20
        x509_cert_id_and_signature_for_file = 21
        x509_cert_id_for_central_dir = 22
        strong_encryption_header = 23
        record_management_controls = 24
        pkcs7_enc_recip_cert_list = 25
        ibm_s390_uncomp = 101
        ibm_s390_comp = 102
        poszip_4690 = 18064
        extended_timestamp = 21589
        infozip_unix = 30805
        infozip_unix_var_size = 30837
    SEQ_FIELDS = ["sections"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['sections']['start'] = self._io.pos()
        self.sections = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['sections']:
                self._debug['sections']['arr'] = []
            self._debug['sections']['arr'].append({'start': self._io.pos()})
            _t_sections = self._root.PkSection(self._io, self, self._root)
            _t_sections._read()
            self.sections.append(_t_sections)
            self._debug['sections']['arr'][len(self.sections) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['sections']['end'] = self._io.pos()

    class LocalFile(KaitaiStruct):
        SEQ_FIELDS = ["header", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self.header = self._root.LocalFileHeader(self._io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.header.compressed_size)
            self._debug['body']['end'] = self._io.pos()


    class ExtraField(KaitaiStruct):
        SEQ_FIELDS = ["code", "size", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = KaitaiStream.resolve_enum(self._root.ExtraCodes, self._io.read_u2le())
            self._debug['code']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u2le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.code
            if _on == self._root.ExtraCodes.ntfs:
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.ExtraField.Ntfs(io, self, self._root)
                self.body._read()
            elif _on == self._root.ExtraCodes.extended_timestamp:
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.ExtraField.ExtendedTimestamp(io, self, self._root)
                self.body._read()
            elif _on == self._root.ExtraCodes.infozip_unix_var_size:
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.ExtraField.InfozipUnixVarSize(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.size)
            self._debug['body']['end'] = self._io.pos()

        class Ntfs(KaitaiStruct):
            """
            .. seealso::
               Source - https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L191
            """
            SEQ_FIELDS = ["reserved", "attributes"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_u4le()
                self._debug['reserved']['end'] = self._io.pos()
                self._debug['attributes']['start'] = self._io.pos()
                self.attributes = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['attributes']:
                        self._debug['attributes']['arr'] = []
                    self._debug['attributes']['arr'].append({'start': self._io.pos()})
                    _t_attributes = self._root.ExtraField.Ntfs.Attribute(self._io, self, self._root)
                    _t_attributes._read()
                    self.attributes.append(_t_attributes)
                    self._debug['attributes']['arr'][len(self.attributes) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['attributes']['end'] = self._io.pos()

            class Attribute(KaitaiStruct):
                SEQ_FIELDS = ["tag", "size", "body"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['tag']['start'] = self._io.pos()
                    self.tag = self._io.read_u2le()
                    self._debug['tag']['end'] = self._io.pos()
                    self._debug['size']['start'] = self._io.pos()
                    self.size = self._io.read_u2le()
                    self._debug['size']['end'] = self._io.pos()
                    self._debug['body']['start'] = self._io.pos()
                    _on = self.tag
                    if _on == 1:
                        self._raw_body = self._io.read_bytes(self.size)
                        io = KaitaiStream(BytesIO(self._raw_body))
                        self.body = self._root.ExtraField.Ntfs.Attribute1(io, self, self._root)
                        self.body._read()
                    else:
                        self.body = self._io.read_bytes(self.size)
                    self._debug['body']['end'] = self._io.pos()


            class Attribute1(KaitaiStruct):
                SEQ_FIELDS = ["last_mod_time", "last_access_time", "creation_time"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['last_mod_time']['start'] = self._io.pos()
                    self.last_mod_time = self._io.read_u8le()
                    self._debug['last_mod_time']['end'] = self._io.pos()
                    self._debug['last_access_time']['start'] = self._io.pos()
                    self.last_access_time = self._io.read_u8le()
                    self._debug['last_access_time']['end'] = self._io.pos()
                    self._debug['creation_time']['start'] = self._io.pos()
                    self.creation_time = self._io.read_u8le()
                    self._debug['creation_time']['end'] = self._io.pos()



        class ExtendedTimestamp(KaitaiStruct):
            """
            .. seealso::
               Source - https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L817
            """
            SEQ_FIELDS = ["flags", "mod_time", "access_time", "create_time"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._io.read_u1()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['mod_time']['start'] = self._io.pos()
                self.mod_time = self._io.read_u4le()
                self._debug['mod_time']['end'] = self._io.pos()
                if not (self._io.is_eof()):
                    self._debug['access_time']['start'] = self._io.pos()
                    self.access_time = self._io.read_u4le()
                    self._debug['access_time']['end'] = self._io.pos()

                if not (self._io.is_eof()):
                    self._debug['create_time']['start'] = self._io.pos()
                    self.create_time = self._io.read_u4le()
                    self._debug['create_time']['end'] = self._io.pos()



        class InfozipUnixVarSize(KaitaiStruct):
            """
            .. seealso::
               Source - https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L1339
            """
            SEQ_FIELDS = ["version", "uid_size", "uid", "gid_size", "gid"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['version']['start'] = self._io.pos()
                self.version = self._io.read_u1()
                self._debug['version']['end'] = self._io.pos()
                self._debug['uid_size']['start'] = self._io.pos()
                self.uid_size = self._io.read_u1()
                self._debug['uid_size']['end'] = self._io.pos()
                self._debug['uid']['start'] = self._io.pos()
                self.uid = self._io.read_bytes(self.uid_size)
                self._debug['uid']['end'] = self._io.pos()
                self._debug['gid_size']['start'] = self._io.pos()
                self.gid_size = self._io.read_u1()
                self._debug['gid_size']['end'] = self._io.pos()
                self._debug['gid']['start'] = self._io.pos()
                self.gid = self._io.read_bytes(self.gid_size)
                self._debug['gid']['end'] = self._io.pos()



    class CentralDirEntry(KaitaiStruct):
        """
        .. seealso::
           - 4.3.12 - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
        """
        SEQ_FIELDS = ["version_made_by", "version_needed_to_extract", "flags", "compression_method", "last_mod_file_time", "last_mod_file_date", "crc32", "compressed_size", "uncompressed_size", "file_name_len", "extra_len", "comment_len", "disk_number_start", "int_file_attr", "ext_file_attr", "local_header_offset", "file_name", "extra", "comment"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version_made_by']['start'] = self._io.pos()
            self.version_made_by = self._io.read_u2le()
            self._debug['version_made_by']['end'] = self._io.pos()
            self._debug['version_needed_to_extract']['start'] = self._io.pos()
            self.version_needed_to_extract = self._io.read_u2le()
            self._debug['version_needed_to_extract']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['compression_method']['start'] = self._io.pos()
            self.compression_method = KaitaiStream.resolve_enum(self._root.Compression, self._io.read_u2le())
            self._debug['compression_method']['end'] = self._io.pos()
            self._debug['last_mod_file_time']['start'] = self._io.pos()
            self.last_mod_file_time = self._io.read_u2le()
            self._debug['last_mod_file_time']['end'] = self._io.pos()
            self._debug['last_mod_file_date']['start'] = self._io.pos()
            self.last_mod_file_date = self._io.read_u2le()
            self._debug['last_mod_file_date']['end'] = self._io.pos()
            self._debug['crc32']['start'] = self._io.pos()
            self.crc32 = self._io.read_u4le()
            self._debug['crc32']['end'] = self._io.pos()
            self._debug['compressed_size']['start'] = self._io.pos()
            self.compressed_size = self._io.read_u4le()
            self._debug['compressed_size']['end'] = self._io.pos()
            self._debug['uncompressed_size']['start'] = self._io.pos()
            self.uncompressed_size = self._io.read_u4le()
            self._debug['uncompressed_size']['end'] = self._io.pos()
            self._debug['file_name_len']['start'] = self._io.pos()
            self.file_name_len = self._io.read_u2le()
            self._debug['file_name_len']['end'] = self._io.pos()
            self._debug['extra_len']['start'] = self._io.pos()
            self.extra_len = self._io.read_u2le()
            self._debug['extra_len']['end'] = self._io.pos()
            self._debug['comment_len']['start'] = self._io.pos()
            self.comment_len = self._io.read_u2le()
            self._debug['comment_len']['end'] = self._io.pos()
            self._debug['disk_number_start']['start'] = self._io.pos()
            self.disk_number_start = self._io.read_u2le()
            self._debug['disk_number_start']['end'] = self._io.pos()
            self._debug['int_file_attr']['start'] = self._io.pos()
            self.int_file_attr = self._io.read_u2le()
            self._debug['int_file_attr']['end'] = self._io.pos()
            self._debug['ext_file_attr']['start'] = self._io.pos()
            self.ext_file_attr = self._io.read_u4le()
            self._debug['ext_file_attr']['end'] = self._io.pos()
            self._debug['local_header_offset']['start'] = self._io.pos()
            self.local_header_offset = self._io.read_s4le()
            self._debug['local_header_offset']['end'] = self._io.pos()
            self._debug['file_name']['start'] = self._io.pos()
            self.file_name = (self._io.read_bytes(self.file_name_len)).decode(u"UTF-8")
            self._debug['file_name']['end'] = self._io.pos()
            self._debug['extra']['start'] = self._io.pos()
            self._raw_extra = self._io.read_bytes(self.extra_len)
            io = KaitaiStream(BytesIO(self._raw_extra))
            self.extra = self._root.Extras(io, self, self._root)
            self.extra._read()
            self._debug['extra']['end'] = self._io.pos()
            self._debug['comment']['start'] = self._io.pos()
            self.comment = (self._io.read_bytes(self.comment_len)).decode(u"UTF-8")
            self._debug['comment']['end'] = self._io.pos()

        @property
        def local_header(self):
            if hasattr(self, '_m_local_header'):
                return self._m_local_header if hasattr(self, '_m_local_header') else None

            _pos = self._io.pos()
            self._io.seek(self.local_header_offset)
            self._debug['_m_local_header']['start'] = self._io.pos()
            self._m_local_header = self._root.PkSection(self._io, self, self._root)
            self._m_local_header._read()
            self._debug['_m_local_header']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_local_header if hasattr(self, '_m_local_header') else None


    class PkSection(KaitaiStruct):
        SEQ_FIELDS = ["magic", "section_type", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x50\x4B")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['section_type']['start'] = self._io.pos()
            self.section_type = self._io.read_u2le()
            self._debug['section_type']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.section_type
            if _on == 513:
                self.body = self._root.CentralDirEntry(self._io, self, self._root)
                self.body._read()
            elif _on == 1027:
                self.body = self._root.LocalFile(self._io, self, self._root)
                self.body._read()
            elif _on == 1541:
                self.body = self._root.EndOfCentralDir(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class Extras(KaitaiStruct):
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
                _t_entries = self._root.ExtraField(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class LocalFileHeader(KaitaiStruct):
        SEQ_FIELDS = ["version", "flags", "compression_method", "file_mod_time", "file_mod_date", "crc32", "compressed_size", "uncompressed_size", "file_name_len", "extra_len", "file_name", "extra"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2le()
            self._debug['version']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['compression_method']['start'] = self._io.pos()
            self.compression_method = KaitaiStream.resolve_enum(self._root.Compression, self._io.read_u2le())
            self._debug['compression_method']['end'] = self._io.pos()
            self._debug['file_mod_time']['start'] = self._io.pos()
            self.file_mod_time = self._io.read_u2le()
            self._debug['file_mod_time']['end'] = self._io.pos()
            self._debug['file_mod_date']['start'] = self._io.pos()
            self.file_mod_date = self._io.read_u2le()
            self._debug['file_mod_date']['end'] = self._io.pos()
            self._debug['crc32']['start'] = self._io.pos()
            self.crc32 = self._io.read_u4le()
            self._debug['crc32']['end'] = self._io.pos()
            self._debug['compressed_size']['start'] = self._io.pos()
            self.compressed_size = self._io.read_u4le()
            self._debug['compressed_size']['end'] = self._io.pos()
            self._debug['uncompressed_size']['start'] = self._io.pos()
            self.uncompressed_size = self._io.read_u4le()
            self._debug['uncompressed_size']['end'] = self._io.pos()
            self._debug['file_name_len']['start'] = self._io.pos()
            self.file_name_len = self._io.read_u2le()
            self._debug['file_name_len']['end'] = self._io.pos()
            self._debug['extra_len']['start'] = self._io.pos()
            self.extra_len = self._io.read_u2le()
            self._debug['extra_len']['end'] = self._io.pos()
            self._debug['file_name']['start'] = self._io.pos()
            self.file_name = (self._io.read_bytes(self.file_name_len)).decode(u"UTF-8")
            self._debug['file_name']['end'] = self._io.pos()
            self._debug['extra']['start'] = self._io.pos()
            self._raw_extra = self._io.read_bytes(self.extra_len)
            io = KaitaiStream(BytesIO(self._raw_extra))
            self.extra = self._root.Extras(io, self, self._root)
            self.extra._read()
            self._debug['extra']['end'] = self._io.pos()


    class EndOfCentralDir(KaitaiStruct):
        SEQ_FIELDS = ["disk_of_end_of_central_dir", "disk_of_central_dir", "qty_central_dir_entries_on_disk", "qty_central_dir_entries_total", "central_dir_size", "central_dir_offset", "comment_len", "comment"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['disk_of_end_of_central_dir']['start'] = self._io.pos()
            self.disk_of_end_of_central_dir = self._io.read_u2le()
            self._debug['disk_of_end_of_central_dir']['end'] = self._io.pos()
            self._debug['disk_of_central_dir']['start'] = self._io.pos()
            self.disk_of_central_dir = self._io.read_u2le()
            self._debug['disk_of_central_dir']['end'] = self._io.pos()
            self._debug['qty_central_dir_entries_on_disk']['start'] = self._io.pos()
            self.qty_central_dir_entries_on_disk = self._io.read_u2le()
            self._debug['qty_central_dir_entries_on_disk']['end'] = self._io.pos()
            self._debug['qty_central_dir_entries_total']['start'] = self._io.pos()
            self.qty_central_dir_entries_total = self._io.read_u2le()
            self._debug['qty_central_dir_entries_total']['end'] = self._io.pos()
            self._debug['central_dir_size']['start'] = self._io.pos()
            self.central_dir_size = self._io.read_u4le()
            self._debug['central_dir_size']['end'] = self._io.pos()
            self._debug['central_dir_offset']['start'] = self._io.pos()
            self.central_dir_offset = self._io.read_u4le()
            self._debug['central_dir_offset']['end'] = self._io.pos()
            self._debug['comment_len']['start'] = self._io.pos()
            self.comment_len = self._io.read_u2le()
            self._debug['comment_len']['end'] = self._io.pos()
            self._debug['comment']['start'] = self._io.pos()
            self.comment = (self._io.read_bytes(self.comment_len)).decode(u"UTF-8")
            self._debug['comment']['end'] = self._io.pos()



