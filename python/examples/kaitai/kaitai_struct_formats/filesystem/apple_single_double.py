from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class AppleSingleDouble(KaitaiStruct):
    """AppleSingle and AppleDouble files are used by certain Mac
    applications (e.g. Finder) to store Mac-specific file attributes on
    filesystems that do not support that.
    
    Syntactically, both formats are the same, the only difference is how
    they are being used:
    
    * AppleSingle means that only one file will be created on external
      filesystem that will hold both the data (AKA "data fork" in Apple
      terminology), and the attributes (AKA "resource fork").
    * AppleDouble means that two files will be created: a normal file
      that keeps the data ("data fork") is kept separately from an
      auxiliary file that contains attributes ("resource fork"), which
      is kept with the same name, but starting with an extra dot and
      underscore `._` to keep it hidden.
    
    In modern practice (Mac OS X), Finder only uses AppleDouble to keep
    compatibility with other OSes, as virtually nobody outside of Mac
    understands how to access data in AppleSingle container.
    
    .. seealso::
       Source - http://kaiser-edv.de/documents/AppleSingle_AppleDouble.pdf
    """

    class FileType(Enum):
        apple_single = 333312
        apple_double = 333319
    SEQ_FIELDS = ["magic", "version", "reserved", "num_entries", "entries"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = KaitaiStream.resolve_enum(self._root.FileType, self._io.read_u4be())
        self._debug['magic']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u4be()
        self._debug['version']['end'] = self._io.pos()
        self._debug['reserved']['start'] = self._io.pos()
        self.reserved = self._io.read_bytes(16)
        self._debug['reserved']['end'] = self._io.pos()
        self._debug['num_entries']['start'] = self._io.pos()
        self.num_entries = self._io.read_u2be()
        self._debug['num_entries']['end'] = self._io.pos()
        self._debug['entries']['start'] = self._io.pos()
        self.entries = [None] * (self.num_entries)
        for i in range(self.num_entries):
            if not 'arr' in self._debug['entries']:
                self._debug['entries']['arr'] = []
            self._debug['entries']['arr'].append({'start': self._io.pos()})
            _t_entries = self._root.Entry(self._io, self, self._root)
            _t_entries._read()
            self.entries[i] = _t_entries
            self._debug['entries']['arr'][i]['end'] = self._io.pos()

        self._debug['entries']['end'] = self._io.pos()

    class Entry(KaitaiStruct):

        class Types(Enum):
            data_fork = 1
            resource_fork = 2
            real_name = 3
            comment = 4
            icon_bw = 5
            icon_color = 6
            file_dates_info = 8
            finder_info = 9
            macintosh_file_info = 10
            prodos_file_info = 11
            msdos_file_info = 12
            afp_short_name = 13
            afp_file_info = 14
            afp_directory_id = 15
        SEQ_FIELDS = ["type", "ofs_body", "len_body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.Entry.Types, self._io.read_u4be())
            self._debug['type']['end'] = self._io.pos()
            self._debug['ofs_body']['start'] = self._io.pos()
            self.ofs_body = self._io.read_u4be()
            self._debug['ofs_body']['end'] = self._io.pos()
            self._debug['len_body']['start'] = self._io.pos()
            self.len_body = self._io.read_u4be()
            self._debug['len_body']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_body)
            self._debug['_m_body']['start'] = self._io.pos()
            _on = self.type
            if _on == self._root.Entry.Types.finder_info:
                self._raw__m_body = self._io.read_bytes(self.len_body)
                io = KaitaiStream(BytesIO(self._raw__m_body))
                self._m_body = self._root.FinderInfo(io, self, self._root)
                self._m_body._read()
            else:
                self._m_body = self._io.read_bytes(self.len_body)
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class FinderInfo(KaitaiStruct):
        """Information specific to Finder.
        
        .. seealso::
           older Inside Macintosh, Volume II page 84 or Volume IV page 104.
        """
        SEQ_FIELDS = ["file_type", "file_creator", "flags", "location", "folder_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['file_type']['start'] = self._io.pos()
            self.file_type = self._io.read_bytes(4)
            self._debug['file_type']['end'] = self._io.pos()
            self._debug['file_creator']['start'] = self._io.pos()
            self.file_creator = self._io.read_bytes(4)
            self._debug['file_creator']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2be()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['location']['start'] = self._io.pos()
            self.location = self._root.Point(self._io, self, self._root)
            self.location._read()
            self._debug['location']['end'] = self._io.pos()
            self._debug['folder_id']['start'] = self._io.pos()
            self.folder_id = self._io.read_u2be()
            self._debug['folder_id']['end'] = self._io.pos()


    class Point(KaitaiStruct):
        """Specifies 2D coordinate in QuickDraw grid."""
        SEQ_FIELDS = ["x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u2be()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u2be()
            self._debug['y']['end'] = self._io.pos()



