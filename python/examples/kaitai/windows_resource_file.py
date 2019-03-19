# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class WindowsResourceFile(KaitaiStruct):
    """Windows resource file (.res) are binary bundles of
    "resources". Resource has some sort of ID (numerical or string),
    type (predefined or user-defined), and raw value. Resource files can
    be seen standalone (as .res file), or embedded inside PE executable
    (.exe, .dll) files.
    
    Typical use cases include:
    
    * providing information about the application (such as title, copyrights, etc)
    * embedding icon(s) to be displayed in file managers into .exe
    * adding non-code data into the binary, such as menus, dialog forms,
      cursor images, fonts, various misc bitmaps, and locale-aware
      strings
    
    Windows provides special API to access "resources" from a binary.
    
    Normally, resources files are created with `rc` compiler: it takes a
    .rc file (so called "resource-definition script") + all the raw
    resource binary files for input, and outputs .res file. That .res
    file can be linked into an .exe / .dll afterwards using a linker.
    
    Internally, resource file is just a sequence of individual resource
    definitions. RC tool ensures that first resource (#0) is always
    empty.
    """
    SEQ_FIELDS = ["resources"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['resources']['start'] = self._io.pos()
        self.resources = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['resources']:
                self._debug['resources']['arr'] = []
            self._debug['resources']['arr'].append({'start': self._io.pos()})
            _t_resources = self._root.Resource(self._io, self, self._root)
            _t_resources._read()
            self.resources.append(_t_resources)
            self._debug['resources']['arr'][len(self.resources) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['resources']['end'] = self._io.pos()

    class Resource(KaitaiStruct):
        """Each resource has a `type` and a `name`, which can be used to
        identify it, and a `value`. Both `type` and `name` can be a
        number or a string.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/windows/desktop/ms648027.aspx
        """

        class PredefTypes(Enum):
            cursor = 1
            bitmap = 2
            icon = 3
            menu = 4
            dialog = 5
            string = 6
            fontdir = 7
            font = 8
            accelerator = 9
            rcdata = 10
            messagetable = 11
            group_cursor = 12
            group_icon = 14
            version = 16
            dlginclude = 17
            plugplay = 19
            vxd = 20
            anicursor = 21
            aniicon = 22
            html = 23
            manifest = 24
        SEQ_FIELDS = ["value_size", "header_size", "type", "name", "padding1", "format_version", "flags", "language", "value_version", "characteristics", "value", "padding2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value_size']['start'] = self._io.pos()
            self.value_size = self._io.read_u4le()
            self._debug['value_size']['end'] = self._io.pos()
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u4le()
            self._debug['header_size']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = self._root.UnicodeOrId(self._io, self, self._root)
            self.type._read()
            self._debug['type']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.UnicodeOrId(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()
            self._debug['padding1']['start'] = self._io.pos()
            self.padding1 = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self._debug['padding1']['end'] = self._io.pos()
            self._debug['format_version']['start'] = self._io.pos()
            self.format_version = self._io.read_u4le()
            self._debug['format_version']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['language']['start'] = self._io.pos()
            self.language = self._io.read_u2le()
            self._debug['language']['end'] = self._io.pos()
            self._debug['value_version']['start'] = self._io.pos()
            self.value_version = self._io.read_u4le()
            self._debug['value_version']['end'] = self._io.pos()
            self._debug['characteristics']['start'] = self._io.pos()
            self.characteristics = self._io.read_u4le()
            self._debug['characteristics']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_bytes(self.value_size)
            self._debug['value']['end'] = self._io.pos()
            self._debug['padding2']['start'] = self._io.pos()
            self.padding2 = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self._debug['padding2']['end'] = self._io.pos()

        @property
        def type_as_predef(self):
            """Numeric type IDs in range of [0..0xff] are reserved for
            system usage in Windows, and there are some predefined,
            well-known values in that range. This instance allows to get
            it as enum value, if applicable.
            """
            if hasattr(self, '_m_type_as_predef'):
                return self._m_type_as_predef if hasattr(self, '_m_type_as_predef') else None

            if  ((not (self.type.is_string)) and (self.type.as_numeric <= 255)) :
                self._m_type_as_predef = KaitaiStream.resolve_enum(self._root.Resource.PredefTypes, self.type.as_numeric)

            return self._m_type_as_predef if hasattr(self, '_m_type_as_predef') else None


    class UnicodeOrId(KaitaiStruct):
        """Resources use a special serialization of names and types: they
        can be either a number or a string.
        
        Use `is_string` to check which kind we've got here, and then use
        `as_numeric` or `as_string` to get relevant value.
        """
        SEQ_FIELDS = ["first", "as_numeric", "rest", "noop"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if self.save_pos1 >= 0:
                self._debug['first']['start'] = self._io.pos()
                self.first = self._io.read_u2le()
                self._debug['first']['end'] = self._io.pos()

            if not (self.is_string):
                self._debug['as_numeric']['start'] = self._io.pos()
                self.as_numeric = self._io.read_u2le()
                self._debug['as_numeric']['end'] = self._io.pos()

            if self.is_string:
                self._debug['rest']['start'] = self._io.pos()
                self.rest = []
                i = 0
                while True:
                    if not 'arr' in self._debug['rest']:
                        self._debug['rest']['arr'] = []
                    self._debug['rest']['arr'].append({'start': self._io.pos()})
                    _ = self._io.read_u2le()
                    self.rest.append(_)
                    self._debug['rest']['arr'][len(self.rest) - 1]['end'] = self._io.pos()
                    if _ == 0:
                        break
                    i += 1
                self._debug['rest']['end'] = self._io.pos()

            if  ((self.is_string) and (self.save_pos2 >= 0)) :
                self._debug['noop']['start'] = self._io.pos()
                self.noop = self._io.read_bytes(0)
                self._debug['noop']['end'] = self._io.pos()


        @property
        def save_pos1(self):
            if hasattr(self, '_m_save_pos1'):
                return self._m_save_pos1 if hasattr(self, '_m_save_pos1') else None

            self._m_save_pos1 = self._io.pos()
            return self._m_save_pos1 if hasattr(self, '_m_save_pos1') else None

        @property
        def save_pos2(self):
            if hasattr(self, '_m_save_pos2'):
                return self._m_save_pos2 if hasattr(self, '_m_save_pos2') else None

            self._m_save_pos2 = self._io.pos()
            return self._m_save_pos2 if hasattr(self, '_m_save_pos2') else None

        @property
        def is_string(self):
            if hasattr(self, '_m_is_string'):
                return self._m_is_string if hasattr(self, '_m_is_string') else None

            self._m_is_string = self.first != 65535
            return self._m_is_string if hasattr(self, '_m_is_string') else None

        @property
        def as_string(self):
            if hasattr(self, '_m_as_string'):
                return self._m_as_string if hasattr(self, '_m_as_string') else None

            if self.is_string:
                _pos = self._io.pos()
                self._io.seek(self.save_pos1)
                self._debug['_m_as_string']['start'] = self._io.pos()
                self._m_as_string = (self._io.read_bytes(((self.save_pos2 - self.save_pos1) - 2))).decode(u"UTF-16LE")
                self._debug['_m_as_string']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_as_string if hasattr(self, '_m_as_string') else None



