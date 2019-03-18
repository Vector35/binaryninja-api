from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class WindowsShellItems(KaitaiStruct):
    """Windows Shell Items (AKA "shellbags") is an undocumented set of
    structures used internally within Windows to identify paths in
    Windows Folder Hierarchy. It is widely used in Windows Shell (and
    most visible in File Explorer), both as in-memory and in-file
    structures. Some formats embed them, namely:
    
    * Windows Shell link files (.lnk) Windows registry
    * Windows registry "ShellBags" keys
    
    The format is mostly undocumented, and is known to vary between
    various Windows versions.
    
    .. seealso::
       Source - https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc
    """
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
            _t_items = self._root.ShellItem(self._io, self, self._root)
            _t_items._read()
            _ = _t_items
            self.items.append(_)
            self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
            if _.len_data == 0:
                break
            i += 1
        self._debug['items']['end'] = self._io.pos()

    class ShellItemData(KaitaiStruct):
        SEQ_FIELDS = ["code", "body1", "body2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = self._io.read_u1()
            self._debug['code']['end'] = self._io.pos()
            self._debug['body1']['start'] = self._io.pos()
            _on = self.code
            if _on == 31:
                self.body1 = self._root.RootFolderBody(self._io, self, self._root)
                self.body1._read()
            self._debug['body1']['end'] = self._io.pos()
            self._debug['body2']['start'] = self._io.pos()
            _on = (self.code & 112)
            if _on == 32:
                self.body2 = self._root.VolumeBody(self._io, self, self._root)
                self.body2._read()
            elif _on == 48:
                self.body2 = self._root.FileEntryBody(self._io, self, self._root)
                self.body2._read()
            self._debug['body2']['end'] = self._io.pos()


    class ShellItem(KaitaiStruct):
        """
        .. seealso::
           Section 2.2.2 - https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
        """
        SEQ_FIELDS = ["len_data", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = self._io.read_u2le()
            self._debug['len_data']['end'] = self._io.pos()
            if self.len_data >= 2:
                self._debug['data']['start'] = self._io.pos()
                self._raw_data = self._io.read_bytes((self.len_data - 2))
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.ShellItemData(io, self, self._root)
                self.data._read()
                self._debug['data']['end'] = self._io.pos()



    class RootFolderBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#32-root-folder-shell-item
        """
        SEQ_FIELDS = ["sort_index", "shell_folder_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sort_index']['start'] = self._io.pos()
            self.sort_index = self._io.read_u1()
            self._debug['sort_index']['end'] = self._io.pos()
            self._debug['shell_folder_id']['start'] = self._io.pos()
            self.shell_folder_id = self._io.read_bytes(16)
            self._debug['shell_folder_id']['end'] = self._io.pos()


    class VolumeBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#33-volume-shell-item
        """
        SEQ_FIELDS = ["flags"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u1()
            self._debug['flags']['end'] = self._io.pos()


    class FileEntryBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#34-file-entry-shell-item
        """
        SEQ_FIELDS = ["_unnamed0", "file_size", "last_mod_time", "file_attrs"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['_unnamed0']['start'] = self._io.pos()
            self._unnamed0 = self._io.read_u1()
            self._debug['_unnamed0']['end'] = self._io.pos()
            self._debug['file_size']['start'] = self._io.pos()
            self.file_size = self._io.read_u4le()
            self._debug['file_size']['end'] = self._io.pos()
            self._debug['last_mod_time']['start'] = self._io.pos()
            self.last_mod_time = self._io.read_u4le()
            self._debug['last_mod_time']['end'] = self._io.pos()
            self._debug['file_attrs']['start'] = self._io.pos()
            self.file_attrs = self._io.read_u2le()
            self._debug['file_attrs']['end'] = self._io.pos()

        @property
        def is_dir(self):
            if hasattr(self, '_m_is_dir'):
                return self._m_is_dir if hasattr(self, '_m_is_dir') else None

            self._m_is_dir = (self._parent.code & 1) != 0
            return self._m_is_dir if hasattr(self, '_m_is_dir') else None

        @property
        def is_file(self):
            if hasattr(self, '_m_is_file'):
                return self._m_is_file if hasattr(self, '_m_is_file') else None

            self._m_is_file = (self._parent.code & 2) != 0
            return self._m_is_file if hasattr(self, '_m_is_file') else None



