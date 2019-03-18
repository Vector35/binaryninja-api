from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Id3v23(KaitaiStruct):
    SEQ_FIELDS = ["tag"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['tag']['start'] = self._io.pos()
        self.tag = self._root.Tag(self._io, self, self._root)
        self.tag._read()
        self._debug['tag']['end'] = self._io.pos()

    class U1beSynchsafe(KaitaiStruct):
        SEQ_FIELDS = ["padding", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_bits_int(1) != 0
            self._debug['padding']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_bits_int(7)
            self._debug['value']['end'] = self._io.pos()


    class U2beSynchsafe(KaitaiStruct):
        SEQ_FIELDS = ["byte0", "byte1"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['byte0']['start'] = self._io.pos()
            self.byte0 = self._root.U1beSynchsafe(self._io, self, self._root)
            self.byte0._read()
            self._debug['byte0']['end'] = self._io.pos()
            self._debug['byte1']['start'] = self._io.pos()
            self.byte1 = self._root.U1beSynchsafe(self._io, self, self._root)
            self.byte1._read()
            self._debug['byte1']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = ((self.byte0.value << 7) | self.byte1.value)
            return self._m_value if hasattr(self, '_m_value') else None


    class Tag(KaitaiStruct):
        SEQ_FIELDS = ["header", "header_ex", "frames", "padding"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self.header = self._root.Header(self._io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            if self.header.flags.flag_headerex:
                self._debug['header_ex']['start'] = self._io.pos()
                self.header_ex = self._root.HeaderEx(self._io, self, self._root)
                self.header_ex._read()
                self._debug['header_ex']['end'] = self._io.pos()

            self._debug['frames']['start'] = self._io.pos()
            self.frames = []
            i = 0
            while True:
                if not 'arr' in self._debug['frames']:
                    self._debug['frames']['arr'] = []
                self._debug['frames']['arr'].append({'start': self._io.pos()})
                _t_frames = self._root.Frame(self._io, self, self._root)
                _t_frames._read()
                _ = _t_frames
                self.frames.append(_)
                self._debug['frames']['arr'][len(self.frames) - 1]['end'] = self._io.pos()
                if  (((self._io.pos() + _.size) > self.header.size.value) or (_.is_invalid)) :
                    break
                i += 1
            self._debug['frames']['end'] = self._io.pos()
            if self.header.flags.flag_headerex:
                self._debug['padding']['start'] = self._io.pos()
                self.padding = self._io.read_bytes((self.header_ex.padding_size - self._io.pos()))
                self._debug['padding']['end'] = self._io.pos()



    class U4beSynchsafe(KaitaiStruct):
        SEQ_FIELDS = ["short0", "short1"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['short0']['start'] = self._io.pos()
            self.short0 = self._root.U2beSynchsafe(self._io, self, self._root)
            self.short0._read()
            self._debug['short0']['end'] = self._io.pos()
            self._debug['short1']['start'] = self._io.pos()
            self.short1 = self._root.U2beSynchsafe(self._io, self, self._root)
            self.short1._read()
            self._debug['short1']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = ((self.short0.value << 14) | self.short1.value)
            return self._m_value if hasattr(self, '_m_value') else None


    class Frame(KaitaiStruct):
        SEQ_FIELDS = ["id", "size", "flags", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['id']['start'] = self._io.pos()
            self.id = (self._io.read_bytes(4)).decode(u"ASCII")
            self._debug['id']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4be()
            self._debug['size']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.Frame.Flags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes(self.size)
            self._debug['data']['end'] = self._io.pos()

        class Flags(KaitaiStruct):
            SEQ_FIELDS = ["flag_discard_alter_tag", "flag_discard_alter_file", "flag_read_only", "reserved1", "flag_compressed", "flag_encrypted", "flag_grouping", "reserved2"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['flag_discard_alter_tag']['start'] = self._io.pos()
                self.flag_discard_alter_tag = self._io.read_bits_int(1) != 0
                self._debug['flag_discard_alter_tag']['end'] = self._io.pos()
                self._debug['flag_discard_alter_file']['start'] = self._io.pos()
                self.flag_discard_alter_file = self._io.read_bits_int(1) != 0
                self._debug['flag_discard_alter_file']['end'] = self._io.pos()
                self._debug['flag_read_only']['start'] = self._io.pos()
                self.flag_read_only = self._io.read_bits_int(1) != 0
                self._debug['flag_read_only']['end'] = self._io.pos()
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.read_bits_int(5)
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['flag_compressed']['start'] = self._io.pos()
                self.flag_compressed = self._io.read_bits_int(1) != 0
                self._debug['flag_compressed']['end'] = self._io.pos()
                self._debug['flag_encrypted']['start'] = self._io.pos()
                self.flag_encrypted = self._io.read_bits_int(1) != 0
                self._debug['flag_encrypted']['end'] = self._io.pos()
                self._debug['flag_grouping']['start'] = self._io.pos()
                self.flag_grouping = self._io.read_bits_int(1) != 0
                self._debug['flag_grouping']['end'] = self._io.pos()
                self._debug['reserved2']['start'] = self._io.pos()
                self.reserved2 = self._io.read_bits_int(5)
                self._debug['reserved2']['end'] = self._io.pos()


        @property
        def is_invalid(self):
            if hasattr(self, '_m_is_invalid'):
                return self._m_is_invalid if hasattr(self, '_m_is_invalid') else None

            self._m_is_invalid = self.id == u"\000\000\000\000"
            return self._m_is_invalid if hasattr(self, '_m_is_invalid') else None


    class HeaderEx(KaitaiStruct):
        """ID3v2 extended header.
        
        .. seealso::
           Section 3.2. ID3v2 extended header
        """
        SEQ_FIELDS = ["size", "flags_ex", "padding_size", "crc"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4be()
            self._debug['size']['end'] = self._io.pos()
            self._debug['flags_ex']['start'] = self._io.pos()
            self.flags_ex = self._root.HeaderEx.FlagsEx(self._io, self, self._root)
            self.flags_ex._read()
            self._debug['flags_ex']['end'] = self._io.pos()
            self._debug['padding_size']['start'] = self._io.pos()
            self.padding_size = self._io.read_u4be()
            self._debug['padding_size']['end'] = self._io.pos()
            if self.flags_ex.flag_crc:
                self._debug['crc']['start'] = self._io.pos()
                self.crc = self._io.read_u4be()
                self._debug['crc']['end'] = self._io.pos()


        class FlagsEx(KaitaiStruct):
            SEQ_FIELDS = ["flag_crc", "reserved"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['flag_crc']['start'] = self._io.pos()
                self.flag_crc = self._io.read_bits_int(1) != 0
                self._debug['flag_crc']['end'] = self._io.pos()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bits_int(15)
                self._debug['reserved']['end'] = self._io.pos()



    class Header(KaitaiStruct):
        """ID3v2 fixed header.
        
        .. seealso::
           Section 3.1. ID3v2 header
        """
        SEQ_FIELDS = ["magic", "version_major", "version_revision", "flags", "size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x49\x44\x33")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version_major']['start'] = self._io.pos()
            self.version_major = self._io.read_u1()
            self._debug['version_major']['end'] = self._io.pos()
            self._debug['version_revision']['start'] = self._io.pos()
            self.version_revision = self._io.read_u1()
            self._debug['version_revision']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.Header.Flags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._root.U4beSynchsafe(self._io, self, self._root)
            self.size._read()
            self._debug['size']['end'] = self._io.pos()

        class Flags(KaitaiStruct):
            SEQ_FIELDS = ["flag_unsynchronization", "flag_headerex", "flag_experimental", "reserved"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['flag_unsynchronization']['start'] = self._io.pos()
                self.flag_unsynchronization = self._io.read_bits_int(1) != 0
                self._debug['flag_unsynchronization']['end'] = self._io.pos()
                self._debug['flag_headerex']['start'] = self._io.pos()
                self.flag_headerex = self._io.read_bits_int(1) != 0
                self._debug['flag_headerex']['end'] = self._io.pos()
                self._debug['flag_experimental']['start'] = self._io.pos()
                self.flag_experimental = self._io.read_bits_int(1) != 0
                self._debug['flag_experimental']['end'] = self._io.pos()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bits_int(5)
                self._debug['reserved']['end'] = self._io.pos()




