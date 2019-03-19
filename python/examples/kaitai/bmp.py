# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Bmp(KaitaiStruct):

    class Compressions(Enum):
        rgb = 0
        rle8 = 1
        rle4 = 2
        bitfields = 3
        jpeg = 4
        png = 5
        cmyk = 11
        cmyk_rle8 = 12
        cmyk_rle4 = 13
    SEQ_FIELDS = ["file_hdr", "len_dib_header", "dib_header"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['file_hdr']['start'] = self._io.pos()
        self.file_hdr = self._root.FileHeader(self._io, self, self._root)
        self.file_hdr._read()
        self._debug['file_hdr']['end'] = self._io.pos()
        self._debug['len_dib_header']['start'] = self._io.pos()
        self.len_dib_header = self._io.read_s4le()
        self._debug['len_dib_header']['end'] = self._io.pos()
        self._debug['dib_header']['start'] = self._io.pos()
        _on = self.len_dib_header
        if _on == 104:
            self._raw_dib_header = self._io.read_bytes((self.len_dib_header - 4))
            io = KaitaiStream(BytesIO(self._raw_dib_header))
            self.dib_header = self._root.BitmapCoreHeader(io, self, self._root)
            self.dib_header._read()
        elif _on == 12:
            self._raw_dib_header = self._io.read_bytes((self.len_dib_header - 4))
            io = KaitaiStream(BytesIO(self._raw_dib_header))
            self.dib_header = self._root.BitmapCoreHeader(io, self, self._root)
            self.dib_header._read()
        elif _on == 40:
            self._raw_dib_header = self._io.read_bytes((self.len_dib_header - 4))
            io = KaitaiStream(BytesIO(self._raw_dib_header))
            self.dib_header = self._root.BitmapInfoHeader(io, self, self._root)
            self.dib_header._read()
        elif _on == 124:
            self._raw_dib_header = self._io.read_bytes((self.len_dib_header - 4))
            io = KaitaiStream(BytesIO(self._raw_dib_header))
            self.dib_header = self._root.BitmapCoreHeader(io, self, self._root)
            self.dib_header._read()
        else:
            self.dib_header = self._io.read_bytes((self.len_dib_header - 4))
        self._debug['dib_header']['end'] = self._io.pos()

    class FileHeader(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/dd183374.aspx
        """
        SEQ_FIELDS = ["magic", "len_file", "reserved1", "reserved2", "ofs_bitmap"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x42\x4D")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['len_file']['start'] = self._io.pos()
            self.len_file = self._io.read_u4le()
            self._debug['len_file']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_u2le()
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_u2le()
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['ofs_bitmap']['start'] = self._io.pos()
            self.ofs_bitmap = self._io.read_s4le()
            self._debug['ofs_bitmap']['end'] = self._io.pos()


    class BitmapCoreHeader(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/dd183372.aspx
        """
        SEQ_FIELDS = ["image_width", "image_height", "num_planes", "bits_per_pixel"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['image_width']['start'] = self._io.pos()
            self.image_width = self._io.read_u2le()
            self._debug['image_width']['end'] = self._io.pos()
            self._debug['image_height']['start'] = self._io.pos()
            self.image_height = self._io.read_u2le()
            self._debug['image_height']['end'] = self._io.pos()
            self._debug['num_planes']['start'] = self._io.pos()
            self.num_planes = self._io.read_u2le()
            self._debug['num_planes']['end'] = self._io.pos()
            self._debug['bits_per_pixel']['start'] = self._io.pos()
            self.bits_per_pixel = self._io.read_u2le()
            self._debug['bits_per_pixel']['end'] = self._io.pos()


    class BitmapInfoHeader(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/dd183376.aspx
        """
        SEQ_FIELDS = ["image_width", "image_height", "num_planes", "bits_per_pixel", "compression", "len_image", "x_px_per_m", "y_px_per_m", "num_colors_used", "num_colors_important"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['image_width']['start'] = self._io.pos()
            self.image_width = self._io.read_u4le()
            self._debug['image_width']['end'] = self._io.pos()
            self._debug['image_height']['start'] = self._io.pos()
            self.image_height = self._io.read_u4le()
            self._debug['image_height']['end'] = self._io.pos()
            self._debug['num_planes']['start'] = self._io.pos()
            self.num_planes = self._io.read_u2le()
            self._debug['num_planes']['end'] = self._io.pos()
            self._debug['bits_per_pixel']['start'] = self._io.pos()
            self.bits_per_pixel = self._io.read_u2le()
            self._debug['bits_per_pixel']['end'] = self._io.pos()
            self._debug['compression']['start'] = self._io.pos()
            self.compression = KaitaiStream.resolve_enum(self._root.Compressions, self._io.read_u4le())
            self._debug['compression']['end'] = self._io.pos()
            self._debug['len_image']['start'] = self._io.pos()
            self.len_image = self._io.read_u4le()
            self._debug['len_image']['end'] = self._io.pos()
            self._debug['x_px_per_m']['start'] = self._io.pos()
            self.x_px_per_m = self._io.read_u4le()
            self._debug['x_px_per_m']['end'] = self._io.pos()
            self._debug['y_px_per_m']['start'] = self._io.pos()
            self.y_px_per_m = self._io.read_u4le()
            self._debug['y_px_per_m']['end'] = self._io.pos()
            self._debug['num_colors_used']['start'] = self._io.pos()
            self.num_colors_used = self._io.read_u4le()
            self._debug['num_colors_used']['end'] = self._io.pos()
            self._debug['num_colors_important']['start'] = self._io.pos()
            self.num_colors_important = self._io.read_u4le()
            self._debug['num_colors_important']['end'] = self._io.pos()


    @property
    def image(self):
        if hasattr(self, '_m_image'):
            return self._m_image if hasattr(self, '_m_image') else None

        _pos = self._io.pos()
        self._io.seek(self.file_hdr.ofs_bitmap)
        self._debug['_m_image']['start'] = self._io.pos()
        self._m_image = self._io.read_bytes_full()
        self._debug['_m_image']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_image if hasattr(self, '_m_image') else None


