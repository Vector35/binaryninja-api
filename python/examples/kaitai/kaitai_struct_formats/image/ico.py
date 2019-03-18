from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Ico(KaitaiStruct):
    """Microsoft Windows uses specific file format to store applications
    icons - ICO. This is a container that contains one or more image
    files (effectively, DIB parts of BMP files or full PNG files are
    contained inside).
    
    .. seealso::
       Source - https://msdn.microsoft.com/en-us/library/ms997538.aspx
    """
    SEQ_FIELDS = ["magic", "num_images", "images"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x00\x00\x01\x00")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['num_images']['start'] = self._io.pos()
        self.num_images = self._io.read_u2le()
        self._debug['num_images']['end'] = self._io.pos()
        self._debug['images']['start'] = self._io.pos()
        self.images = [None] * (self.num_images)
        for i in range(self.num_images):
            if not 'arr' in self._debug['images']:
                self._debug['images']['arr'] = []
            self._debug['images']['arr'].append({'start': self._io.pos()})
            _t_images = self._root.IconDirEntry(self._io, self, self._root)
            _t_images._read()
            self.images[i] = _t_images
            self._debug['images']['arr'][i]['end'] = self._io.pos()

        self._debug['images']['end'] = self._io.pos()

    class IconDirEntry(KaitaiStruct):
        SEQ_FIELDS = ["width", "height", "num_colors", "reserved", "num_planes", "bpp", "len_img", "ofs_img"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u1()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u1()
            self._debug['height']['end'] = self._io.pos()
            self._debug['num_colors']['start'] = self._io.pos()
            self.num_colors = self._io.read_u1()
            self._debug['num_colors']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.ensure_fixed_contents(b"\x00")
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['num_planes']['start'] = self._io.pos()
            self.num_planes = self._io.read_u2le()
            self._debug['num_planes']['end'] = self._io.pos()
            self._debug['bpp']['start'] = self._io.pos()
            self.bpp = self._io.read_u2le()
            self._debug['bpp']['end'] = self._io.pos()
            self._debug['len_img']['start'] = self._io.pos()
            self.len_img = self._io.read_u4le()
            self._debug['len_img']['end'] = self._io.pos()
            self._debug['ofs_img']['start'] = self._io.pos()
            self.ofs_img = self._io.read_u4le()
            self._debug['ofs_img']['end'] = self._io.pos()

        @property
        def img(self):
            """Raw image data. Use `is_png` to determine whether this is an
            embedded PNG file (true) or a DIB bitmap (false) and call a
            relevant parser, if needed to parse image data further.
            """
            if hasattr(self, '_m_img'):
                return self._m_img if hasattr(self, '_m_img') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_img)
            self._debug['_m_img']['start'] = self._io.pos()
            self._m_img = self._io.read_bytes(self.len_img)
            self._debug['_m_img']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_img if hasattr(self, '_m_img') else None

        @property
        def png_header(self):
            """Pre-reads first 8 bytes of the image to determine if it's an
            embedded PNG file.
            """
            if hasattr(self, '_m_png_header'):
                return self._m_png_header if hasattr(self, '_m_png_header') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_img)
            self._debug['_m_png_header']['start'] = self._io.pos()
            self._m_png_header = self._io.read_bytes(8)
            self._debug['_m_png_header']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_png_header if hasattr(self, '_m_png_header') else None

        @property
        def is_png(self):
            """True if this image is in PNG format."""
            if hasattr(self, '_m_is_png'):
                return self._m_is_png if hasattr(self, '_m_is_png') else None

            self._m_is_png = self.png_header == b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
            return self._m_is_png if hasattr(self, '_m_is_png') else None



