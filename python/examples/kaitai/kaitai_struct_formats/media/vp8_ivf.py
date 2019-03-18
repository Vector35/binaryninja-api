from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Vp8Ivf(KaitaiStruct):
    """IVF is a simple container format for raw VP8 data, which is an open
    and royalty-free video compression format, currently developed by
    Google.
    
    Test .ivf files are available at https://chromium.googlesource.com/webm/vp8-test-vectors
    
    .. seealso::
       Source - https://wiki.multimedia.cx/index.php/IVF
    """
    SEQ_FIELDS = ["magic1", "version", "len_header", "codec", "width", "height", "framerate", "timescale", "num_frames", "unused", "image_data"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic1']['start'] = self._io.pos()
        self.magic1 = self._io.ensure_fixed_contents(b"\x44\x4B\x49\x46")
        self._debug['magic1']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u2le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['len_header']['start'] = self._io.pos()
        self.len_header = self._io.read_u2le()
        self._debug['len_header']['end'] = self._io.pos()
        self._debug['codec']['start'] = self._io.pos()
        self.codec = self._io.ensure_fixed_contents(b"\x56\x50\x38\x30")
        self._debug['codec']['end'] = self._io.pos()
        self._debug['width']['start'] = self._io.pos()
        self.width = self._io.read_u2le()
        self._debug['width']['end'] = self._io.pos()
        self._debug['height']['start'] = self._io.pos()
        self.height = self._io.read_u2le()
        self._debug['height']['end'] = self._io.pos()
        self._debug['framerate']['start'] = self._io.pos()
        self.framerate = self._io.read_u4le()
        self._debug['framerate']['end'] = self._io.pos()
        self._debug['timescale']['start'] = self._io.pos()
        self.timescale = self._io.read_u4le()
        self._debug['timescale']['end'] = self._io.pos()
        self._debug['num_frames']['start'] = self._io.pos()
        self.num_frames = self._io.read_u4le()
        self._debug['num_frames']['end'] = self._io.pos()
        self._debug['unused']['start'] = self._io.pos()
        self.unused = self._io.read_u4le()
        self._debug['unused']['end'] = self._io.pos()
        self._debug['image_data']['start'] = self._io.pos()
        self.image_data = [None] * (self.num_frames)
        for i in range(self.num_frames):
            if not 'arr' in self._debug['image_data']:
                self._debug['image_data']['arr'] = []
            self._debug['image_data']['arr'].append({'start': self._io.pos()})
            _t_image_data = self._root.Blocks(self._io, self, self._root)
            _t_image_data._read()
            self.image_data[i] = _t_image_data
            self._debug['image_data']['arr'][i]['end'] = self._io.pos()

        self._debug['image_data']['end'] = self._io.pos()

    class Blocks(KaitaiStruct):
        SEQ_FIELDS = ["entries"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entries']['start'] = self._io.pos()
            self.entries = self._root.Block(self._io, self, self._root)
            self.entries._read()
            self._debug['entries']['end'] = self._io.pos()


    class Block(KaitaiStruct):
        SEQ_FIELDS = ["len_frame", "timestamp", "framedata"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_frame']['start'] = self._io.pos()
            self.len_frame = self._io.read_u4le()
            self._debug['len_frame']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_u8le()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['framedata']['start'] = self._io.pos()
            self.framedata = self._io.read_bytes(self.len_frame)
            self._debug['framedata']['end'] = self._io.pos()



