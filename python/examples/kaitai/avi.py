# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Avi(KaitaiStruct):
    """
    .. seealso::
       Source - https://msdn.microsoft.com/en-us/library/ms779636.aspx
    """

    class ChunkType(Enum):
        idx1 = 829973609
        junk = 1263424842
        info = 1330007625
        isft = 1413894985
        list = 1414744396
        strf = 1718776947
        avih = 1751742049
        strh = 1752331379
        movi = 1769369453
        hdrl = 1819436136
        strl = 1819440243

    class StreamType(Enum):
        mids = 1935960429
        vids = 1935960438
        auds = 1935963489
        txts = 1937012852

    class HandlerType(Enum):
        mp3 = 85
        ac3 = 8192
        dts = 8193
        cvid = 1684633187
        xvid = 1684633208
    SEQ_FIELDS = ["magic1", "file_size", "magic2", "data"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic1']['start'] = self._io.pos()
        self.magic1 = self._io.ensure_fixed_contents(b"\x52\x49\x46\x46")
        self._debug['magic1']['end'] = self._io.pos()
        self._debug['file_size']['start'] = self._io.pos()
        self.file_size = self._io.read_u4le()
        self._debug['file_size']['end'] = self._io.pos()
        self._debug['magic2']['start'] = self._io.pos()
        self.magic2 = self._io.ensure_fixed_contents(b"\x41\x56\x49\x20")
        self._debug['magic2']['end'] = self._io.pos()
        self._debug['data']['start'] = self._io.pos()
        self._raw_data = self._io.read_bytes((self.file_size - 4))
        io = KaitaiStream(BytesIO(self._raw_data))
        self.data = self._root.Blocks(io, self, self._root)
        self.data._read()
        self._debug['data']['end'] = self._io.pos()

    class ListBody(KaitaiStruct):
        SEQ_FIELDS = ["list_type", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['list_type']['start'] = self._io.pos()
            self.list_type = KaitaiStream.resolve_enum(self._root.ChunkType, self._io.read_u4le())
            self._debug['list_type']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._root.Blocks(self._io, self, self._root)
            self.data._read()
            self._debug['data']['end'] = self._io.pos()


    class Rect(KaitaiStruct):
        SEQ_FIELDS = ["left", "top", "right", "bottom"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['left']['start'] = self._io.pos()
            self.left = self._io.read_s2le()
            self._debug['left']['end'] = self._io.pos()
            self._debug['top']['start'] = self._io.pos()
            self.top = self._io.read_s2le()
            self._debug['top']['end'] = self._io.pos()
            self._debug['right']['start'] = self._io.pos()
            self.right = self._io.read_s2le()
            self._debug['right']['end'] = self._io.pos()
            self._debug['bottom']['start'] = self._io.pos()
            self.bottom = self._io.read_s2le()
            self._debug['bottom']['end'] = self._io.pos()


    class Blocks(KaitaiStruct):
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
                _t_entries = self._root.Block(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class AvihBody(KaitaiStruct):
        """Main header of an AVI file, defined as AVIMAINHEADER structure.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms779632.aspx
        """
        SEQ_FIELDS = ["micro_sec_per_frame", "max_bytes_per_sec", "padding_granularity", "flags", "total_frames", "initial_frames", "streams", "suggested_buffer_size", "width", "height", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['micro_sec_per_frame']['start'] = self._io.pos()
            self.micro_sec_per_frame = self._io.read_u4le()
            self._debug['micro_sec_per_frame']['end'] = self._io.pos()
            self._debug['max_bytes_per_sec']['start'] = self._io.pos()
            self.max_bytes_per_sec = self._io.read_u4le()
            self._debug['max_bytes_per_sec']['end'] = self._io.pos()
            self._debug['padding_granularity']['start'] = self._io.pos()
            self.padding_granularity = self._io.read_u4le()
            self._debug['padding_granularity']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['total_frames']['start'] = self._io.pos()
            self.total_frames = self._io.read_u4le()
            self._debug['total_frames']['end'] = self._io.pos()
            self._debug['initial_frames']['start'] = self._io.pos()
            self.initial_frames = self._io.read_u4le()
            self._debug['initial_frames']['end'] = self._io.pos()
            self._debug['streams']['start'] = self._io.pos()
            self.streams = self._io.read_u4le()
            self._debug['streams']['end'] = self._io.pos()
            self._debug['suggested_buffer_size']['start'] = self._io.pos()
            self.suggested_buffer_size = self._io.read_u4le()
            self._debug['suggested_buffer_size']['end'] = self._io.pos()
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u4le()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u4le()
            self._debug['height']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(16)
            self._debug['reserved']['end'] = self._io.pos()


    class Block(KaitaiStruct):
        SEQ_FIELDS = ["four_cc", "block_size", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['four_cc']['start'] = self._io.pos()
            self.four_cc = KaitaiStream.resolve_enum(self._root.ChunkType, self._io.read_u4le())
            self._debug['four_cc']['end'] = self._io.pos()
            self._debug['block_size']['start'] = self._io.pos()
            self.block_size = self._io.read_u4le()
            self._debug['block_size']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            _on = self.four_cc
            if _on == self._root.ChunkType.list:
                self._raw_data = self._io.read_bytes(self.block_size)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.ListBody(io, self, self._root)
                self.data._read()
            elif _on == self._root.ChunkType.avih:
                self._raw_data = self._io.read_bytes(self.block_size)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.AvihBody(io, self, self._root)
                self.data._read()
            elif _on == self._root.ChunkType.strh:
                self._raw_data = self._io.read_bytes(self.block_size)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.StrhBody(io, self, self._root)
                self.data._read()
            else:
                self.data = self._io.read_bytes(self.block_size)
            self._debug['data']['end'] = self._io.pos()


    class StrhBody(KaitaiStruct):
        """Stream header (one header per stream), defined as AVISTREAMHEADER structure.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms779638.aspx
        """
        SEQ_FIELDS = ["fcc_type", "fcc_handler", "flags", "priority", "language", "initial_frames", "scale", "rate", "start", "length", "suggested_buffer_size", "quality", "sample_size", "frame"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['fcc_type']['start'] = self._io.pos()
            self.fcc_type = KaitaiStream.resolve_enum(self._root.StreamType, self._io.read_u4le())
            self._debug['fcc_type']['end'] = self._io.pos()
            self._debug['fcc_handler']['start'] = self._io.pos()
            self.fcc_handler = KaitaiStream.resolve_enum(self._root.HandlerType, self._io.read_u4le())
            self._debug['fcc_handler']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['priority']['start'] = self._io.pos()
            self.priority = self._io.read_u2le()
            self._debug['priority']['end'] = self._io.pos()
            self._debug['language']['start'] = self._io.pos()
            self.language = self._io.read_u2le()
            self._debug['language']['end'] = self._io.pos()
            self._debug['initial_frames']['start'] = self._io.pos()
            self.initial_frames = self._io.read_u4le()
            self._debug['initial_frames']['end'] = self._io.pos()
            self._debug['scale']['start'] = self._io.pos()
            self.scale = self._io.read_u4le()
            self._debug['scale']['end'] = self._io.pos()
            self._debug['rate']['start'] = self._io.pos()
            self.rate = self._io.read_u4le()
            self._debug['rate']['end'] = self._io.pos()
            self._debug['start']['start'] = self._io.pos()
            self.start = self._io.read_u4le()
            self._debug['start']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u4le()
            self._debug['length']['end'] = self._io.pos()
            self._debug['suggested_buffer_size']['start'] = self._io.pos()
            self.suggested_buffer_size = self._io.read_u4le()
            self._debug['suggested_buffer_size']['end'] = self._io.pos()
            self._debug['quality']['start'] = self._io.pos()
            self.quality = self._io.read_u4le()
            self._debug['quality']['end'] = self._io.pos()
            self._debug['sample_size']['start'] = self._io.pos()
            self.sample_size = self._io.read_u4le()
            self._debug['sample_size']['end'] = self._io.pos()
            self._debug['frame']['start'] = self._io.pos()
            self.frame = self._root.Rect(self._io, self, self._root)
            self.frame._read()
            self._debug['frame']['end'] = self._io.pos()


    class StrfBody(KaitaiStruct):
        """Stream format description."""
        SEQ_FIELDS = []
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass



