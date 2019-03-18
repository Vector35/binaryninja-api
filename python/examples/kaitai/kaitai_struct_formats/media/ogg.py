from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Ogg(KaitaiStruct):
    """Ogg is a popular media container format, which provides basic
    streaming / buffering mechanisms and is content-agnostic. Most
    popular codecs that are used within Ogg streams are Vorbis (thus
    making Ogg/Vorbis streams) and Theora (Ogg/Theora).
    
    Ogg stream is a sequence Ogg pages. They can be read sequentially,
    or one can jump into arbitrary stream location and scan for "OggS"
    sync code to find the beginning of a new Ogg page and continue
    decoding the stream contents from that one.
    """
    SEQ_FIELDS = ["pages"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['pages']['start'] = self._io.pos()
        self.pages = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['pages']:
                self._debug['pages']['arr'] = []
            self._debug['pages']['arr'].append({'start': self._io.pos()})
            _t_pages = self._root.Page(self._io, self, self._root)
            _t_pages._read()
            self.pages.append(_t_pages)
            self._debug['pages']['arr'][len(self.pages) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['pages']['end'] = self._io.pos()

    class Page(KaitaiStruct):
        """Ogg page is a basic unit of data in an Ogg bitstream, usually
        it's around 4-8 KB, with a maximum size of 65307 bytes.
        """
        SEQ_FIELDS = ["sync_code", "version", "reserved1", "is_end_of_stream", "is_beginning_of_stream", "is_continuation", "granule_pos", "bitstream_serial", "page_seq_num", "crc32", "num_segments", "len_segments", "segments"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sync_code']['start'] = self._io.pos()
            self.sync_code = self._io.ensure_fixed_contents(b"\x4F\x67\x67\x53")
            self._debug['sync_code']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.ensure_fixed_contents(b"\x00")
            self._debug['version']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(5)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['is_end_of_stream']['start'] = self._io.pos()
            self.is_end_of_stream = self._io.read_bits_int(1) != 0
            self._debug['is_end_of_stream']['end'] = self._io.pos()
            self._debug['is_beginning_of_stream']['start'] = self._io.pos()
            self.is_beginning_of_stream = self._io.read_bits_int(1) != 0
            self._debug['is_beginning_of_stream']['end'] = self._io.pos()
            self._debug['is_continuation']['start'] = self._io.pos()
            self.is_continuation = self._io.read_bits_int(1) != 0
            self._debug['is_continuation']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['granule_pos']['start'] = self._io.pos()
            self.granule_pos = self._io.read_u8le()
            self._debug['granule_pos']['end'] = self._io.pos()
            self._debug['bitstream_serial']['start'] = self._io.pos()
            self.bitstream_serial = self._io.read_u4le()
            self._debug['bitstream_serial']['end'] = self._io.pos()
            self._debug['page_seq_num']['start'] = self._io.pos()
            self.page_seq_num = self._io.read_u4le()
            self._debug['page_seq_num']['end'] = self._io.pos()
            self._debug['crc32']['start'] = self._io.pos()
            self.crc32 = self._io.read_u4le()
            self._debug['crc32']['end'] = self._io.pos()
            self._debug['num_segments']['start'] = self._io.pos()
            self.num_segments = self._io.read_u1()
            self._debug['num_segments']['end'] = self._io.pos()
            self._debug['len_segments']['start'] = self._io.pos()
            self.len_segments = [None] * (self.num_segments)
            for i in range(self.num_segments):
                if not 'arr' in self._debug['len_segments']:
                    self._debug['len_segments']['arr'] = []
                self._debug['len_segments']['arr'].append({'start': self._io.pos()})
                self.len_segments[i] = self._io.read_u1()
                self._debug['len_segments']['arr'][i]['end'] = self._io.pos()

            self._debug['len_segments']['end'] = self._io.pos()
            self._debug['segments']['start'] = self._io.pos()
            self.segments = [None] * (self.num_segments)
            for i in range(self.num_segments):
                if not 'arr' in self._debug['segments']:
                    self._debug['segments']['arr'] = []
                self._debug['segments']['arr'].append({'start': self._io.pos()})
                self.segments[i] = self._io.read_bytes(self.len_segments[i])
                self._debug['segments']['arr'][i]['end'] = self._io.pos()

            self._debug['segments']['end'] = self._io.pos()



