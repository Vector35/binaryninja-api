from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class RtpPacket(KaitaiStruct):
    """The Real-time Transport Protocol (RTP) is a widely used network
    protocol for transmitting audio or video. It usually works with the
    RTP Control Protocol (RTCP). The transmission can be based on
    Transmission Control Protocol (TCP) or User Datagram Protocol (UDP).
    """

    class PayloadTypeEnum(Enum):
        pcmu = 0
        reserved1 = 1
        reserved2 = 2
        gsm = 3
        g723 = 4
        dvi4_1 = 5
        dvi4_2 = 6
        lpc = 7
        pama = 8
        g722 = 9
        l16_1 = 10
        l16_2 = 11
        qcelp = 12
        cn = 13
        mpa = 14
        g728 = 15
        dvi4_3 = 16
        dvi4_4 = 17
        g729 = 18
        reserved3 = 19
        unassigned1 = 20
        unassigned2 = 21
        unassigned3 = 22
        unassigned4 = 23
        unassigned5 = 24
        celb = 25
        jpeg = 26
        unassigned6 = 27
        nv = 28
        unassigned7 = 29
        unassigned8 = 30
        h261 = 31
        mpv = 32
        mp2t = 33
        h263 = 34
        mpeg_ps = 96
    SEQ_FIELDS = ["version", "has_padding", "has_extension", "csrc_count", "marker", "payload_type", "sequence_number", "timestamp", "ssrc", "header_extension", "data", "padding"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_bits_int(2)
        self._debug['version']['end'] = self._io.pos()
        self._debug['has_padding']['start'] = self._io.pos()
        self.has_padding = self._io.read_bits_int(1) != 0
        self._debug['has_padding']['end'] = self._io.pos()
        self._debug['has_extension']['start'] = self._io.pos()
        self.has_extension = self._io.read_bits_int(1) != 0
        self._debug['has_extension']['end'] = self._io.pos()
        self._debug['csrc_count']['start'] = self._io.pos()
        self.csrc_count = self._io.read_bits_int(4)
        self._debug['csrc_count']['end'] = self._io.pos()
        self._debug['marker']['start'] = self._io.pos()
        self.marker = self._io.read_bits_int(1) != 0
        self._debug['marker']['end'] = self._io.pos()
        self._debug['payload_type']['start'] = self._io.pos()
        self.payload_type = KaitaiStream.resolve_enum(self._root.PayloadTypeEnum, self._io.read_bits_int(7))
        self._debug['payload_type']['end'] = self._io.pos()
        self._io.align_to_byte()
        self._debug['sequence_number']['start'] = self._io.pos()
        self.sequence_number = self._io.read_u2be()
        self._debug['sequence_number']['end'] = self._io.pos()
        self._debug['timestamp']['start'] = self._io.pos()
        self.timestamp = self._io.read_u4be()
        self._debug['timestamp']['end'] = self._io.pos()
        self._debug['ssrc']['start'] = self._io.pos()
        self.ssrc = self._io.read_u4be()
        self._debug['ssrc']['end'] = self._io.pos()
        if self.has_extension:
            self._debug['header_extension']['start'] = self._io.pos()
            self.header_extension = self._root.HeaderExtention(self._io, self, self._root)
            self.header_extension._read()
            self._debug['header_extension']['end'] = self._io.pos()

        self._debug['data']['start'] = self._io.pos()
        self.data = self._io.read_bytes(((self._io.size() - self._io.pos()) - self.len_padding))
        self._debug['data']['end'] = self._io.pos()
        self._debug['padding']['start'] = self._io.pos()
        self.padding = self._io.read_bytes(self.len_padding)
        self._debug['padding']['end'] = self._io.pos()

    class HeaderExtention(KaitaiStruct):
        SEQ_FIELDS = ["id", "length"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['id']['start'] = self._io.pos()
            self.id = self._io.read_u2be()
            self._debug['id']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u2be()
            self._debug['length']['end'] = self._io.pos()


    @property
    def len_padding_if_exists(self):
        """If padding bit is enabled, last byte of data contains number of
        bytes appended to the payload as padding.
        """
        if hasattr(self, '_m_len_padding_if_exists'):
            return self._m_len_padding_if_exists if hasattr(self, '_m_len_padding_if_exists') else None

        if self.has_padding:
            _pos = self._io.pos()
            self._io.seek((self._io.size() - 1))
            self._debug['_m_len_padding_if_exists']['start'] = self._io.pos()
            self._m_len_padding_if_exists = self._io.read_u1()
            self._debug['_m_len_padding_if_exists']['end'] = self._io.pos()
            self._io.seek(_pos)

        return self._m_len_padding_if_exists if hasattr(self, '_m_len_padding_if_exists') else None

    @property
    def len_padding(self):
        """Always returns number of padding bytes to in the payload."""
        if hasattr(self, '_m_len_padding'):
            return self._m_len_padding if hasattr(self, '_m_len_padding') else None

        self._m_len_padding = (self.len_padding_if_exists if self.has_padding else 0)
        return self._m_len_padding if hasattr(self, '_m_len_padding') else None


