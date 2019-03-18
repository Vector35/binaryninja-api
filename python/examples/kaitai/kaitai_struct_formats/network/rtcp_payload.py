from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class RtcpPayload(KaitaiStruct):
    """RTCP is the Real-Time Control Protocol.
    
    .. seealso::
       Source - https://tools.ietf.org/html/rfc3550
    """

    class PayloadType(Enum):
        fir = 192
        nack = 193
        ij = 195
        sr = 200
        rr = 201
        sdes = 202
        bye = 203
        app = 204
        rtpfb = 205
        psfb = 206
        xr = 207
        avb = 208
        rsi = 209

    class SdesSubtype(Enum):
        pad = 0
        cname = 1
        name = 2
        email = 3
        phone = 4
        loc = 5
        tool = 6
        note = 7
        priv = 8

    class PsfbSubtype(Enum):
        pli = 1
        sli = 2
        rpsi = 3
        fir = 4
        tstr = 5
        tstn = 6
        vbcm = 7
        afb = 15

    class RtpfbSubtype(Enum):
        nack = 1
        tmmbr = 3
        tmmbn = 4
        rrr = 5
        transport_feedback = 15
    SEQ_FIELDS = ["rtcp_packets"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['rtcp_packets']['start'] = self._io.pos()
        self.rtcp_packets = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['rtcp_packets']:
                self._debug['rtcp_packets']['arr'] = []
            self._debug['rtcp_packets']['arr'].append({'start': self._io.pos()})
            _t_rtcp_packets = self._root.RtcpPacket(self._io, self, self._root)
            _t_rtcp_packets._read()
            self.rtcp_packets.append(_t_rtcp_packets)
            self._debug['rtcp_packets']['arr'][len(self.rtcp_packets) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['rtcp_packets']['end'] = self._io.pos()

    class PsfbAfbRembPacket(KaitaiStruct):
        SEQ_FIELDS = ["num_ssrc", "br_exp", "br_mantissa", "ssrc_list"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_ssrc']['start'] = self._io.pos()
            self.num_ssrc = self._io.read_u1()
            self._debug['num_ssrc']['end'] = self._io.pos()
            self._debug['br_exp']['start'] = self._io.pos()
            self.br_exp = self._io.read_bits_int(6)
            self._debug['br_exp']['end'] = self._io.pos()
            self._debug['br_mantissa']['start'] = self._io.pos()
            self.br_mantissa = self._io.read_bits_int(18)
            self._debug['br_mantissa']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['ssrc_list']['start'] = self._io.pos()
            self.ssrc_list = [None] * (self.num_ssrc)
            for i in range(self.num_ssrc):
                if not 'arr' in self._debug['ssrc_list']:
                    self._debug['ssrc_list']['arr'] = []
                self._debug['ssrc_list']['arr'].append({'start': self._io.pos()})
                self.ssrc_list[i] = self._io.read_u4be()
                self._debug['ssrc_list']['arr'][i]['end'] = self._io.pos()

            self._debug['ssrc_list']['end'] = self._io.pos()

        @property
        def max_total_bitrate(self):
            if hasattr(self, '_m_max_total_bitrate'):
                return self._m_max_total_bitrate if hasattr(self, '_m_max_total_bitrate') else None

            self._m_max_total_bitrate = (self.br_mantissa * (1 << self.br_exp))
            return self._m_max_total_bitrate if hasattr(self, '_m_max_total_bitrate') else None


    class SrPacket(KaitaiStruct):
        SEQ_FIELDS = ["ssrc", "ntp_msw", "ntp_lsw", "rtp_timestamp", "sender_packet_count", "sender_octet_count", "report_block"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc']['start'] = self._io.pos()
            self.ssrc = self._io.read_u4be()
            self._debug['ssrc']['end'] = self._io.pos()
            self._debug['ntp_msw']['start'] = self._io.pos()
            self.ntp_msw = self._io.read_u4be()
            self._debug['ntp_msw']['end'] = self._io.pos()
            self._debug['ntp_lsw']['start'] = self._io.pos()
            self.ntp_lsw = self._io.read_u4be()
            self._debug['ntp_lsw']['end'] = self._io.pos()
            self._debug['rtp_timestamp']['start'] = self._io.pos()
            self.rtp_timestamp = self._io.read_u4be()
            self._debug['rtp_timestamp']['end'] = self._io.pos()
            self._debug['sender_packet_count']['start'] = self._io.pos()
            self.sender_packet_count = self._io.read_u4be()
            self._debug['sender_packet_count']['end'] = self._io.pos()
            self._debug['sender_octet_count']['start'] = self._io.pos()
            self.sender_octet_count = self._io.read_u4be()
            self._debug['sender_octet_count']['end'] = self._io.pos()
            self._debug['report_block']['start'] = self._io.pos()
            self.report_block = [None] * (self._parent.subtype)
            for i in range(self._parent.subtype):
                if not 'arr' in self._debug['report_block']:
                    self._debug['report_block']['arr'] = []
                self._debug['report_block']['arr'].append({'start': self._io.pos()})
                _t_report_block = self._root.ReportBlock(self._io, self, self._root)
                _t_report_block._read()
                self.report_block[i] = _t_report_block
                self._debug['report_block']['arr'][i]['end'] = self._io.pos()

            self._debug['report_block']['end'] = self._io.pos()

        @property
        def ntp(self):
            if hasattr(self, '_m_ntp'):
                return self._m_ntp if hasattr(self, '_m_ntp') else None

            self._m_ntp = ((self.ntp_msw << 32) & self.ntp_lsw)
            return self._m_ntp if hasattr(self, '_m_ntp') else None


    class RrPacket(KaitaiStruct):
        SEQ_FIELDS = ["ssrc", "report_block"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc']['start'] = self._io.pos()
            self.ssrc = self._io.read_u4be()
            self._debug['ssrc']['end'] = self._io.pos()
            self._debug['report_block']['start'] = self._io.pos()
            self.report_block = [None] * (self._parent.subtype)
            for i in range(self._parent.subtype):
                if not 'arr' in self._debug['report_block']:
                    self._debug['report_block']['arr'] = []
                self._debug['report_block']['arr'].append({'start': self._io.pos()})
                _t_report_block = self._root.ReportBlock(self._io, self, self._root)
                _t_report_block._read()
                self.report_block[i] = _t_report_block
                self._debug['report_block']['arr'][i]['end'] = self._io.pos()

            self._debug['report_block']['end'] = self._io.pos()


    class RtcpPacket(KaitaiStruct):
        SEQ_FIELDS = ["version", "padding", "subtype", "payload_type", "length", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_bits_int(2)
            self._debug['version']['end'] = self._io.pos()
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_bits_int(1) != 0
            self._debug['padding']['end'] = self._io.pos()
            self._debug['subtype']['start'] = self._io.pos()
            self.subtype = self._io.read_bits_int(5)
            self._debug['subtype']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['payload_type']['start'] = self._io.pos()
            self.payload_type = KaitaiStream.resolve_enum(self._root.PayloadType, self._io.read_u1())
            self._debug['payload_type']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u2be()
            self._debug['length']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.payload_type
            if _on == self._root.PayloadType.sr:
                self._raw_body = self._io.read_bytes((4 * self.length))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SrPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PayloadType.psfb:
                self._raw_body = self._io.read_bytes((4 * self.length))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.PsfbPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PayloadType.rr:
                self._raw_body = self._io.read_bytes((4 * self.length))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RrPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PayloadType.rtpfb:
                self._raw_body = self._io.read_bytes((4 * self.length))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RtpfbPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PayloadType.sdes:
                self._raw_body = self._io.read_bytes((4 * self.length))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SdesPacket(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes((4 * self.length))
            self._debug['body']['end'] = self._io.pos()


    class SdesTlv(KaitaiStruct):
        SEQ_FIELDS = ["type", "length", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.SdesSubtype, self._io.read_u1())
            self._debug['type']['end'] = self._io.pos()
            if self.type != self._root.SdesSubtype.pad:
                self._debug['length']['start'] = self._io.pos()
                self.length = self._io.read_u1()
                self._debug['length']['end'] = self._io.pos()

            if self.type != self._root.SdesSubtype.pad:
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_bytes(self.length)
                self._debug['value']['end'] = self._io.pos()



    class ReportBlock(KaitaiStruct):
        SEQ_FIELDS = ["ssrc_source", "lost_val", "highest_seq_num_received", "interarrival_jitter", "lsr", "dlsr"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc_source']['start'] = self._io.pos()
            self.ssrc_source = self._io.read_u4be()
            self._debug['ssrc_source']['end'] = self._io.pos()
            self._debug['lost_val']['start'] = self._io.pos()
            self.lost_val = self._io.read_u1()
            self._debug['lost_val']['end'] = self._io.pos()
            self._debug['highest_seq_num_received']['start'] = self._io.pos()
            self.highest_seq_num_received = self._io.read_u4be()
            self._debug['highest_seq_num_received']['end'] = self._io.pos()
            self._debug['interarrival_jitter']['start'] = self._io.pos()
            self.interarrival_jitter = self._io.read_u4be()
            self._debug['interarrival_jitter']['end'] = self._io.pos()
            self._debug['lsr']['start'] = self._io.pos()
            self.lsr = self._io.read_u4be()
            self._debug['lsr']['end'] = self._io.pos()
            self._debug['dlsr']['start'] = self._io.pos()
            self.dlsr = self._io.read_u4be()
            self._debug['dlsr']['end'] = self._io.pos()

        @property
        def fraction_lost(self):
            if hasattr(self, '_m_fraction_lost'):
                return self._m_fraction_lost if hasattr(self, '_m_fraction_lost') else None

            self._m_fraction_lost = (self.lost_val >> 24)
            return self._m_fraction_lost if hasattr(self, '_m_fraction_lost') else None

        @property
        def cumulative_packets_lost(self):
            if hasattr(self, '_m_cumulative_packets_lost'):
                return self._m_cumulative_packets_lost if hasattr(self, '_m_cumulative_packets_lost') else None

            self._m_cumulative_packets_lost = (self.lost_val & 16777215)
            return self._m_cumulative_packets_lost if hasattr(self, '_m_cumulative_packets_lost') else None


    class RtpfbTransportFeedbackPacket(KaitaiStruct):
        SEQ_FIELDS = ["base_sequence_number", "packet_status_count", "b4", "remaining"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['base_sequence_number']['start'] = self._io.pos()
            self.base_sequence_number = self._io.read_u2be()
            self._debug['base_sequence_number']['end'] = self._io.pos()
            self._debug['packet_status_count']['start'] = self._io.pos()
            self.packet_status_count = self._io.read_u2be()
            self._debug['packet_status_count']['end'] = self._io.pos()
            self._debug['b4']['start'] = self._io.pos()
            self.b4 = self._io.read_u4be()
            self._debug['b4']['end'] = self._io.pos()
            self._debug['remaining']['start'] = self._io.pos()
            self.remaining = self._io.read_bytes_full()
            self._debug['remaining']['end'] = self._io.pos()

        @property
        def reference_time(self):
            if hasattr(self, '_m_reference_time'):
                return self._m_reference_time if hasattr(self, '_m_reference_time') else None

            self._m_reference_time = (self.b4 >> 8)
            return self._m_reference_time if hasattr(self, '_m_reference_time') else None

        @property
        def fb_pkt_count(self):
            if hasattr(self, '_m_fb_pkt_count'):
                return self._m_fb_pkt_count if hasattr(self, '_m_fb_pkt_count') else None

            self._m_fb_pkt_count = (self.b4 & 255)
            return self._m_fb_pkt_count if hasattr(self, '_m_fb_pkt_count') else None

        @property
        def packet_status(self):
            if hasattr(self, '_m_packet_status'):
                return self._m_packet_status if hasattr(self, '_m_packet_status') else None

            self._debug['_m_packet_status']['start'] = self._io.pos()
            self._m_packet_status = self._io.read_bytes(0)
            self._debug['_m_packet_status']['end'] = self._io.pos()
            return self._m_packet_status if hasattr(self, '_m_packet_status') else None

        @property
        def recv_delta(self):
            if hasattr(self, '_m_recv_delta'):
                return self._m_recv_delta if hasattr(self, '_m_recv_delta') else None

            self._debug['_m_recv_delta']['start'] = self._io.pos()
            self._m_recv_delta = self._io.read_bytes(0)
            self._debug['_m_recv_delta']['end'] = self._io.pos()
            return self._m_recv_delta if hasattr(self, '_m_recv_delta') else None


    class PsfbPacket(KaitaiStruct):
        SEQ_FIELDS = ["ssrc", "ssrc_media_source", "fci_block"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc']['start'] = self._io.pos()
            self.ssrc = self._io.read_u4be()
            self._debug['ssrc']['end'] = self._io.pos()
            self._debug['ssrc_media_source']['start'] = self._io.pos()
            self.ssrc_media_source = self._io.read_u4be()
            self._debug['ssrc_media_source']['end'] = self._io.pos()
            self._debug['fci_block']['start'] = self._io.pos()
            _on = self.fmt
            if _on == self._root.PsfbSubtype.afb:
                self._raw_fci_block = self._io.read_bytes_full()
                io = KaitaiStream(BytesIO(self._raw_fci_block))
                self.fci_block = self._root.PsfbAfbPacket(io, self, self._root)
                self.fci_block._read()
            else:
                self.fci_block = self._io.read_bytes_full()
            self._debug['fci_block']['end'] = self._io.pos()

        @property
        def fmt(self):
            if hasattr(self, '_m_fmt'):
                return self._m_fmt if hasattr(self, '_m_fmt') else None

            self._m_fmt = KaitaiStream.resolve_enum(self._root.PsfbSubtype, self._parent.subtype)
            return self._m_fmt if hasattr(self, '_m_fmt') else None


    class SourceChunk(KaitaiStruct):
        SEQ_FIELDS = ["ssrc", "sdes_tlv"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc']['start'] = self._io.pos()
            self.ssrc = self._io.read_u4be()
            self._debug['ssrc']['end'] = self._io.pos()
            self._debug['sdes_tlv']['start'] = self._io.pos()
            self.sdes_tlv = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['sdes_tlv']:
                    self._debug['sdes_tlv']['arr'] = []
                self._debug['sdes_tlv']['arr'].append({'start': self._io.pos()})
                _t_sdes_tlv = self._root.SdesTlv(self._io, self, self._root)
                _t_sdes_tlv._read()
                self.sdes_tlv.append(_t_sdes_tlv)
                self._debug['sdes_tlv']['arr'][len(self.sdes_tlv) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['sdes_tlv']['end'] = self._io.pos()


    class SdesPacket(KaitaiStruct):
        SEQ_FIELDS = ["source_chunk"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['source_chunk']['start'] = self._io.pos()
            self.source_chunk = [None] * (self.source_count)
            for i in range(self.source_count):
                if not 'arr' in self._debug['source_chunk']:
                    self._debug['source_chunk']['arr'] = []
                self._debug['source_chunk']['arr'].append({'start': self._io.pos()})
                _t_source_chunk = self._root.SourceChunk(self._io, self, self._root)
                _t_source_chunk._read()
                self.source_chunk[i] = _t_source_chunk
                self._debug['source_chunk']['arr'][i]['end'] = self._io.pos()

            self._debug['source_chunk']['end'] = self._io.pos()

        @property
        def source_count(self):
            if hasattr(self, '_m_source_count'):
                return self._m_source_count if hasattr(self, '_m_source_count') else None

            self._m_source_count = self._parent.subtype
            return self._m_source_count if hasattr(self, '_m_source_count') else None


    class RtpfbPacket(KaitaiStruct):
        SEQ_FIELDS = ["ssrc", "ssrc_media_source", "fci_block"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ssrc']['start'] = self._io.pos()
            self.ssrc = self._io.read_u4be()
            self._debug['ssrc']['end'] = self._io.pos()
            self._debug['ssrc_media_source']['start'] = self._io.pos()
            self.ssrc_media_source = self._io.read_u4be()
            self._debug['ssrc_media_source']['end'] = self._io.pos()
            self._debug['fci_block']['start'] = self._io.pos()
            _on = self.fmt
            if _on == self._root.RtpfbSubtype.transport_feedback:
                self._raw_fci_block = self._io.read_bytes_full()
                io = KaitaiStream(BytesIO(self._raw_fci_block))
                self.fci_block = self._root.RtpfbTransportFeedbackPacket(io, self, self._root)
                self.fci_block._read()
            else:
                self.fci_block = self._io.read_bytes_full()
            self._debug['fci_block']['end'] = self._io.pos()

        @property
        def fmt(self):
            if hasattr(self, '_m_fmt'):
                return self._m_fmt if hasattr(self, '_m_fmt') else None

            self._m_fmt = KaitaiStream.resolve_enum(self._root.RtpfbSubtype, self._parent.subtype)
            return self._m_fmt if hasattr(self, '_m_fmt') else None


    class PacketStatusChunk(KaitaiStruct):
        SEQ_FIELDS = ["t", "s2", "s1", "rle", "symbol_list"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['t']['start'] = self._io.pos()
            self.t = self._io.read_bits_int(1) != 0
            self._debug['t']['end'] = self._io.pos()
            if int(self.t) == 0:
                self._debug['s2']['start'] = self._io.pos()
                self.s2 = self._io.read_bits_int(2)
                self._debug['s2']['end'] = self._io.pos()

            if int(self.t) == 1:
                self._debug['s1']['start'] = self._io.pos()
                self.s1 = self._io.read_bits_int(1) != 0
                self._debug['s1']['end'] = self._io.pos()

            if int(self.t) == 0:
                self._debug['rle']['start'] = self._io.pos()
                self.rle = self._io.read_bits_int(13)
                self._debug['rle']['end'] = self._io.pos()

            if int(self.t) == 1:
                self._debug['symbol_list']['start'] = self._io.pos()
                self.symbol_list = self._io.read_bits_int(14)
                self._debug['symbol_list']['end'] = self._io.pos()


        @property
        def s(self):
            if hasattr(self, '_m_s'):
                return self._m_s if hasattr(self, '_m_s') else None

            self._m_s = (self.s2 if int(self.t) == 0 else (1 if int(self.s1) == 0 else 0))
            return self._m_s if hasattr(self, '_m_s') else None


    class PsfbAfbPacket(KaitaiStruct):
        SEQ_FIELDS = ["uid", "contents"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['uid']['start'] = self._io.pos()
            self.uid = self._io.read_u4be()
            self._debug['uid']['end'] = self._io.pos()
            self._debug['contents']['start'] = self._io.pos()
            _on = self.uid
            if _on == 1380273474:
                self._raw_contents = self._io.read_bytes_full()
                io = KaitaiStream(BytesIO(self._raw_contents))
                self.contents = self._root.PsfbAfbRembPacket(io, self, self._root)
                self.contents._read()
            else:
                self.contents = self._io.read_bytes_full()
            self._debug['contents']['end'] = self._io.pos()



