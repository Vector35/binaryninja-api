from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from windows_systemtime import WindowsSystemtime
from ethernet_frame import EthernetFrame
class MicrosoftNetworkMonitorV2(KaitaiStruct):
    """Microsoft Network Monitor (AKA Netmon) is a proprietary Microsoft's
    network packet sniffing and analysis tool. It can save captured
    traffic as .cap files, which usually contain the packets and may
    contain some additional info - enhanced network info, calculated
    statistics, etc.
    
    There are at least 2 different versions of the format: v1 and
    v2. Netmon v3 seems to use the same file format as v1.
    
    .. seealso::
       Source - https://msdn.microsoft.com/en-us/library/windows/desktop/ee817717.aspx
    """

    class Linktype(Enum):
        null_linktype = 0
        ethernet = 1
        ax25 = 3
        ieee802_5 = 6
        arcnet_bsd = 7
        slip = 8
        ppp = 9
        fddi = 10
        ppp_hdlc = 50
        ppp_ether = 51
        atm_rfc1483 = 100
        raw = 101
        c_hdlc = 104
        ieee802_11 = 105
        frelay = 107
        loop = 108
        linux_sll = 113
        ltalk = 114
        pflog = 117
        ieee802_11_prism = 119
        ip_over_fc = 122
        sunatm = 123
        ieee802_11_radiotap = 127
        arcnet_linux = 129
        apple_ip_over_ieee1394 = 138
        mtp2_with_phdr = 139
        mtp2 = 140
        mtp3 = 141
        sccp = 142
        docsis = 143
        linux_irda = 144
        user0 = 147
        user1 = 148
        user2 = 149
        user3 = 150
        user4 = 151
        user5 = 152
        user6 = 153
        user7 = 154
        user8 = 155
        user9 = 156
        user10 = 157
        user11 = 158
        user12 = 159
        user13 = 160
        user14 = 161
        user15 = 162
        ieee802_11_avs = 163
        bacnet_ms_tp = 165
        ppp_pppd = 166
        gprs_llc = 169
        gpf_t = 170
        gpf_f = 171
        linux_lapd = 177
        bluetooth_hci_h4 = 187
        usb_linux = 189
        ppi = 192
        ieee802_15_4 = 195
        sita = 196
        erf = 197
        bluetooth_hci_h4_with_phdr = 201
        ax25_kiss = 202
        lapd = 203
        ppp_with_dir = 204
        c_hdlc_with_dir = 205
        frelay_with_dir = 206
        ipmb_linux = 209
        ieee802_15_4_nonask_phy = 215
        usb_linux_mmapped = 220
        fc_2 = 224
        fc_2_with_frame_delims = 225
        ipnet = 226
        can_socketcan = 227
        ipv4 = 228
        ipv6 = 229
        ieee802_15_4_nofcs = 230
        dbus = 231
        dvb_ci = 235
        mux27010 = 236
        stanag_5066_d_pdu = 237
        nflog = 239
        netanalyzer = 240
        netanalyzer_transparent = 241
        ipoib = 242
        mpeg_2_ts = 243
        ng40 = 244
        nfc_llcp = 245
        infiniband = 247
        sctp = 248
        usbpcap = 249
        rtac_serial = 250
        bluetooth_le_ll = 251
        netlink = 253
        bluetooth_linux_monitor = 254
        bluetooth_bredr_bb = 255
        bluetooth_le_ll_with_phdr = 256
        profibus_dl = 257
        pktap = 258
        epon = 259
        ipmi_hpm_2 = 260
        zwave_r1_r2 = 261
        zwave_r3 = 262
        wattstopper_dlm = 263
        iso_14443 = 264
    SEQ_FIELDS = ["signature", "version_minor", "version_major", "mac_type", "time_capture_start", "frame_table_ofs", "frame_table_len", "user_data_ofs", "user_data_len", "comment_ofs", "comment_len", "statistics_ofs", "statistics_len", "network_info_ofs", "network_info_len", "conversation_stats_ofs", "conversation_stats_len"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['signature']['start'] = self._io.pos()
        self.signature = self._io.ensure_fixed_contents(b"\x47\x4D\x42\x55")
        self._debug['signature']['end'] = self._io.pos()
        self._debug['version_minor']['start'] = self._io.pos()
        self.version_minor = self._io.read_u1()
        self._debug['version_minor']['end'] = self._io.pos()
        self._debug['version_major']['start'] = self._io.pos()
        self.version_major = self._io.read_u1()
        self._debug['version_major']['end'] = self._io.pos()
        self._debug['mac_type']['start'] = self._io.pos()
        self.mac_type = KaitaiStream.resolve_enum(self._root.Linktype, self._io.read_u2le())
        self._debug['mac_type']['end'] = self._io.pos()
        self._debug['time_capture_start']['start'] = self._io.pos()
        self.time_capture_start = WindowsSystemtime(self._io)
        self.time_capture_start._read()
        self._debug['time_capture_start']['end'] = self._io.pos()
        self._debug['frame_table_ofs']['start'] = self._io.pos()
        self.frame_table_ofs = self._io.read_u4le()
        self._debug['frame_table_ofs']['end'] = self._io.pos()
        self._debug['frame_table_len']['start'] = self._io.pos()
        self.frame_table_len = self._io.read_u4le()
        self._debug['frame_table_len']['end'] = self._io.pos()
        self._debug['user_data_ofs']['start'] = self._io.pos()
        self.user_data_ofs = self._io.read_u4le()
        self._debug['user_data_ofs']['end'] = self._io.pos()
        self._debug['user_data_len']['start'] = self._io.pos()
        self.user_data_len = self._io.read_u4le()
        self._debug['user_data_len']['end'] = self._io.pos()
        self._debug['comment_ofs']['start'] = self._io.pos()
        self.comment_ofs = self._io.read_u4le()
        self._debug['comment_ofs']['end'] = self._io.pos()
        self._debug['comment_len']['start'] = self._io.pos()
        self.comment_len = self._io.read_u4le()
        self._debug['comment_len']['end'] = self._io.pos()
        self._debug['statistics_ofs']['start'] = self._io.pos()
        self.statistics_ofs = self._io.read_u4le()
        self._debug['statistics_ofs']['end'] = self._io.pos()
        self._debug['statistics_len']['start'] = self._io.pos()
        self.statistics_len = self._io.read_u4le()
        self._debug['statistics_len']['end'] = self._io.pos()
        self._debug['network_info_ofs']['start'] = self._io.pos()
        self.network_info_ofs = self._io.read_u4le()
        self._debug['network_info_ofs']['end'] = self._io.pos()
        self._debug['network_info_len']['start'] = self._io.pos()
        self.network_info_len = self._io.read_u4le()
        self._debug['network_info_len']['end'] = self._io.pos()
        self._debug['conversation_stats_ofs']['start'] = self._io.pos()
        self.conversation_stats_ofs = self._io.read_u4le()
        self._debug['conversation_stats_ofs']['end'] = self._io.pos()
        self._debug['conversation_stats_len']['start'] = self._io.pos()
        self.conversation_stats_len = self._io.read_u4le()
        self._debug['conversation_stats_len']['end'] = self._io.pos()

    class FrameIndex(KaitaiStruct):
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
                _t_entries = self._root.FrameIndexEntry(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class FrameIndexEntry(KaitaiStruct):
        """Each index entry is just a pointer to where the frame data is
        stored in the file.
        """
        SEQ_FIELDS = ["ofs"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ofs']['start'] = self._io.pos()
            self.ofs = self._io.read_u4le()
            self._debug['ofs']['end'] = self._io.pos()

        @property
        def body(self):
            """Frame body itself."""
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs)
            self._debug['_m_body']['start'] = io.pos()
            self._m_body = self._root.Frame(io, self, self._root)
            self._m_body._read()
            self._debug['_m_body']['end'] = io.pos()
            io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class Frame(KaitaiStruct):
        """A container for actually captured network data. Allow to
        timestamp individual frames and designates how much data from
        the original packet was actually written into the file.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/windows/desktop/ee831821.aspx
        """
        SEQ_FIELDS = ["ts_delta", "orig_len", "inc_len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ts_delta']['start'] = self._io.pos()
            self.ts_delta = self._io.read_u8le()
            self._debug['ts_delta']['end'] = self._io.pos()
            self._debug['orig_len']['start'] = self._io.pos()
            self.orig_len = self._io.read_u4le()
            self._debug['orig_len']['end'] = self._io.pos()
            self._debug['inc_len']['start'] = self._io.pos()
            self.inc_len = self._io.read_u4le()
            self._debug['inc_len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self._root.mac_type
            if _on == self._root.Linktype.ethernet:
                self._raw_body = self._io.read_bytes(self.inc_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = EthernetFrame(io)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.inc_len)
            self._debug['body']['end'] = self._io.pos()


    @property
    def frame_table(self):
        """Index that is used to access individual captured frames."""
        if hasattr(self, '_m_frame_table'):
            return self._m_frame_table if hasattr(self, '_m_frame_table') else None

        _pos = self._io.pos()
        self._io.seek(self.frame_table_ofs)
        self._debug['_m_frame_table']['start'] = self._io.pos()
        self._raw__m_frame_table = self._io.read_bytes(self.frame_table_len)
        io = KaitaiStream(BytesIO(self._raw__m_frame_table))
        self._m_frame_table = self._root.FrameIndex(io, self, self._root)
        self._m_frame_table._read()
        self._debug['_m_frame_table']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_frame_table if hasattr(self, '_m_frame_table') else None


