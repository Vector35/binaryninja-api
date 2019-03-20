# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from . import ethernet_frame
class PacketPpi(KaitaiStruct):
    """PPI is a standard for link layer packet encapsulation, proposed as
    generic extensible container to store both captured in-band data and
    out-of-band data. Originally it was developed to provide 802.11n
    radio information, but can be used for other purposes as well.
    
    Sample capture: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=Http.cap  
    
    .. seealso::
       PPI header format spec, section 3 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
    """

    class PfhType(Enum):
        radio_802_11_common = 2
        radio_802_11n_mac_ext = 3
        radio_802_11n_mac_phy_ext = 4
        spectrum_map = 5
        process_info = 6
        capture_info = 7

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
    SEQ_FIELDS = ["header", "fields", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.PacketPpiHeader(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['fields']['start'] = self._io.pos()
        self._raw_fields = self._io.read_bytes((self.header.pph_len - 8))
        io = KaitaiStream(BytesIO(self._raw_fields))
        self.fields = self._root.PacketPpiFields(io, self, self._root)
        self.fields._read()
        self._debug['fields']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        _on = self.header.pph_dlt
        if _on == self._root.Linktype.ppi:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = PacketPpi(io)
            self.body._read()
        elif _on == self._root.Linktype.ethernet:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = ethernet_frame.EthernetFrame(io)
            self.body._read()
        else:
            self.body = self._io.read_bytes_full()
        self._debug['body']['end'] = self._io.pos()

    class PacketPpiFields(KaitaiStruct):
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
                _t_entries = self._root.PacketPpiField(self._io, self, self._root)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class Radio80211nMacExtBody(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 4.1.3 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """
        SEQ_FIELDS = ["flags", "a_mpdu_id", "num_delimiters", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['a_mpdu_id']['start'] = self._io.pos()
            self.a_mpdu_id = self._io.read_u4le()
            self._debug['a_mpdu_id']['end'] = self._io.pos()
            self._debug['num_delimiters']['start'] = self._io.pos()
            self.num_delimiters = self._io.read_u1()
            self._debug['num_delimiters']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(3)
            self._debug['reserved']['end'] = self._io.pos()


    class MacFlags(KaitaiStruct):
        SEQ_FIELDS = ["unused1", "aggregate_delimiter", "more_aggregates", "aggregate", "dup_rx", "rx_short_guard", "is_ht_40", "greenfield", "unused2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['unused1']['start'] = self._io.pos()
            self.unused1 = self._io.read_bits_int(1) != 0
            self._debug['unused1']['end'] = self._io.pos()
            self._debug['aggregate_delimiter']['start'] = self._io.pos()
            self.aggregate_delimiter = self._io.read_bits_int(1) != 0
            self._debug['aggregate_delimiter']['end'] = self._io.pos()
            self._debug['more_aggregates']['start'] = self._io.pos()
            self.more_aggregates = self._io.read_bits_int(1) != 0
            self._debug['more_aggregates']['end'] = self._io.pos()
            self._debug['aggregate']['start'] = self._io.pos()
            self.aggregate = self._io.read_bits_int(1) != 0
            self._debug['aggregate']['end'] = self._io.pos()
            self._debug['dup_rx']['start'] = self._io.pos()
            self.dup_rx = self._io.read_bits_int(1) != 0
            self._debug['dup_rx']['end'] = self._io.pos()
            self._debug['rx_short_guard']['start'] = self._io.pos()
            self.rx_short_guard = self._io.read_bits_int(1) != 0
            self._debug['rx_short_guard']['end'] = self._io.pos()
            self._debug['is_ht_40']['start'] = self._io.pos()
            self.is_ht_40 = self._io.read_bits_int(1) != 0
            self._debug['is_ht_40']['end'] = self._io.pos()
            self._debug['greenfield']['start'] = self._io.pos()
            self.greenfield = self._io.read_bits_int(1) != 0
            self._debug['greenfield']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['unused2']['start'] = self._io.pos()
            self.unused2 = self._io.read_bytes(3)
            self._debug['unused2']['end'] = self._io.pos()


    class PacketPpiHeader(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 3.1 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """
        SEQ_FIELDS = ["pph_version", "pph_flags", "pph_len", "pph_dlt"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['pph_version']['start'] = self._io.pos()
            self.pph_version = self._io.read_u1()
            self._debug['pph_version']['end'] = self._io.pos()
            self._debug['pph_flags']['start'] = self._io.pos()
            self.pph_flags = self._io.read_u1()
            self._debug['pph_flags']['end'] = self._io.pos()
            self._debug['pph_len']['start'] = self._io.pos()
            self.pph_len = self._io.read_u2le()
            self._debug['pph_len']['end'] = self._io.pos()
            self._debug['pph_dlt']['start'] = self._io.pos()
            self.pph_dlt = KaitaiStream.resolve_enum(self._root.Linktype, self._io.read_u4le())
            self._debug['pph_dlt']['end'] = self._io.pos()


    class Radio80211CommonBody(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 4.1.2 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """
        SEQ_FIELDS = ["tsf_timer", "flags", "rate", "channel_freq", "channel_flags", "fhss_hopset", "fhss_pattern", "dbm_antsignal", "dbm_antnoise"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['tsf_timer']['start'] = self._io.pos()
            self.tsf_timer = self._io.read_u8le()
            self._debug['tsf_timer']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['rate']['start'] = self._io.pos()
            self.rate = self._io.read_u2le()
            self._debug['rate']['end'] = self._io.pos()
            self._debug['channel_freq']['start'] = self._io.pos()
            self.channel_freq = self._io.read_u2le()
            self._debug['channel_freq']['end'] = self._io.pos()
            self._debug['channel_flags']['start'] = self._io.pos()
            self.channel_flags = self._io.read_u2le()
            self._debug['channel_flags']['end'] = self._io.pos()
            self._debug['fhss_hopset']['start'] = self._io.pos()
            self.fhss_hopset = self._io.read_u1()
            self._debug['fhss_hopset']['end'] = self._io.pos()
            self._debug['fhss_pattern']['start'] = self._io.pos()
            self.fhss_pattern = self._io.read_u1()
            self._debug['fhss_pattern']['end'] = self._io.pos()
            self._debug['dbm_antsignal']['start'] = self._io.pos()
            self.dbm_antsignal = self._io.read_s1()
            self._debug['dbm_antsignal']['end'] = self._io.pos()
            self._debug['dbm_antnoise']['start'] = self._io.pos()
            self.dbm_antnoise = self._io.read_s1()
            self._debug['dbm_antnoise']['end'] = self._io.pos()


    class PacketPpiField(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 3.1 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """
        SEQ_FIELDS = ["pfh_type", "pfh_datalen", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['pfh_type']['start'] = self._io.pos()
            self.pfh_type = KaitaiStream.resolve_enum(self._root.PfhType, self._io.read_u2le())
            self._debug['pfh_type']['end'] = self._io.pos()
            self._debug['pfh_datalen']['start'] = self._io.pos()
            self.pfh_datalen = self._io.read_u2le()
            self._debug['pfh_datalen']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.pfh_type
            if _on == self._root.PfhType.radio_802_11_common:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211CommonBody(io, self, self._root)
                self.body._read()
            elif _on == self._root.PfhType.radio_802_11n_mac_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacExtBody(io, self, self._root)
                self.body._read()
            elif _on == self._root.PfhType.radio_802_11n_mac_phy_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacPhyExtBody(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.pfh_datalen)
            self._debug['body']['end'] = self._io.pos()


    class Radio80211nMacPhyExtBody(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 4.1.4 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """
        SEQ_FIELDS = ["flags", "a_mpdu_id", "num_delimiters", "mcs", "num_streams", "rssi_combined", "rssi_ant_ctl", "rssi_ant_ext", "ext_channel_freq", "ext_channel_flags", "rf_signal_noise", "evm"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['a_mpdu_id']['start'] = self._io.pos()
            self.a_mpdu_id = self._io.read_u4le()
            self._debug['a_mpdu_id']['end'] = self._io.pos()
            self._debug['num_delimiters']['start'] = self._io.pos()
            self.num_delimiters = self._io.read_u1()
            self._debug['num_delimiters']['end'] = self._io.pos()
            self._debug['mcs']['start'] = self._io.pos()
            self.mcs = self._io.read_u1()
            self._debug['mcs']['end'] = self._io.pos()
            self._debug['num_streams']['start'] = self._io.pos()
            self.num_streams = self._io.read_u1()
            self._debug['num_streams']['end'] = self._io.pos()
            self._debug['rssi_combined']['start'] = self._io.pos()
            self.rssi_combined = self._io.read_u1()
            self._debug['rssi_combined']['end'] = self._io.pos()
            self._debug['rssi_ant_ctl']['start'] = self._io.pos()
            self.rssi_ant_ctl = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['rssi_ant_ctl']:
                    self._debug['rssi_ant_ctl']['arr'] = []
                self._debug['rssi_ant_ctl']['arr'].append({'start': self._io.pos()})
                self.rssi_ant_ctl[i] = self._io.read_u1()
                self._debug['rssi_ant_ctl']['arr'][i]['end'] = self._io.pos()

            self._debug['rssi_ant_ctl']['end'] = self._io.pos()
            self._debug['rssi_ant_ext']['start'] = self._io.pos()
            self.rssi_ant_ext = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['rssi_ant_ext']:
                    self._debug['rssi_ant_ext']['arr'] = []
                self._debug['rssi_ant_ext']['arr'].append({'start': self._io.pos()})
                self.rssi_ant_ext[i] = self._io.read_u1()
                self._debug['rssi_ant_ext']['arr'][i]['end'] = self._io.pos()

            self._debug['rssi_ant_ext']['end'] = self._io.pos()
            self._debug['ext_channel_freq']['start'] = self._io.pos()
            self.ext_channel_freq = self._io.read_u2le()
            self._debug['ext_channel_freq']['end'] = self._io.pos()
            self._debug['ext_channel_flags']['start'] = self._io.pos()
            self.ext_channel_flags = self._root.Radio80211nMacPhyExtBody.ChannelFlags(self._io, self, self._root)
            self.ext_channel_flags._read()
            self._debug['ext_channel_flags']['end'] = self._io.pos()
            self._debug['rf_signal_noise']['start'] = self._io.pos()
            self.rf_signal_noise = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['rf_signal_noise']:
                    self._debug['rf_signal_noise']['arr'] = []
                self._debug['rf_signal_noise']['arr'].append({'start': self._io.pos()})
                _t_rf_signal_noise = self._root.Radio80211nMacPhyExtBody.SignalNoise(self._io, self, self._root)
                _t_rf_signal_noise._read()
                self.rf_signal_noise[i] = _t_rf_signal_noise
                self._debug['rf_signal_noise']['arr'][i]['end'] = self._io.pos()

            self._debug['rf_signal_noise']['end'] = self._io.pos()
            self._debug['evm']['start'] = self._io.pos()
            self.evm = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['evm']:
                    self._debug['evm']['arr'] = []
                self._debug['evm']['arr'].append({'start': self._io.pos()})
                self.evm[i] = self._io.read_u4le()
                self._debug['evm']['arr'][i]['end'] = self._io.pos()

            self._debug['evm']['end'] = self._io.pos()

        class ChannelFlags(KaitaiStruct):
            SEQ_FIELDS = ["spectrum_2ghz", "ofdm", "cck", "turbo", "unused", "gfsk", "dyn_cck_ofdm", "only_passive_scan", "spectrum_5ghz"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['spectrum_2ghz']['start'] = self._io.pos()
                self.spectrum_2ghz = self._io.read_bits_int(1) != 0
                self._debug['spectrum_2ghz']['end'] = self._io.pos()
                self._debug['ofdm']['start'] = self._io.pos()
                self.ofdm = self._io.read_bits_int(1) != 0
                self._debug['ofdm']['end'] = self._io.pos()
                self._debug['cck']['start'] = self._io.pos()
                self.cck = self._io.read_bits_int(1) != 0
                self._debug['cck']['end'] = self._io.pos()
                self._debug['turbo']['start'] = self._io.pos()
                self.turbo = self._io.read_bits_int(1) != 0
                self._debug['turbo']['end'] = self._io.pos()
                self._debug['unused']['start'] = self._io.pos()
                self.unused = self._io.read_bits_int(8)
                self._debug['unused']['end'] = self._io.pos()
                self._debug['gfsk']['start'] = self._io.pos()
                self.gfsk = self._io.read_bits_int(1) != 0
                self._debug['gfsk']['end'] = self._io.pos()
                self._debug['dyn_cck_ofdm']['start'] = self._io.pos()
                self.dyn_cck_ofdm = self._io.read_bits_int(1) != 0
                self._debug['dyn_cck_ofdm']['end'] = self._io.pos()
                self._debug['only_passive_scan']['start'] = self._io.pos()
                self.only_passive_scan = self._io.read_bits_int(1) != 0
                self._debug['only_passive_scan']['end'] = self._io.pos()
                self._debug['spectrum_5ghz']['start'] = self._io.pos()
                self.spectrum_5ghz = self._io.read_bits_int(1) != 0
                self._debug['spectrum_5ghz']['end'] = self._io.pos()


        class SignalNoise(KaitaiStruct):
            """RF signal + noise pair at a single antenna."""
            SEQ_FIELDS = ["signal", "noise"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['signal']['start'] = self._io.pos()
                self.signal = self._io.read_s1()
                self._debug['signal']['end'] = self._io.pos()
                self._debug['noise']['start'] = self._io.pos()
                self.noise = self._io.read_s1()
                self._debug['noise']['end'] = self._io.pos()




