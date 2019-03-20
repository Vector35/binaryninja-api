# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from . import ethernet_frame
from . import packet_ppi
class Pcap(KaitaiStruct):
    """PCAP (named after libpcap / winpcap) is a popular format for saving
    network traffic grabbed by network sniffers. It is typically
    produced by tools like [tcpdump](https://www.tcpdump.org/) or
    [Wireshark](https://www.wireshark.org/).
    
    .. seealso::
       Source - http://wiki.wireshark.org/Development/LibpcapFileFormat
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
    SEQ_FIELDS = ["hdr", "packets"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['hdr']['start'] = self._io.pos()
        self.hdr = self._root.Header(self._io, self, self._root)
        self.hdr._read()
        self._debug['hdr']['end'] = self._io.pos()
        self._debug['packets']['start'] = self._io.pos()
        self.packets = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['packets']:
                self._debug['packets']['arr'] = []
            self._debug['packets']['arr'].append({'start': self._io.pos()})
            _t_packets = self._root.Packet(self._io, self, self._root)
            _t_packets._read()
            self.packets.append(_t_packets)
            self._debug['packets']['arr'][len(self.packets) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['packets']['end'] = self._io.pos()

    class Header(KaitaiStruct):
        """
        .. seealso::
           Source - https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
        """
        SEQ_FIELDS = ["magic_number", "version_major", "version_minor", "thiszone", "sigfigs", "snaplen", "network"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic_number']['start'] = self._io.pos()
            self.magic_number = self._io.ensure_fixed_contents(b"\xD4\xC3\xB2\xA1")
            self._debug['magic_number']['end'] = self._io.pos()
            self._debug['version_major']['start'] = self._io.pos()
            self.version_major = self._io.read_u2le()
            self._debug['version_major']['end'] = self._io.pos()
            self._debug['version_minor']['start'] = self._io.pos()
            self.version_minor = self._io.read_u2le()
            self._debug['version_minor']['end'] = self._io.pos()
            self._debug['thiszone']['start'] = self._io.pos()
            self.thiszone = self._io.read_s4le()
            self._debug['thiszone']['end'] = self._io.pos()
            self._debug['sigfigs']['start'] = self._io.pos()
            self.sigfigs = self._io.read_u4le()
            self._debug['sigfigs']['end'] = self._io.pos()
            self._debug['snaplen']['start'] = self._io.pos()
            self.snaplen = self._io.read_u4le()
            self._debug['snaplen']['end'] = self._io.pos()
            self._debug['network']['start'] = self._io.pos()
            self.network = KaitaiStream.resolve_enum(self._root.Linktype, self._io.read_u4le())
            self._debug['network']['end'] = self._io.pos()


    class Packet(KaitaiStruct):
        """
        .. seealso::
           Source - https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
        """
        SEQ_FIELDS = ["ts_sec", "ts_usec", "incl_len", "orig_len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ts_sec']['start'] = self._io.pos()
            self.ts_sec = self._io.read_u4le()
            self._debug['ts_sec']['end'] = self._io.pos()
            self._debug['ts_usec']['start'] = self._io.pos()
            self.ts_usec = self._io.read_u4le()
            self._debug['ts_usec']['end'] = self._io.pos()
            self._debug['incl_len']['start'] = self._io.pos()
            self.incl_len = self._io.read_u4le()
            self._debug['incl_len']['end'] = self._io.pos()
            self._debug['orig_len']['start'] = self._io.pos()
            self.orig_len = self._io.read_u4le()
            self._debug['orig_len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self._root.hdr.network
            if _on == self._root.Linktype.ppi:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = packet_ppi.PacketPpi(io)
                self.body._read()
            elif _on == self._root.Linktype.ethernet:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = ethernet_frame.EthernetFrame(io)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.incl_len)
            self._debug['body']['end'] = self._io.pos()



