# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Hccapx(KaitaiStruct):
    """Native format of Hashcat password "recovery" utility
    
    .. seealso::
       Source - https://hashcat.net/wiki/doku.php?id=hccapx
    """
    SEQ_FIELDS = ["records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['records']['start'] = self._io.pos()
        self.records = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            _t_records = self._root.HccapxRecord(self._io, self, self._root)
            _t_records._read()
            self.records.append(_t_records)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['records']['end'] = self._io.pos()

    class HccapxRecord(KaitaiStruct):
        SEQ_FIELDS = ["magic", "version", "ignore_replay_counter", "message_pair", "len_essid", "essid", "padding1", "keyver", "keymic", "mac_ap", "nonce_ap", "mac_station", "nonce_station", "len_eapol", "eapol", "padding2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x48\x43\x50\x58")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u4le()
            self._debug['version']['end'] = self._io.pos()
            self._debug['ignore_replay_counter']['start'] = self._io.pos()
            self.ignore_replay_counter = self._io.read_bits_int(1) != 0
            self._debug['ignore_replay_counter']['end'] = self._io.pos()
            self._debug['message_pair']['start'] = self._io.pos()
            self.message_pair = self._io.read_bits_int(7)
            self._debug['message_pair']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['len_essid']['start'] = self._io.pos()
            self.len_essid = self._io.read_u1()
            self._debug['len_essid']['end'] = self._io.pos()
            self._debug['essid']['start'] = self._io.pos()
            self.essid = self._io.read_bytes(self.len_essid)
            self._debug['essid']['end'] = self._io.pos()
            self._debug['padding1']['start'] = self._io.pos()
            self.padding1 = self._io.read_bytes((32 - self.len_essid))
            self._debug['padding1']['end'] = self._io.pos()
            self._debug['keyver']['start'] = self._io.pos()
            self.keyver = self._io.read_u1()
            self._debug['keyver']['end'] = self._io.pos()
            self._debug['keymic']['start'] = self._io.pos()
            self.keymic = self._io.read_bytes(16)
            self._debug['keymic']['end'] = self._io.pos()
            self._debug['mac_ap']['start'] = self._io.pos()
            self.mac_ap = self._io.read_bytes(6)
            self._debug['mac_ap']['end'] = self._io.pos()
            self._debug['nonce_ap']['start'] = self._io.pos()
            self.nonce_ap = self._io.read_bytes(32)
            self._debug['nonce_ap']['end'] = self._io.pos()
            self._debug['mac_station']['start'] = self._io.pos()
            self.mac_station = self._io.read_bytes(6)
            self._debug['mac_station']['end'] = self._io.pos()
            self._debug['nonce_station']['start'] = self._io.pos()
            self.nonce_station = self._io.read_bytes(32)
            self._debug['nonce_station']['end'] = self._io.pos()
            self._debug['len_eapol']['start'] = self._io.pos()
            self.len_eapol = self._io.read_u2le()
            self._debug['len_eapol']['end'] = self._io.pos()
            self._debug['eapol']['start'] = self._io.pos()
            self.eapol = self._io.read_bytes(self.len_eapol)
            self._debug['eapol']['end'] = self._io.pos()
            self._debug['padding2']['start'] = self._io.pos()
            self.padding2 = self._io.read_bytes((256 - self.len_eapol))
            self._debug['padding2']['end'] = self._io.pos()



