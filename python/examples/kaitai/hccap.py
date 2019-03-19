# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Hccap(KaitaiStruct):
    """Native format of Hashcat password "recovery" utility.
    
    A sample of file for testing can be downloaded from https://web.archive.org/web/20150220013635if_/http://hashcat.net:80/misc/example_hashes/hashcat.hccap
    
    .. seealso::
       Source - https://hashcat.net/wiki/doku.php?id=hccap
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
            _t_records = self._root.HccapRecord(self._io, self, self._root)
            _t_records._read()
            self.records.append(_t_records)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['records']['end'] = self._io.pos()

    class HccapRecord(KaitaiStruct):
        SEQ_FIELDS = ["essid", "mac_ap", "mac_station", "nonce_station", "nonce_ap", "eapol_buffer", "len_eapol", "keyver", "keymic"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['essid']['start'] = self._io.pos()
            self.essid = self._io.read_bytes(36)
            self._debug['essid']['end'] = self._io.pos()
            self._debug['mac_ap']['start'] = self._io.pos()
            self.mac_ap = self._io.read_bytes(6)
            self._debug['mac_ap']['end'] = self._io.pos()
            self._debug['mac_station']['start'] = self._io.pos()
            self.mac_station = self._io.read_bytes(6)
            self._debug['mac_station']['end'] = self._io.pos()
            self._debug['nonce_station']['start'] = self._io.pos()
            self.nonce_station = self._io.read_bytes(32)
            self._debug['nonce_station']['end'] = self._io.pos()
            self._debug['nonce_ap']['start'] = self._io.pos()
            self.nonce_ap = self._io.read_bytes(32)
            self._debug['nonce_ap']['end'] = self._io.pos()
            self._debug['eapol_buffer']['start'] = self._io.pos()
            self._raw_eapol_buffer = self._io.read_bytes(256)
            io = KaitaiStream(BytesIO(self._raw_eapol_buffer))
            self.eapol_buffer = self._root.EapolDummy(io, self, self._root)
            self.eapol_buffer._read()
            self._debug['eapol_buffer']['end'] = self._io.pos()
            self._debug['len_eapol']['start'] = self._io.pos()
            self.len_eapol = self._io.read_u4le()
            self._debug['len_eapol']['end'] = self._io.pos()
            self._debug['keyver']['start'] = self._io.pos()
            self.keyver = self._io.read_u4le()
            self._debug['keyver']['end'] = self._io.pos()
            self._debug['keymic']['start'] = self._io.pos()
            self.keymic = self._io.read_bytes(16)
            self._debug['keymic']['end'] = self._io.pos()

        @property
        def eapol(self):
            if hasattr(self, '_m_eapol'):
                return self._m_eapol if hasattr(self, '_m_eapol') else None

            io = self.eapol_buffer._io
            _pos = io.pos()
            io.seek(0)
            self._debug['_m_eapol']['start'] = io.pos()
            self._m_eapol = io.read_bytes(self.len_eapol)
            self._debug['_m_eapol']['end'] = io.pos()
            io.seek(_pos)
            return self._m_eapol if hasattr(self, '_m_eapol') else None


    class EapolDummy(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass



