from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class BitcoinTransaction(KaitaiStruct):
    """
    .. seealso::
       Source - https://bitcoin.org/en/developer-guide#transactions
       https://en.bitcoin.it/wiki/Transaction
    """

    class SighashType(Enum):
        sighash_all = 1
        sighash_none = 2
        sighash_single = 3
        sighash_anyonecanpay = 80
    SEQ_FIELDS = ["version", "num_vins", "vins", "num_vouts", "vouts", "locktime"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u4le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['num_vins']['start'] = self._io.pos()
        self.num_vins = self._io.read_u1()
        self._debug['num_vins']['end'] = self._io.pos()
        self._debug['vins']['start'] = self._io.pos()
        self.vins = [None] * (self.num_vins)
        for i in range(self.num_vins):
            if not 'arr' in self._debug['vins']:
                self._debug['vins']['arr'] = []
            self._debug['vins']['arr'].append({'start': self._io.pos()})
            _t_vins = self._root.Vin(self._io, self, self._root)
            _t_vins._read()
            self.vins[i] = _t_vins
            self._debug['vins']['arr'][i]['end'] = self._io.pos()

        self._debug['vins']['end'] = self._io.pos()
        self._debug['num_vouts']['start'] = self._io.pos()
        self.num_vouts = self._io.read_u1()
        self._debug['num_vouts']['end'] = self._io.pos()
        self._debug['vouts']['start'] = self._io.pos()
        self.vouts = [None] * (self.num_vouts)
        for i in range(self.num_vouts):
            if not 'arr' in self._debug['vouts']:
                self._debug['vouts']['arr'] = []
            self._debug['vouts']['arr'].append({'start': self._io.pos()})
            _t_vouts = self._root.Vout(self._io, self, self._root)
            _t_vouts._read()
            self.vouts[i] = _t_vouts
            self._debug['vouts']['arr'][i]['end'] = self._io.pos()

        self._debug['vouts']['end'] = self._io.pos()
        self._debug['locktime']['start'] = self._io.pos()
        self.locktime = self._io.read_u4le()
        self._debug['locktime']['end'] = self._io.pos()

    class Vout(KaitaiStruct):
        SEQ_FIELDS = ["amount", "script_len", "script_pub_key"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['amount']['start'] = self._io.pos()
            self.amount = self._io.read_u8le()
            self._debug['amount']['end'] = self._io.pos()
            self._debug['script_len']['start'] = self._io.pos()
            self.script_len = self._io.read_u1()
            self._debug['script_len']['end'] = self._io.pos()
            self._debug['script_pub_key']['start'] = self._io.pos()
            self.script_pub_key = self._io.read_bytes(self.script_len)
            self._debug['script_pub_key']['end'] = self._io.pos()


    class PublicKey(KaitaiStruct):
        SEQ_FIELDS = ["type", "x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u1()
            self._debug['type']['end'] = self._io.pos()
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_bytes(32)
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_bytes(32)
            self._debug['y']['end'] = self._io.pos()


    class Vin(KaitaiStruct):
        SEQ_FIELDS = ["txid", "output_id", "script_len", "script_sig", "end_of_vin"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['txid']['start'] = self._io.pos()
            self.txid = self._io.read_bytes(32)
            self._debug['txid']['end'] = self._io.pos()
            self._debug['output_id']['start'] = self._io.pos()
            self.output_id = self._io.read_u4le()
            self._debug['output_id']['end'] = self._io.pos()
            self._debug['script_len']['start'] = self._io.pos()
            self.script_len = self._io.read_u1()
            self._debug['script_len']['end'] = self._io.pos()
            self._debug['script_sig']['start'] = self._io.pos()
            self._raw_script_sig = self._io.read_bytes(self.script_len)
            io = KaitaiStream(BytesIO(self._raw_script_sig))
            self.script_sig = self._root.ScriptSignature(io, self, self._root)
            self.script_sig._read()
            self._debug['script_sig']['end'] = self._io.pos()
            self._debug['end_of_vin']['start'] = self._io.pos()
            self.end_of_vin = self._io.ensure_fixed_contents(b"\xFF\xFF\xFF\xFF")
            self._debug['end_of_vin']['end'] = self._io.pos()


    class ScriptSignature(KaitaiStruct):
        SEQ_FIELDS = ["sig_stack_len", "der_sig", "sig_type", "pubkey_stack_len", "pubkey"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sig_stack_len']['start'] = self._io.pos()
            self.sig_stack_len = self._io.read_u1()
            self._debug['sig_stack_len']['end'] = self._io.pos()
            self._debug['der_sig']['start'] = self._io.pos()
            self.der_sig = self._root.DerSignature(self._io, self, self._root)
            self.der_sig._read()
            self._debug['der_sig']['end'] = self._io.pos()
            self._debug['sig_type']['start'] = self._io.pos()
            self.sig_type = KaitaiStream.resolve_enum(self._root.SighashType, self._io.read_u1())
            self._debug['sig_type']['end'] = self._io.pos()
            self._debug['pubkey_stack_len']['start'] = self._io.pos()
            self.pubkey_stack_len = self._io.read_u1()
            self._debug['pubkey_stack_len']['end'] = self._io.pos()
            self._debug['pubkey']['start'] = self._io.pos()
            self.pubkey = self._root.PublicKey(self._io, self, self._root)
            self.pubkey._read()
            self._debug['pubkey']['end'] = self._io.pos()


    class DerSignature(KaitaiStruct):
        SEQ_FIELDS = ["sequence", "sig_len", "sep_1", "sig_r_len", "sig_r", "sep_2", "sig_s_len", "sig_s"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sequence']['start'] = self._io.pos()
            self.sequence = self._io.ensure_fixed_contents(b"\x30")
            self._debug['sequence']['end'] = self._io.pos()
            self._debug['sig_len']['start'] = self._io.pos()
            self.sig_len = self._io.read_u1()
            self._debug['sig_len']['end'] = self._io.pos()
            self._debug['sep_1']['start'] = self._io.pos()
            self.sep_1 = self._io.ensure_fixed_contents(b"\x02")
            self._debug['sep_1']['end'] = self._io.pos()
            self._debug['sig_r_len']['start'] = self._io.pos()
            self.sig_r_len = self._io.read_u1()
            self._debug['sig_r_len']['end'] = self._io.pos()
            self._debug['sig_r']['start'] = self._io.pos()
            self.sig_r = self._io.read_bytes(self.sig_r_len)
            self._debug['sig_r']['end'] = self._io.pos()
            self._debug['sep_2']['start'] = self._io.pos()
            self.sep_2 = self._io.ensure_fixed_contents(b"\x02")
            self._debug['sep_2']['end'] = self._io.pos()
            self._debug['sig_s_len']['start'] = self._io.pos()
            self.sig_s_len = self._io.read_u1()
            self._debug['sig_s_len']['end'] = self._io.pos()
            self._debug['sig_s']['start'] = self._io.pos()
            self.sig_s = self._io.read_bytes(self.sig_s_len)
            self._debug['sig_s']['end'] = self._io.pos()



