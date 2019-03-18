from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class GenmidiOp2(KaitaiStruct):
    """GENMIDI.OP2 is a sound bank file used by players based on DMX sound
    library to play MIDI files with General MIDI instruments using OPL2
    sound chip (which was commonly installed on popular AdLib and Sound
    Blaster sound cards).
    
    Major users of DMX sound library include:
    
    * Original Doom game engine (and games based on it: Heretic, Hexen, Strife, Chex Quest)
    * Raptor: Call of the Shadows 
    
    .. seealso::
       http://doom.wikia.com/wiki/GENMIDI - http://www.fit.vutbr.cz/~arnost/muslib/op2_form.zip
    """
    SEQ_FIELDS = ["magic", "instruments", "instrument_names"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\x23\x4F\x50\x4C\x5F\x49\x49\x23")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['instruments']['start'] = self._io.pos()
        self.instruments = [None] * (175)
        for i in range(175):
            if not 'arr' in self._debug['instruments']:
                self._debug['instruments']['arr'] = []
            self._debug['instruments']['arr'].append({'start': self._io.pos()})
            _t_instruments = self._root.InstrumentEntry(self._io, self, self._root)
            _t_instruments._read()
            self.instruments[i] = _t_instruments
            self._debug['instruments']['arr'][i]['end'] = self._io.pos()

        self._debug['instruments']['end'] = self._io.pos()
        self._debug['instrument_names']['start'] = self._io.pos()
        self.instrument_names = [None] * (175)
        for i in range(175):
            if not 'arr' in self._debug['instrument_names']:
                self._debug['instrument_names']['arr'] = []
            self._debug['instrument_names']['arr'].append({'start': self._io.pos()})
            self.instrument_names[i] = (KaitaiStream.bytes_terminate(KaitaiStream.bytes_strip_right(self._io.read_bytes(32), 0), 0, False)).decode(u"ASCII")
            self._debug['instrument_names']['arr'][i]['end'] = self._io.pos()

        self._debug['instrument_names']['end'] = self._io.pos()

    class InstrumentEntry(KaitaiStruct):
        SEQ_FIELDS = ["flags", "finetune", "note", "instruments"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u2le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['finetune']['start'] = self._io.pos()
            self.finetune = self._io.read_u1()
            self._debug['finetune']['end'] = self._io.pos()
            self._debug['note']['start'] = self._io.pos()
            self.note = self._io.read_u1()
            self._debug['note']['end'] = self._io.pos()
            self._debug['instruments']['start'] = self._io.pos()
            self.instruments = [None] * (2)
            for i in range(2):
                if not 'arr' in self._debug['instruments']:
                    self._debug['instruments']['arr'] = []
                self._debug['instruments']['arr'].append({'start': self._io.pos()})
                _t_instruments = self._root.Instrument(self._io, self, self._root)
                _t_instruments._read()
                self.instruments[i] = _t_instruments
                self._debug['instruments']['arr'][i]['end'] = self._io.pos()

            self._debug['instruments']['end'] = self._io.pos()


    class Instrument(KaitaiStruct):
        SEQ_FIELDS = ["op1", "feedback", "op2", "unused", "base_note"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['op1']['start'] = self._io.pos()
            self.op1 = self._root.OpSettings(self._io, self, self._root)
            self.op1._read()
            self._debug['op1']['end'] = self._io.pos()
            self._debug['feedback']['start'] = self._io.pos()
            self.feedback = self._io.read_u1()
            self._debug['feedback']['end'] = self._io.pos()
            self._debug['op2']['start'] = self._io.pos()
            self.op2 = self._root.OpSettings(self._io, self, self._root)
            self.op2._read()
            self._debug['op2']['end'] = self._io.pos()
            self._debug['unused']['start'] = self._io.pos()
            self.unused = self._io.read_u1()
            self._debug['unused']['end'] = self._io.pos()
            self._debug['base_note']['start'] = self._io.pos()
            self.base_note = self._io.read_s2le()
            self._debug['base_note']['end'] = self._io.pos()


    class OpSettings(KaitaiStruct):
        """OPL2 settings for one operator (carrier or modulator)
        """
        SEQ_FIELDS = ["trem_vibr", "att_dec", "sust_rel", "wave", "scale", "level"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['trem_vibr']['start'] = self._io.pos()
            self.trem_vibr = self._io.read_u1()
            self._debug['trem_vibr']['end'] = self._io.pos()
            self._debug['att_dec']['start'] = self._io.pos()
            self.att_dec = self._io.read_u1()
            self._debug['att_dec']['end'] = self._io.pos()
            self._debug['sust_rel']['start'] = self._io.pos()
            self.sust_rel = self._io.read_u1()
            self._debug['sust_rel']['end'] = self._io.pos()
            self._debug['wave']['start'] = self._io.pos()
            self.wave = self._io.read_u1()
            self._debug['wave']['end'] = self._io.pos()
            self._debug['scale']['start'] = self._io.pos()
            self.scale = self._io.read_u1()
            self._debug['scale']['end'] = self._io.pos()
            self._debug['level']['start'] = self._io.pos()
            self.level = self._io.read_u1()
            self._debug['level']['end'] = self._io.pos()



