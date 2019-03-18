from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ....kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class S3m(KaitaiStruct):
    """Scream Tracker 3 module is a tracker music file format that, as all
    tracker music, bundles both sound samples and instructions on which
    notes to play. It originates from a Scream Tracker 3 music editor
    (1994) by Future Crew, derived from original Scream Tracker 2 (.stm)
    module format.
    
    Instrument descriptions in S3M format allow to use either digital
    samples or setup and control AdLib (OPL2) synth.
    
    Music is organized in so called `patterns`. "Pattern" is a generally
    a 64-row long table, which instructs which notes to play on which
    time measure. "Patterns" are played one-by-one in a sequence
    determined by `orders`, which is essentially an array of pattern IDs
    - this way it's possible to reuse certain patterns more than once
    for repetitive musical phrases.
    
    .. seealso::
       Source - http://hackipedia.org/File%20formats/Music/Sample%20based/text/Scream%20Tracker%203.20%20file%20format.cp437.txt.utf-8.txt
    """
    SEQ_FIELDS = ["song_name", "magic1", "file_type", "reserved1", "num_orders", "num_instruments", "num_patterns", "flags", "version", "samples_format", "magic2", "global_volume", "initial_speed", "initial_tempo", "is_stereo", "master_volume", "ultra_click_removal", "has_custom_pan", "reserved2", "ofs_special", "channels", "orders", "instruments", "patterns", "channel_pans"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['song_name']['start'] = self._io.pos()
        self.song_name = KaitaiStream.bytes_terminate(self._io.read_bytes(28), 0, False)
        self._debug['song_name']['end'] = self._io.pos()
        self._debug['magic1']['start'] = self._io.pos()
        self.magic1 = self._io.ensure_fixed_contents(b"\x1A")
        self._debug['magic1']['end'] = self._io.pos()
        self._debug['file_type']['start'] = self._io.pos()
        self.file_type = self._io.read_u1()
        self._debug['file_type']['end'] = self._io.pos()
        self._debug['reserved1']['start'] = self._io.pos()
        self.reserved1 = self._io.read_bytes(2)
        self._debug['reserved1']['end'] = self._io.pos()
        self._debug['num_orders']['start'] = self._io.pos()
        self.num_orders = self._io.read_u2le()
        self._debug['num_orders']['end'] = self._io.pos()
        self._debug['num_instruments']['start'] = self._io.pos()
        self.num_instruments = self._io.read_u2le()
        self._debug['num_instruments']['end'] = self._io.pos()
        self._debug['num_patterns']['start'] = self._io.pos()
        self.num_patterns = self._io.read_u2le()
        self._debug['num_patterns']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._io.read_u2le()
        self._debug['flags']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u2le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['samples_format']['start'] = self._io.pos()
        self.samples_format = self._io.read_u2le()
        self._debug['samples_format']['end'] = self._io.pos()
        self._debug['magic2']['start'] = self._io.pos()
        self.magic2 = self._io.ensure_fixed_contents(b"\x53\x43\x52\x4D")
        self._debug['magic2']['end'] = self._io.pos()
        self._debug['global_volume']['start'] = self._io.pos()
        self.global_volume = self._io.read_u1()
        self._debug['global_volume']['end'] = self._io.pos()
        self._debug['initial_speed']['start'] = self._io.pos()
        self.initial_speed = self._io.read_u1()
        self._debug['initial_speed']['end'] = self._io.pos()
        self._debug['initial_tempo']['start'] = self._io.pos()
        self.initial_tempo = self._io.read_u1()
        self._debug['initial_tempo']['end'] = self._io.pos()
        self._debug['is_stereo']['start'] = self._io.pos()
        self.is_stereo = self._io.read_bits_int(1) != 0
        self._debug['is_stereo']['end'] = self._io.pos()
        self._debug['master_volume']['start'] = self._io.pos()
        self.master_volume = self._io.read_bits_int(7)
        self._debug['master_volume']['end'] = self._io.pos()
        self._io.align_to_byte()
        self._debug['ultra_click_removal']['start'] = self._io.pos()
        self.ultra_click_removal = self._io.read_u1()
        self._debug['ultra_click_removal']['end'] = self._io.pos()
        self._debug['has_custom_pan']['start'] = self._io.pos()
        self.has_custom_pan = self._io.read_u1()
        self._debug['has_custom_pan']['end'] = self._io.pos()
        self._debug['reserved2']['start'] = self._io.pos()
        self.reserved2 = self._io.read_bytes(8)
        self._debug['reserved2']['end'] = self._io.pos()
        self._debug['ofs_special']['start'] = self._io.pos()
        self.ofs_special = self._io.read_u2le()
        self._debug['ofs_special']['end'] = self._io.pos()
        self._debug['channels']['start'] = self._io.pos()
        self.channels = [None] * (32)
        for i in range(32):
            if not 'arr' in self._debug['channels']:
                self._debug['channels']['arr'] = []
            self._debug['channels']['arr'].append({'start': self._io.pos()})
            _t_channels = self._root.Channel(self._io, self, self._root)
            _t_channels._read()
            self.channels[i] = _t_channels
            self._debug['channels']['arr'][i]['end'] = self._io.pos()

        self._debug['channels']['end'] = self._io.pos()
        self._debug['orders']['start'] = self._io.pos()
        self.orders = self._io.read_bytes(self.num_orders)
        self._debug['orders']['end'] = self._io.pos()
        self._debug['instruments']['start'] = self._io.pos()
        self.instruments = [None] * (self.num_instruments)
        for i in range(self.num_instruments):
            if not 'arr' in self._debug['instruments']:
                self._debug['instruments']['arr'] = []
            self._debug['instruments']['arr'].append({'start': self._io.pos()})
            _t_instruments = self._root.InstrumentPtr(self._io, self, self._root)
            _t_instruments._read()
            self.instruments[i] = _t_instruments
            self._debug['instruments']['arr'][i]['end'] = self._io.pos()

        self._debug['instruments']['end'] = self._io.pos()
        self._debug['patterns']['start'] = self._io.pos()
        self.patterns = [None] * (self.num_patterns)
        for i in range(self.num_patterns):
            if not 'arr' in self._debug['patterns']:
                self._debug['patterns']['arr'] = []
            self._debug['patterns']['arr'].append({'start': self._io.pos()})
            _t_patterns = self._root.PatternPtr(self._io, self, self._root)
            _t_patterns._read()
            self.patterns[i] = _t_patterns
            self._debug['patterns']['arr'][i]['end'] = self._io.pos()

        self._debug['patterns']['end'] = self._io.pos()
        if self.has_custom_pan == 252:
            self._debug['channel_pans']['start'] = self._io.pos()
            self.channel_pans = [None] * (32)
            for i in range(32):
                if not 'arr' in self._debug['channel_pans']:
                    self._debug['channel_pans']['arr'] = []
                self._debug['channel_pans']['arr'].append({'start': self._io.pos()})
                _t_channel_pans = self._root.ChannelPan(self._io, self, self._root)
                _t_channel_pans._read()
                self.channel_pans[i] = _t_channel_pans
                self._debug['channel_pans']['arr'][i]['end'] = self._io.pos()

            self._debug['channel_pans']['end'] = self._io.pos()


    class ChannelPan(KaitaiStruct):
        SEQ_FIELDS = ["reserved1", "has_custom_pan", "reserved2", "pan"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bits_int(2)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['has_custom_pan']['start'] = self._io.pos()
            self.has_custom_pan = self._io.read_bits_int(1) != 0
            self._debug['has_custom_pan']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bits_int(1) != 0
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['pan']['start'] = self._io.pos()
            self.pan = self._io.read_bits_int(4)
            self._debug['pan']['end'] = self._io.pos()


    class PatternCell(KaitaiStruct):
        SEQ_FIELDS = ["has_fx", "has_volume", "has_note_and_instrument", "channel_num", "note", "instrument", "volume", "fx_type", "fx_value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['has_fx']['start'] = self._io.pos()
            self.has_fx = self._io.read_bits_int(1) != 0
            self._debug['has_fx']['end'] = self._io.pos()
            self._debug['has_volume']['start'] = self._io.pos()
            self.has_volume = self._io.read_bits_int(1) != 0
            self._debug['has_volume']['end'] = self._io.pos()
            self._debug['has_note_and_instrument']['start'] = self._io.pos()
            self.has_note_and_instrument = self._io.read_bits_int(1) != 0
            self._debug['has_note_and_instrument']['end'] = self._io.pos()
            self._debug['channel_num']['start'] = self._io.pos()
            self.channel_num = self._io.read_bits_int(5)
            self._debug['channel_num']['end'] = self._io.pos()
            self._io.align_to_byte()
            if self.has_note_and_instrument:
                self._debug['note']['start'] = self._io.pos()
                self.note = self._io.read_u1()
                self._debug['note']['end'] = self._io.pos()

            if self.has_note_and_instrument:
                self._debug['instrument']['start'] = self._io.pos()
                self.instrument = self._io.read_u1()
                self._debug['instrument']['end'] = self._io.pos()

            if self.has_volume:
                self._debug['volume']['start'] = self._io.pos()
                self.volume = self._io.read_u1()
                self._debug['volume']['end'] = self._io.pos()

            if self.has_fx:
                self._debug['fx_type']['start'] = self._io.pos()
                self.fx_type = self._io.read_u1()
                self._debug['fx_type']['end'] = self._io.pos()

            if self.has_fx:
                self._debug['fx_value']['start'] = self._io.pos()
                self.fx_value = self._io.read_u1()
                self._debug['fx_value']['end'] = self._io.pos()



    class PatternCells(KaitaiStruct):
        SEQ_FIELDS = ["cells"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['cells']['start'] = self._io.pos()
            self.cells = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['cells']:
                    self._debug['cells']['arr'] = []
                self._debug['cells']['arr'].append({'start': self._io.pos()})
                _t_cells = self._root.PatternCell(self._io, self, self._root)
                _t_cells._read()
                self.cells.append(_t_cells)
                self._debug['cells']['arr'][len(self.cells) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['cells']['end'] = self._io.pos()


    class Channel(KaitaiStruct):
        SEQ_FIELDS = ["is_disabled", "ch_type"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['is_disabled']['start'] = self._io.pos()
            self.is_disabled = self._io.read_bits_int(1) != 0
            self._debug['is_disabled']['end'] = self._io.pos()
            self._debug['ch_type']['start'] = self._io.pos()
            self.ch_type = self._io.read_bits_int(7)
            self._debug['ch_type']['end'] = self._io.pos()


    class SwappedU3(KaitaiStruct):
        """Custom 3-byte integer, stored in mixed endian manner."""
        SEQ_FIELDS = ["hi", "lo"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['hi']['start'] = self._io.pos()
            self.hi = self._io.read_u1()
            self._debug['hi']['end'] = self._io.pos()
            self._debug['lo']['start'] = self._io.pos()
            self.lo = self._io.read_u2le()
            self._debug['lo']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = (self.lo | (self.hi << 16))
            return self._m_value if hasattr(self, '_m_value') else None


    class Pattern(KaitaiStruct):
        SEQ_FIELDS = ["size", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u2le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self._raw_body = self._io.read_bytes((self.size - 2))
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.PatternCells(io, self, self._root)
            self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class PatternPtr(KaitaiStruct):
        SEQ_FIELDS = ["paraptr"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['paraptr']['start'] = self._io.pos()
            self.paraptr = self._io.read_u2le()
            self._debug['paraptr']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek((self.paraptr * 16))
            self._debug['_m_body']['start'] = self._io.pos()
            self._m_body = self._root.Pattern(self._io, self, self._root)
            self._m_body._read()
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class InstrumentPtr(KaitaiStruct):
        SEQ_FIELDS = ["paraptr"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['paraptr']['start'] = self._io.pos()
            self.paraptr = self._io.read_u2le()
            self._debug['paraptr']['end'] = self._io.pos()

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body if hasattr(self, '_m_body') else None

            _pos = self._io.pos()
            self._io.seek((self.paraptr * 16))
            self._debug['_m_body']['start'] = self._io.pos()
            self._m_body = self._root.Instrument(self._io, self, self._root)
            self._m_body._read()
            self._debug['_m_body']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_body if hasattr(self, '_m_body') else None


    class Instrument(KaitaiStruct):

        class InstTypes(Enum):
            sample = 1
            melodic = 2
            bass_drum = 3
            snare_drum = 4
            tom = 5
            cymbal = 6
            hihat = 7
        SEQ_FIELDS = ["type", "filename", "body", "tuning_hz", "reserved2", "sample_name", "magic"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.Instrument.InstTypes, self._io.read_u1())
            self._debug['type']['end'] = self._io.pos()
            self._debug['filename']['start'] = self._io.pos()
            self.filename = KaitaiStream.bytes_terminate(self._io.read_bytes(12), 0, False)
            self._debug['filename']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.type
            if _on == self._root.Instrument.InstTypes.sample:
                self.body = self._root.Instrument.Sampled(self._io, self, self._root)
                self.body._read()
            else:
                self.body = self._root.Instrument.Adlib(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()
            self._debug['tuning_hz']['start'] = self._io.pos()
            self.tuning_hz = self._io.read_u4le()
            self._debug['tuning_hz']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bytes(12)
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['sample_name']['start'] = self._io.pos()
            self.sample_name = KaitaiStream.bytes_terminate(self._io.read_bytes(28), 0, False)
            self._debug['sample_name']['end'] = self._io.pos()
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x53\x43\x52\x53")
            self._debug['magic']['end'] = self._io.pos()

        class Sampled(KaitaiStruct):
            SEQ_FIELDS = ["paraptr_sample", "len_sample", "loop_begin", "loop_end", "default_volume", "reserved1", "is_packed", "flags"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['paraptr_sample']['start'] = self._io.pos()
                self.paraptr_sample = self._root.SwappedU3(self._io, self, self._root)
                self.paraptr_sample._read()
                self._debug['paraptr_sample']['end'] = self._io.pos()
                self._debug['len_sample']['start'] = self._io.pos()
                self.len_sample = self._io.read_u4le()
                self._debug['len_sample']['end'] = self._io.pos()
                self._debug['loop_begin']['start'] = self._io.pos()
                self.loop_begin = self._io.read_u4le()
                self._debug['loop_begin']['end'] = self._io.pos()
                self._debug['loop_end']['start'] = self._io.pos()
                self.loop_end = self._io.read_u4le()
                self._debug['loop_end']['end'] = self._io.pos()
                self._debug['default_volume']['start'] = self._io.pos()
                self.default_volume = self._io.read_u1()
                self._debug['default_volume']['end'] = self._io.pos()
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.read_u1()
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['is_packed']['start'] = self._io.pos()
                self.is_packed = self._io.read_u1()
                self._debug['is_packed']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._io.read_u1()
                self._debug['flags']['end'] = self._io.pos()

            @property
            def sample(self):
                if hasattr(self, '_m_sample'):
                    return self._m_sample if hasattr(self, '_m_sample') else None

                _pos = self._io.pos()
                self._io.seek((self.paraptr_sample.value * 16))
                self._debug['_m_sample']['start'] = self._io.pos()
                self._m_sample = self._io.read_bytes(self.len_sample)
                self._debug['_m_sample']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_sample if hasattr(self, '_m_sample') else None


        class Adlib(KaitaiStruct):
            SEQ_FIELDS = ["reserved1", "_unnamed1"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved1']['start'] = self._io.pos()
                self.reserved1 = self._io.ensure_fixed_contents(b"\x00\x00\x00")
                self._debug['reserved1']['end'] = self._io.pos()
                self._debug['_unnamed1']['start'] = self._io.pos()
                self._unnamed1 = self._io.read_bytes(16)
                self._debug['_unnamed1']['end'] = self._io.pos()




