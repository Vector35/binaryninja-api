from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ....kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class FasttrackerXmModule(KaitaiStruct):
    """XM (standing for eXtended Module) is a popular module music file
    format, that was introduced in 1994 in FastTracker2 by Triton demo
    group. Akin to MOD files, it bundles both digital samples
    (instruments) and instructions on which note to play at what time
    (patterns), which provides good audio quality with relatively small
    file size. Audio is reproducible without relying on the sound of
    particular hardware samplers or synths.
    
    .. seealso::
       Source - http://sid.ethz.ch/debian/milkytracker/milkytracker-0.90.85%2Bdfsg/resources/reference/xm-form.txt
       ftp://ftp.modland.com/pub/documents/format_documentation/FastTracker%202%20v2.04%20(.xm).html
    """
    SEQ_FIELDS = ["preheader", "header", "patterns", "instruments"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['preheader']['start'] = self._io.pos()
        self.preheader = self._root.Preheader(self._io, self, self._root)
        self.preheader._read()
        self._debug['preheader']['end'] = self._io.pos()
        self._debug['header']['start'] = self._io.pos()
        self._raw_header = self._io.read_bytes((self.preheader.header_size - 4))
        io = KaitaiStream(BytesIO(self._raw_header))
        self.header = self._root.Header(io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['patterns']['start'] = self._io.pos()
        self.patterns = [None] * (self.header.num_patterns)
        for i in range(self.header.num_patterns):
            if not 'arr' in self._debug['patterns']:
                self._debug['patterns']['arr'] = []
            self._debug['patterns']['arr'].append({'start': self._io.pos()})
            _t_patterns = self._root.Pattern(self._io, self, self._root)
            _t_patterns._read()
            self.patterns[i] = _t_patterns
            self._debug['patterns']['arr'][i]['end'] = self._io.pos()

        self._debug['patterns']['end'] = self._io.pos()
        self._debug['instruments']['start'] = self._io.pos()
        self.instruments = [None] * (self.header.num_instruments)
        for i in range(self.header.num_instruments):
            if not 'arr' in self._debug['instruments']:
                self._debug['instruments']['arr'] = []
            self._debug['instruments']['arr'].append({'start': self._io.pos()})
            _t_instruments = self._root.Instrument(self._io, self, self._root)
            _t_instruments._read()
            self.instruments[i] = _t_instruments
            self._debug['instruments']['arr'][i]['end'] = self._io.pos()

        self._debug['instruments']['end'] = self._io.pos()

    class Preheader(KaitaiStruct):
        SEQ_FIELDS = ["signature0", "module_name", "signature1", "tracker_name", "version_number", "header_size"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['signature0']['start'] = self._io.pos()
            self.signature0 = self._io.ensure_fixed_contents(b"\x45\x78\x74\x65\x6E\x64\x65\x64\x20\x4D\x6F\x64\x75\x6C\x65\x3A\x20")
            self._debug['signature0']['end'] = self._io.pos()
            self._debug['module_name']['start'] = self._io.pos()
            self.module_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(20), 0, False)).decode(u"utf-8")
            self._debug['module_name']['end'] = self._io.pos()
            self._debug['signature1']['start'] = self._io.pos()
            self.signature1 = self._io.ensure_fixed_contents(b"\x1A")
            self._debug['signature1']['end'] = self._io.pos()
            self._debug['tracker_name']['start'] = self._io.pos()
            self.tracker_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(20), 0, False)).decode(u"utf-8")
            self._debug['tracker_name']['end'] = self._io.pos()
            self._debug['version_number']['start'] = self._io.pos()
            self.version_number = self._root.Preheader.Version(self._io, self, self._root)
            self.version_number._read()
            self._debug['version_number']['end'] = self._io.pos()
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u4le()
            self._debug['header_size']['end'] = self._io.pos()

        class Version(KaitaiStruct):
            SEQ_FIELDS = ["minor", "major"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['minor']['start'] = self._io.pos()
                self.minor = self._io.read_u1()
                self._debug['minor']['end'] = self._io.pos()
                self._debug['major']['start'] = self._io.pos()
                self.major = self._io.read_u1()
                self._debug['major']['end'] = self._io.pos()

            @property
            def value(self):
                if hasattr(self, '_m_value'):
                    return self._m_value if hasattr(self, '_m_value') else None

                self._m_value = ((self.major << 8) | self.minor)
                return self._m_value if hasattr(self, '_m_value') else None



    class Pattern(KaitaiStruct):
        SEQ_FIELDS = ["header", "packed_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header']['start'] = self._io.pos()
            self.header = self._root.Pattern.Header(self._io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            self._debug['packed_data']['start'] = self._io.pos()
            self.packed_data = self._io.read_bytes(self.header.main.len_packed_pattern)
            self._debug['packed_data']['end'] = self._io.pos()

        class Header(KaitaiStruct):
            SEQ_FIELDS = ["header_length", "main"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['header_length']['start'] = self._io.pos()
                self.header_length = self._io.read_u4le()
                self._debug['header_length']['end'] = self._io.pos()
                self._debug['main']['start'] = self._io.pos()
                self._raw_main = self._io.read_bytes((self.header_length - 4))
                io = KaitaiStream(BytesIO(self._raw_main))
                self.main = self._root.Pattern.Header.HeaderMain(io, self, self._root)
                self.main._read()
                self._debug['main']['end'] = self._io.pos()

            class HeaderMain(KaitaiStruct):
                SEQ_FIELDS = ["packing_type", "num_rows_raw", "len_packed_pattern"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['packing_type']['start'] = self._io.pos()
                    self.packing_type = self._io.read_u1()
                    self._debug['packing_type']['end'] = self._io.pos()
                    self._debug['num_rows_raw']['start'] = self._io.pos()
                    _on = self._root.preheader.version_number.value
                    if _on == 258:
                        self.num_rows_raw = self._io.read_u1()
                    else:
                        self.num_rows_raw = self._io.read_u2le()
                    self._debug['num_rows_raw']['end'] = self._io.pos()
                    self._debug['len_packed_pattern']['start'] = self._io.pos()
                    self.len_packed_pattern = self._io.read_u2le()
                    self._debug['len_packed_pattern']['end'] = self._io.pos()

                @property
                def num_rows(self):
                    if hasattr(self, '_m_num_rows'):
                        return self._m_num_rows if hasattr(self, '_m_num_rows') else None

                    self._m_num_rows = (self.num_rows_raw + (1 if self._root.preheader.version_number.value == 258 else 0))
                    return self._m_num_rows if hasattr(self, '_m_num_rows') else None




    class Flags(KaitaiStruct):
        SEQ_FIELDS = ["reserved", "freq_table_type"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bits_int(15)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['freq_table_type']['start'] = self._io.pos()
            self.freq_table_type = self._io.read_bits_int(1) != 0
            self._debug['freq_table_type']['end'] = self._io.pos()


    class Header(KaitaiStruct):
        SEQ_FIELDS = ["song_length", "restart_position", "num_channels", "num_patterns", "num_instruments", "flags", "default_tempo", "default_bpm", "pattern_order_table"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['song_length']['start'] = self._io.pos()
            self.song_length = self._io.read_u2le()
            self._debug['song_length']['end'] = self._io.pos()
            self._debug['restart_position']['start'] = self._io.pos()
            self.restart_position = self._io.read_u2le()
            self._debug['restart_position']['end'] = self._io.pos()
            self._debug['num_channels']['start'] = self._io.pos()
            self.num_channels = self._io.read_u2le()
            self._debug['num_channels']['end'] = self._io.pos()
            self._debug['num_patterns']['start'] = self._io.pos()
            self.num_patterns = self._io.read_u2le()
            self._debug['num_patterns']['end'] = self._io.pos()
            self._debug['num_instruments']['start'] = self._io.pos()
            self.num_instruments = self._io.read_u2le()
            self._debug['num_instruments']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.Flags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['default_tempo']['start'] = self._io.pos()
            self.default_tempo = self._io.read_u2le()
            self._debug['default_tempo']['end'] = self._io.pos()
            self._debug['default_bpm']['start'] = self._io.pos()
            self.default_bpm = self._io.read_u2le()
            self._debug['default_bpm']['end'] = self._io.pos()
            self._debug['pattern_order_table']['start'] = self._io.pos()
            self.pattern_order_table = [None] * (256)
            for i in range(256):
                if not 'arr' in self._debug['pattern_order_table']:
                    self._debug['pattern_order_table']['arr'] = []
                self._debug['pattern_order_table']['arr'].append({'start': self._io.pos()})
                self.pattern_order_table[i] = self._io.read_u1()
                self._debug['pattern_order_table']['arr'][i]['end'] = self._io.pos()

            self._debug['pattern_order_table']['end'] = self._io.pos()


    class Instrument(KaitaiStruct):
        """XM's notion of "instrument" typically constitutes of a
        instrument metadata and one or several samples. Metadata
        includes:
        
        * instrument's name
        * instruction of which sample to use for which note
        * volume and panning envelopes and looping instructions
        * vibrato settings
        """
        SEQ_FIELDS = ["header_size", "header", "samples_headers", "samples"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u4le()
            self._debug['header_size']['end'] = self._io.pos()
            self._debug['header']['start'] = self._io.pos()
            self._raw_header = self._io.read_bytes((self.header_size - 4))
            io = KaitaiStream(BytesIO(self._raw_header))
            self.header = self._root.Instrument.Header(io, self, self._root)
            self.header._read()
            self._debug['header']['end'] = self._io.pos()
            self._debug['samples_headers']['start'] = self._io.pos()
            self.samples_headers = [None] * (self.header.num_samples)
            for i in range(self.header.num_samples):
                if not 'arr' in self._debug['samples_headers']:
                    self._debug['samples_headers']['arr'] = []
                self._debug['samples_headers']['arr'].append({'start': self._io.pos()})
                _t_samples_headers = self._root.Instrument.SampleHeader(self._io, self, self._root)
                _t_samples_headers._read()
                self.samples_headers[i] = _t_samples_headers
                self._debug['samples_headers']['arr'][i]['end'] = self._io.pos()

            self._debug['samples_headers']['end'] = self._io.pos()
            self._debug['samples']['start'] = self._io.pos()
            self.samples = [None] * (self.header.num_samples)
            for i in range(self.header.num_samples):
                if not 'arr' in self._debug['samples']:
                    self._debug['samples']['arr'] = []
                self._debug['samples']['arr'].append({'start': self._io.pos()})
                _t_samples = self._root.Instrument.SamplesData(self.samples_headers[i], self._io, self, self._root)
                _t_samples._read()
                self.samples[i] = _t_samples
                self._debug['samples']['arr'][i]['end'] = self._io.pos()

            self._debug['samples']['end'] = self._io.pos()

        class Header(KaitaiStruct):
            SEQ_FIELDS = ["name", "type", "num_samples", "extra_header"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['name']['start'] = self._io.pos()
                self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(22), 0, False)).decode(u"utf-8")
                self._debug['name']['end'] = self._io.pos()
                self._debug['type']['start'] = self._io.pos()
                self.type = self._io.read_u1()
                self._debug['type']['end'] = self._io.pos()
                self._debug['num_samples']['start'] = self._io.pos()
                self.num_samples = self._io.read_u2le()
                self._debug['num_samples']['end'] = self._io.pos()
                if self.num_samples > 0:
                    self._debug['extra_header']['start'] = self._io.pos()
                    self.extra_header = self._root.Instrument.ExtraHeader(self._io, self, self._root)
                    self.extra_header._read()
                    self._debug['extra_header']['end'] = self._io.pos()



        class ExtraHeader(KaitaiStruct):

            class Type(Enum):
                true = 0
                sustain = 1
                loop = 2
            SEQ_FIELDS = ["len_sample_header", "idx_sample_per_note", "volume_points", "panning_points", "num_volume_points", "num_panning_points", "volume_sustain_point", "volume_loop_start_point", "volume_loop_end_point", "panning_sustain_point", "panning_loop_start_point", "panning_loop_end_point", "volume_type", "panning_type", "vibrato_type", "vibrato_sweep", "vibrato_depth", "vibrato_rate", "volume_fadeout", "reserved"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['len_sample_header']['start'] = self._io.pos()
                self.len_sample_header = self._io.read_u4le()
                self._debug['len_sample_header']['end'] = self._io.pos()
                self._debug['idx_sample_per_note']['start'] = self._io.pos()
                self.idx_sample_per_note = [None] * (96)
                for i in range(96):
                    if not 'arr' in self._debug['idx_sample_per_note']:
                        self._debug['idx_sample_per_note']['arr'] = []
                    self._debug['idx_sample_per_note']['arr'].append({'start': self._io.pos()})
                    self.idx_sample_per_note[i] = self._io.read_u1()
                    self._debug['idx_sample_per_note']['arr'][i]['end'] = self._io.pos()

                self._debug['idx_sample_per_note']['end'] = self._io.pos()
                self._debug['volume_points']['start'] = self._io.pos()
                self.volume_points = [None] * (12)
                for i in range(12):
                    if not 'arr' in self._debug['volume_points']:
                        self._debug['volume_points']['arr'] = []
                    self._debug['volume_points']['arr'].append({'start': self._io.pos()})
                    _t_volume_points = self._root.Instrument.ExtraHeader.EnvelopePoint(self._io, self, self._root)
                    _t_volume_points._read()
                    self.volume_points[i] = _t_volume_points
                    self._debug['volume_points']['arr'][i]['end'] = self._io.pos()

                self._debug['volume_points']['end'] = self._io.pos()
                self._debug['panning_points']['start'] = self._io.pos()
                self.panning_points = [None] * (12)
                for i in range(12):
                    if not 'arr' in self._debug['panning_points']:
                        self._debug['panning_points']['arr'] = []
                    self._debug['panning_points']['arr'].append({'start': self._io.pos()})
                    _t_panning_points = self._root.Instrument.ExtraHeader.EnvelopePoint(self._io, self, self._root)
                    _t_panning_points._read()
                    self.panning_points[i] = _t_panning_points
                    self._debug['panning_points']['arr'][i]['end'] = self._io.pos()

                self._debug['panning_points']['end'] = self._io.pos()
                self._debug['num_volume_points']['start'] = self._io.pos()
                self.num_volume_points = self._io.read_u1()
                self._debug['num_volume_points']['end'] = self._io.pos()
                self._debug['num_panning_points']['start'] = self._io.pos()
                self.num_panning_points = self._io.read_u1()
                self._debug['num_panning_points']['end'] = self._io.pos()
                self._debug['volume_sustain_point']['start'] = self._io.pos()
                self.volume_sustain_point = self._io.read_u1()
                self._debug['volume_sustain_point']['end'] = self._io.pos()
                self._debug['volume_loop_start_point']['start'] = self._io.pos()
                self.volume_loop_start_point = self._io.read_u1()
                self._debug['volume_loop_start_point']['end'] = self._io.pos()
                self._debug['volume_loop_end_point']['start'] = self._io.pos()
                self.volume_loop_end_point = self._io.read_u1()
                self._debug['volume_loop_end_point']['end'] = self._io.pos()
                self._debug['panning_sustain_point']['start'] = self._io.pos()
                self.panning_sustain_point = self._io.read_u1()
                self._debug['panning_sustain_point']['end'] = self._io.pos()
                self._debug['panning_loop_start_point']['start'] = self._io.pos()
                self.panning_loop_start_point = self._io.read_u1()
                self._debug['panning_loop_start_point']['end'] = self._io.pos()
                self._debug['panning_loop_end_point']['start'] = self._io.pos()
                self.panning_loop_end_point = self._io.read_u1()
                self._debug['panning_loop_end_point']['end'] = self._io.pos()
                self._debug['volume_type']['start'] = self._io.pos()
                self.volume_type = KaitaiStream.resolve_enum(self._root.Instrument.ExtraHeader.Type, self._io.read_u1())
                self._debug['volume_type']['end'] = self._io.pos()
                self._debug['panning_type']['start'] = self._io.pos()
                self.panning_type = KaitaiStream.resolve_enum(self._root.Instrument.ExtraHeader.Type, self._io.read_u1())
                self._debug['panning_type']['end'] = self._io.pos()
                self._debug['vibrato_type']['start'] = self._io.pos()
                self.vibrato_type = self._io.read_u1()
                self._debug['vibrato_type']['end'] = self._io.pos()
                self._debug['vibrato_sweep']['start'] = self._io.pos()
                self.vibrato_sweep = self._io.read_u1()
                self._debug['vibrato_sweep']['end'] = self._io.pos()
                self._debug['vibrato_depth']['start'] = self._io.pos()
                self.vibrato_depth = self._io.read_u1()
                self._debug['vibrato_depth']['end'] = self._io.pos()
                self._debug['vibrato_rate']['start'] = self._io.pos()
                self.vibrato_rate = self._io.read_u1()
                self._debug['vibrato_rate']['end'] = self._io.pos()
                self._debug['volume_fadeout']['start'] = self._io.pos()
                self.volume_fadeout = self._io.read_u2le()
                self._debug['volume_fadeout']['end'] = self._io.pos()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_u2le()
                self._debug['reserved']['end'] = self._io.pos()

            class EnvelopePoint(KaitaiStruct):
                """Envelope frame-counters work in range 0..FFFFh (0..65535 dec).
                BUT! FT2 only itself supports only range 0..FFh (0..255 dec).
                Some other trackers (like SoundTracker for Unix), however, can use the full range 0..FFFF, so it should be supported.
                !!TIP: This is also a good way to detect if the module has been made with FT2 or not. (In case the tracker name is brain- deadly left unchanged!)
                Of course it does not help if all instruments have the values inside FT2 supported range.
                The value-field of the envelope point is ranged between 00..3Fh (0..64 dec).
                """
                SEQ_FIELDS = ["x", "y"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['x']['start'] = self._io.pos()
                    self.x = self._io.read_u2le()
                    self._debug['x']['end'] = self._io.pos()
                    self._debug['y']['start'] = self._io.pos()
                    self.y = self._io.read_u2le()
                    self._debug['y']['end'] = self._io.pos()



        class SamplesData(KaitaiStruct):
            """The saved data uses simple delta-encoding to achieve better compression ratios (when compressed with pkzip, etc.)
            Pseudocode for converting the delta-coded data to normal data,
            old = 0;
            for i in range(data_len):
              new = sample[i] + old;
              sample[i] = new;
              old = new;
            """
            SEQ_FIELDS = ["data"]
            def __init__(self, header, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self.header = header
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['data']['start'] = self._io.pos()
                self.data = self._io.read_bytes((self.header.sample_length * (2 if self.header.type.is_sample_data_16_bit else 1)))
                self._debug['data']['end'] = self._io.pos()


        class SampleHeader(KaitaiStruct):
            SEQ_FIELDS = ["sample_length", "sample_loop_start", "sample_loop_length", "volume", "fine_tune", "type", "panning", "relative_note_number", "reserved", "name"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['sample_length']['start'] = self._io.pos()
                self.sample_length = self._io.read_u4le()
                self._debug['sample_length']['end'] = self._io.pos()
                self._debug['sample_loop_start']['start'] = self._io.pos()
                self.sample_loop_start = self._io.read_u4le()
                self._debug['sample_loop_start']['end'] = self._io.pos()
                self._debug['sample_loop_length']['start'] = self._io.pos()
                self.sample_loop_length = self._io.read_u4le()
                self._debug['sample_loop_length']['end'] = self._io.pos()
                self._debug['volume']['start'] = self._io.pos()
                self.volume = self._io.read_u1()
                self._debug['volume']['end'] = self._io.pos()
                self._debug['fine_tune']['start'] = self._io.pos()
                self.fine_tune = self._io.read_s1()
                self._debug['fine_tune']['end'] = self._io.pos()
                self._debug['type']['start'] = self._io.pos()
                self.type = self._root.Instrument.SampleHeader.LoopType(self._io, self, self._root)
                self.type._read()
                self._debug['type']['end'] = self._io.pos()
                self._debug['panning']['start'] = self._io.pos()
                self.panning = self._io.read_u1()
                self._debug['panning']['end'] = self._io.pos()
                self._debug['relative_note_number']['start'] = self._io.pos()
                self.relative_note_number = self._io.read_s1()
                self._debug['relative_note_number']['end'] = self._io.pos()
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_u1()
                self._debug['reserved']['end'] = self._io.pos()
                self._debug['name']['start'] = self._io.pos()
                self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(22), 0, False)).decode(u"utf-8")
                self._debug['name']['end'] = self._io.pos()

            class LoopType(KaitaiStruct):

                class LoopType(Enum):
                    none = 0
                    forward = 1
                    ping_pong = 2
                SEQ_FIELDS = ["reserved0", "is_sample_data_16_bit", "reserved1", "loop_type"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['reserved0']['start'] = self._io.pos()
                    self.reserved0 = self._io.read_bits_int(3)
                    self._debug['reserved0']['end'] = self._io.pos()
                    self._debug['is_sample_data_16_bit']['start'] = self._io.pos()
                    self.is_sample_data_16_bit = self._io.read_bits_int(1) != 0
                    self._debug['is_sample_data_16_bit']['end'] = self._io.pos()
                    self._debug['reserved1']['start'] = self._io.pos()
                    self.reserved1 = self._io.read_bits_int(2)
                    self._debug['reserved1']['end'] = self._io.pos()
                    self._debug['loop_type']['start'] = self._io.pos()
                    self.loop_type = KaitaiStream.resolve_enum(self._root.Instrument.SampleHeader.LoopType.LoopType, self._io.read_bits_int(2))
                    self._debug['loop_type']['end'] = self._io.pos()





