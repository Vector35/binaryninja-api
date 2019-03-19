# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from vlq_base128_be import VlqBase128Be
class StandardMidiFile(KaitaiStruct):
    """Standard MIDI file, typically knows just as "MID", is a standard way
    to serialize series of MIDI events, which is a protocol used in many
    music synthesizers to transfer music data: notes being played,
    effects being applied, etc.
    
    Internally, file consists of a header and series of tracks, every
    track listing MIDI events with certain header designating time these
    events are happening.
    
    NOTE: Rarely, MIDI files employ certain stateful compression scheme
    to avoid storing certain elements of further elements, instead
    reusing them from events which happened earlier in the
    stream. Kaitai Struct (as of v0.9) is currently unable to parse
    these, but files employing this mechanism are relatively rare.
    """
    SEQ_FIELDS = ["hdr", "tracks"]
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
        self._debug['tracks']['start'] = self._io.pos()
        self.tracks = [None] * (self.hdr.num_tracks)
        for i in range(self.hdr.num_tracks):
            if not 'arr' in self._debug['tracks']:
                self._debug['tracks']['arr'] = []
            self._debug['tracks']['arr'].append({'start': self._io.pos()})
            _t_tracks = self._root.Track(self._io, self, self._root)
            _t_tracks._read()
            self.tracks[i] = _t_tracks
            self._debug['tracks']['arr'][i]['end'] = self._io.pos()

        self._debug['tracks']['end'] = self._io.pos()

    class TrackEvents(KaitaiStruct):
        SEQ_FIELDS = ["event"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['event']['start'] = self._io.pos()
            self.event = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['event']:
                    self._debug['event']['arr'] = []
                self._debug['event']['arr'].append({'start': self._io.pos()})
                _t_event = self._root.TrackEvent(self._io, self, self._root)
                _t_event._read()
                self.event.append(_t_event)
                self._debug['event']['arr'][len(self.event) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['event']['end'] = self._io.pos()


    class TrackEvent(KaitaiStruct):
        SEQ_FIELDS = ["v_time", "event_header", "meta_event_body", "sysex_body", "event_body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['v_time']['start'] = self._io.pos()
            self.v_time = VlqBase128Be(self._io)
            self.v_time._read()
            self._debug['v_time']['end'] = self._io.pos()
            self._debug['event_header']['start'] = self._io.pos()
            self.event_header = self._io.read_u1()
            self._debug['event_header']['end'] = self._io.pos()
            if self.event_header == 255:
                self._debug['meta_event_body']['start'] = self._io.pos()
                self.meta_event_body = self._root.MetaEventBody(self._io, self, self._root)
                self.meta_event_body._read()
                self._debug['meta_event_body']['end'] = self._io.pos()

            if self.event_header == 240:
                self._debug['sysex_body']['start'] = self._io.pos()
                self.sysex_body = self._root.SysexEventBody(self._io, self, self._root)
                self.sysex_body._read()
                self._debug['sysex_body']['end'] = self._io.pos()

            self._debug['event_body']['start'] = self._io.pos()
            _on = self.event_type
            if _on == 224:
                self.event_body = self._root.PitchBendEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 144:
                self.event_body = self._root.NoteOnEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 208:
                self.event_body = self._root.ChannelPressureEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 192:
                self.event_body = self._root.ProgramChangeEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 160:
                self.event_body = self._root.PolyphonicPressureEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 176:
                self.event_body = self._root.ControllerEvent(self._io, self, self._root)
                self.event_body._read()
            elif _on == 128:
                self.event_body = self._root.NoteOffEvent(self._io, self, self._root)
                self.event_body._read()
            self._debug['event_body']['end'] = self._io.pos()

        @property
        def event_type(self):
            if hasattr(self, '_m_event_type'):
                return self._m_event_type if hasattr(self, '_m_event_type') else None

            self._m_event_type = (self.event_header & 240)
            return self._m_event_type if hasattr(self, '_m_event_type') else None

        @property
        def channel(self):
            if hasattr(self, '_m_channel'):
                return self._m_channel if hasattr(self, '_m_channel') else None

            if self.event_type != 240:
                self._m_channel = (self.event_header & 15)

            return self._m_channel if hasattr(self, '_m_channel') else None


    class PitchBendEvent(KaitaiStruct):
        SEQ_FIELDS = ["b1", "b2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['b1']['start'] = self._io.pos()
            self.b1 = self._io.read_u1()
            self._debug['b1']['end'] = self._io.pos()
            self._debug['b2']['start'] = self._io.pos()
            self.b2 = self._io.read_u1()
            self._debug['b2']['end'] = self._io.pos()

        @property
        def bend_value(self):
            if hasattr(self, '_m_bend_value'):
                return self._m_bend_value if hasattr(self, '_m_bend_value') else None

            self._m_bend_value = (((self.b2 << 7) + self.b1) - 16384)
            return self._m_bend_value if hasattr(self, '_m_bend_value') else None

        @property
        def adj_bend_value(self):
            if hasattr(self, '_m_adj_bend_value'):
                return self._m_adj_bend_value if hasattr(self, '_m_adj_bend_value') else None

            self._m_adj_bend_value = (self.bend_value - 16384)
            return self._m_adj_bend_value if hasattr(self, '_m_adj_bend_value') else None


    class ProgramChangeEvent(KaitaiStruct):
        SEQ_FIELDS = ["program"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['program']['start'] = self._io.pos()
            self.program = self._io.read_u1()
            self._debug['program']['end'] = self._io.pos()


    class NoteOnEvent(KaitaiStruct):
        SEQ_FIELDS = ["note", "velocity"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['note']['start'] = self._io.pos()
            self.note = self._io.read_u1()
            self._debug['note']['end'] = self._io.pos()
            self._debug['velocity']['start'] = self._io.pos()
            self.velocity = self._io.read_u1()
            self._debug['velocity']['end'] = self._io.pos()


    class PolyphonicPressureEvent(KaitaiStruct):
        SEQ_FIELDS = ["note", "pressure"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['note']['start'] = self._io.pos()
            self.note = self._io.read_u1()
            self._debug['note']['end'] = self._io.pos()
            self._debug['pressure']['start'] = self._io.pos()
            self.pressure = self._io.read_u1()
            self._debug['pressure']['end'] = self._io.pos()


    class Track(KaitaiStruct):
        SEQ_FIELDS = ["magic", "len_events", "events"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x4D\x54\x72\x6B")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['len_events']['start'] = self._io.pos()
            self.len_events = self._io.read_u4be()
            self._debug['len_events']['end'] = self._io.pos()
            self._debug['events']['start'] = self._io.pos()
            self._raw_events = self._io.read_bytes(self.len_events)
            io = KaitaiStream(BytesIO(self._raw_events))
            self.events = self._root.TrackEvents(io, self, self._root)
            self.events._read()
            self._debug['events']['end'] = self._io.pos()


    class MetaEventBody(KaitaiStruct):

        class MetaTypeEnum(Enum):
            sequence_number = 0
            text_event = 1
            copyright = 2
            sequence_track_name = 3
            instrument_name = 4
            lyric_text = 5
            marker_text = 6
            cue_point = 7
            midi_channel_prefix_assignment = 32
            end_of_track = 47
            tempo = 81
            smpte_offset = 84
            time_signature = 88
            key_signature = 89
            sequencer_specific_event = 127
        SEQ_FIELDS = ["meta_type", "len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['meta_type']['start'] = self._io.pos()
            self.meta_type = KaitaiStream.resolve_enum(self._root.MetaEventBody.MetaTypeEnum, self._io.read_u1())
            self._debug['meta_type']['end'] = self._io.pos()
            self._debug['len']['start'] = self._io.pos()
            self.len = VlqBase128Be(self._io)
            self.len._read()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.len.value)
            self._debug['body']['end'] = self._io.pos()


    class ControllerEvent(KaitaiStruct):
        SEQ_FIELDS = ["controller", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['controller']['start'] = self._io.pos()
            self.controller = self._io.read_u1()
            self._debug['controller']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_u1()
            self._debug['value']['end'] = self._io.pos()


    class Header(KaitaiStruct):
        SEQ_FIELDS = ["magic", "len_header", "format", "num_tracks", "division"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x4D\x54\x68\x64")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['len_header']['start'] = self._io.pos()
            self.len_header = self._io.read_u4be()
            self._debug['len_header']['end'] = self._io.pos()
            self._debug['format']['start'] = self._io.pos()
            self.format = self._io.read_u2be()
            self._debug['format']['end'] = self._io.pos()
            self._debug['num_tracks']['start'] = self._io.pos()
            self.num_tracks = self._io.read_u2be()
            self._debug['num_tracks']['end'] = self._io.pos()
            self._debug['division']['start'] = self._io.pos()
            self.division = self._io.read_s2be()
            self._debug['division']['end'] = self._io.pos()


    class SysexEventBody(KaitaiStruct):
        SEQ_FIELDS = ["len", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = VlqBase128Be(self._io)
            self.len._read()
            self._debug['len']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes(self.len.value)
            self._debug['data']['end'] = self._io.pos()


    class NoteOffEvent(KaitaiStruct):
        SEQ_FIELDS = ["note", "velocity"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['note']['start'] = self._io.pos()
            self.note = self._io.read_u1()
            self._debug['note']['end'] = self._io.pos()
            self._debug['velocity']['start'] = self._io.pos()
            self.velocity = self._io.read_u1()
            self._debug['velocity']['end'] = self._io.pos()


    class ChannelPressureEvent(KaitaiStruct):
        SEQ_FIELDS = ["pressure"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['pressure']['start'] = self._io.pos()
            self.pressure = self._io.read_u1()
            self._debug['pressure']['end'] = self._io.pos()



