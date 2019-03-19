# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Wav(KaitaiStruct):
    """The WAVE file format is a subset of Microsoft's RIFF specification for the
    storage of multimedia files. A RIFF file starts out with a file header
    followed by a sequence of data chunks. A WAVE file is often just a RIFF
    file with a single "WAVE" chunk which consists of two sub-chunks --
    a "fmt " chunk specifying the data format and a "data" chunk containing
    the actual sample data.
    
    This Kaitai implementation was written by John Byrd of Gigantic Software
    (jbyrd@giganticsoftware.com), and it is likely to contain bugs.
    
    .. seealso::
       Source - https://www.loc.gov/preservation/digital/formats/fdd/fdd000001.shtml
    """

    class WFormatTagType(Enum):
        unknown = 0
        pcm = 1
        adpcm = 2
        ieee_float = 3
        alaw = 6
        mulaw = 7
        dvi_adpcm = 17
        dolby_ac3_spdif = 146
        extensible = 65534
        development = 65535

    class ChunkType(Enum):
        fmt = 544501094
        bext = 1650817140
        cue = 1668637984
        data = 1684108385
        minf = 1835626086
        regn = 1919248238
        umid = 1970104676
    SEQ_FIELDS = ["riff_id", "file_size", "wave_id", "chunks"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['riff_id']['start'] = self._io.pos()
        self.riff_id = self._io.ensure_fixed_contents(b"\x52\x49\x46\x46")
        self._debug['riff_id']['end'] = self._io.pos()
        self._debug['file_size']['start'] = self._io.pos()
        self.file_size = self._io.read_u4le()
        self._debug['file_size']['end'] = self._io.pos()
        self._debug['wave_id']['start'] = self._io.pos()
        self.wave_id = self._io.ensure_fixed_contents(b"\x57\x41\x56\x45")
        self._debug['wave_id']['end'] = self._io.pos()
        self._debug['chunks']['start'] = self._io.pos()
        self._raw_chunks = self._io.read_bytes((self.file_size - 5))
        io = KaitaiStream(BytesIO(self._raw_chunks))
        self.chunks = self._root.ChunksType(io, self, self._root)
        self.chunks._read()
        self._debug['chunks']['end'] = self._io.pos()

    class SampleType(KaitaiStruct):
        SEQ_FIELDS = ["sample"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sample']['start'] = self._io.pos()
            self.sample = self._io.read_u2le()
            self._debug['sample']['end'] = self._io.pos()


    class FormatChunkType(KaitaiStruct):
        SEQ_FIELDS = ["w_format_tag", "n_channels", "n_samples_per_sec", "n_avg_bytes_per_sec", "n_block_align", "w_bits_per_sample", "cb_size", "w_valid_bits_per_sample", "channel_mask_and_subformat"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['w_format_tag']['start'] = self._io.pos()
            self.w_format_tag = KaitaiStream.resolve_enum(self._root.WFormatTagType, self._io.read_u2le())
            self._debug['w_format_tag']['end'] = self._io.pos()
            self._debug['n_channels']['start'] = self._io.pos()
            self.n_channels = self._io.read_u2le()
            self._debug['n_channels']['end'] = self._io.pos()
            self._debug['n_samples_per_sec']['start'] = self._io.pos()
            self.n_samples_per_sec = self._io.read_u4le()
            self._debug['n_samples_per_sec']['end'] = self._io.pos()
            self._debug['n_avg_bytes_per_sec']['start'] = self._io.pos()
            self.n_avg_bytes_per_sec = self._io.read_u4le()
            self._debug['n_avg_bytes_per_sec']['end'] = self._io.pos()
            self._debug['n_block_align']['start'] = self._io.pos()
            self.n_block_align = self._io.read_u2le()
            self._debug['n_block_align']['end'] = self._io.pos()
            self._debug['w_bits_per_sample']['start'] = self._io.pos()
            self.w_bits_per_sample = self._io.read_u2le()
            self._debug['w_bits_per_sample']['end'] = self._io.pos()
            if not (self.is_basic_pcm):
                self._debug['cb_size']['start'] = self._io.pos()
                self.cb_size = self._io.read_u2le()
                self._debug['cb_size']['end'] = self._io.pos()

            if self.is_cb_size_meaningful:
                self._debug['w_valid_bits_per_sample']['start'] = self._io.pos()
                self.w_valid_bits_per_sample = self._io.read_u2le()
                self._debug['w_valid_bits_per_sample']['end'] = self._io.pos()

            if self.is_extensible:
                self._debug['channel_mask_and_subformat']['start'] = self._io.pos()
                self.channel_mask_and_subformat = self._root.ChannelMaskAndSubformatType(self._io, self, self._root)
                self.channel_mask_and_subformat._read()
                self._debug['channel_mask_and_subformat']['end'] = self._io.pos()


        @property
        def is_extensible(self):
            if hasattr(self, '_m_is_extensible'):
                return self._m_is_extensible if hasattr(self, '_m_is_extensible') else None

            self._m_is_extensible = self.w_format_tag == self._root.WFormatTagType.extensible
            return self._m_is_extensible if hasattr(self, '_m_is_extensible') else None

        @property
        def is_basic_pcm(self):
            if hasattr(self, '_m_is_basic_pcm'):
                return self._m_is_basic_pcm if hasattr(self, '_m_is_basic_pcm') else None

            self._m_is_basic_pcm = self.w_format_tag == self._root.WFormatTagType.pcm
            return self._m_is_basic_pcm if hasattr(self, '_m_is_basic_pcm') else None

        @property
        def is_basic_float(self):
            if hasattr(self, '_m_is_basic_float'):
                return self._m_is_basic_float if hasattr(self, '_m_is_basic_float') else None

            self._m_is_basic_float = self.w_format_tag == self._root.WFormatTagType.ieee_float
            return self._m_is_basic_float if hasattr(self, '_m_is_basic_float') else None

        @property
        def is_cb_size_meaningful(self):
            if hasattr(self, '_m_is_cb_size_meaningful'):
                return self._m_is_cb_size_meaningful if hasattr(self, '_m_is_cb_size_meaningful') else None

            self._m_is_cb_size_meaningful =  ((not (self.is_basic_pcm)) and (self.cb_size != 0)) 
            return self._m_is_cb_size_meaningful if hasattr(self, '_m_is_cb_size_meaningful') else None


    class GuidType(KaitaiStruct):
        SEQ_FIELDS = ["data1", "data2", "data3", "data4", "data4a"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['data1']['start'] = self._io.pos()
            self.data1 = self._io.read_u4le()
            self._debug['data1']['end'] = self._io.pos()
            self._debug['data2']['start'] = self._io.pos()
            self.data2 = self._io.read_u2le()
            self._debug['data2']['end'] = self._io.pos()
            self._debug['data3']['start'] = self._io.pos()
            self.data3 = self._io.read_u2le()
            self._debug['data3']['end'] = self._io.pos()
            self._debug['data4']['start'] = self._io.pos()
            self.data4 = self._io.read_u4be()
            self._debug['data4']['end'] = self._io.pos()
            self._debug['data4a']['start'] = self._io.pos()
            self.data4a = self._io.read_u4be()
            self._debug['data4a']['end'] = self._io.pos()


    class CuePointType(KaitaiStruct):
        SEQ_FIELDS = ["dw_name", "dw_position", "fcc_chunk", "dw_chunk_start", "dw_block_start", "dw_sample_offset"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['dw_name']['start'] = self._io.pos()
            self.dw_name = self._io.read_u4le()
            self._debug['dw_name']['end'] = self._io.pos()
            self._debug['dw_position']['start'] = self._io.pos()
            self.dw_position = self._io.read_u4le()
            self._debug['dw_position']['end'] = self._io.pos()
            self._debug['fcc_chunk']['start'] = self._io.pos()
            self.fcc_chunk = self._io.read_u4le()
            self._debug['fcc_chunk']['end'] = self._io.pos()
            self._debug['dw_chunk_start']['start'] = self._io.pos()
            self.dw_chunk_start = self._io.read_u4le()
            self._debug['dw_chunk_start']['end'] = self._io.pos()
            self._debug['dw_block_start']['start'] = self._io.pos()
            self.dw_block_start = self._io.read_u4le()
            self._debug['dw_block_start']['end'] = self._io.pos()
            self._debug['dw_sample_offset']['start'] = self._io.pos()
            self.dw_sample_offset = self._io.read_u4le()
            self._debug['dw_sample_offset']['end'] = self._io.pos()


    class DataChunkType(KaitaiStruct):
        SEQ_FIELDS = ["data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes_full()
            self._debug['data']['end'] = self._io.pos()


    class SamplesType(KaitaiStruct):
        SEQ_FIELDS = ["samples"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['samples']['start'] = self._io.pos()
            self.samples = self._io.read_u4le()
            self._debug['samples']['end'] = self._io.pos()


    class ChannelMaskAndSubformatType(KaitaiStruct):
        SEQ_FIELDS = ["dw_channel_mask", "subformat"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['dw_channel_mask']['start'] = self._io.pos()
            self.dw_channel_mask = self._root.ChannelMaskType(self._io, self, self._root)
            self.dw_channel_mask._read()
            self._debug['dw_channel_mask']['end'] = self._io.pos()
            self._debug['subformat']['start'] = self._io.pos()
            self.subformat = self._root.GuidType(self._io, self, self._root)
            self.subformat._read()
            self._debug['subformat']['end'] = self._io.pos()


    class ChunksType(KaitaiStruct):
        SEQ_FIELDS = ["chunk"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chunk']['start'] = self._io.pos()
            self.chunk = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['chunk']:
                    self._debug['chunk']['arr'] = []
                self._debug['chunk']['arr'].append({'start': self._io.pos()})
                _t_chunk = self._root.ChunkType(self._io, self, self._root)
                _t_chunk._read()
                self.chunk.append(_t_chunk)
                self._debug['chunk']['arr'][len(self.chunk) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['chunk']['end'] = self._io.pos()


    class CueChunkType(KaitaiStruct):
        SEQ_FIELDS = ["dw_cue_points", "cue_points"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['dw_cue_points']['start'] = self._io.pos()
            self.dw_cue_points = self._io.read_u4le()
            self._debug['dw_cue_points']['end'] = self._io.pos()
            if self.dw_cue_points != 0:
                self._debug['cue_points']['start'] = self._io.pos()
                self.cue_points = [None] * (self.dw_cue_points)
                for i in range(self.dw_cue_points):
                    if not 'arr' in self._debug['cue_points']:
                        self._debug['cue_points']['arr'] = []
                    self._debug['cue_points']['arr'].append({'start': self._io.pos()})
                    _t_cue_points = self._root.CuePointType(self._io, self, self._root)
                    _t_cue_points._read()
                    self.cue_points[i] = _t_cue_points
                    self._debug['cue_points']['arr'][i]['end'] = self._io.pos()

                self._debug['cue_points']['end'] = self._io.pos()



    class ChannelMaskType(KaitaiStruct):
        SEQ_FIELDS = ["front_right_of_center", "front_left_of_center", "back_right", "back_left", "low_frequency", "front_center", "front_right", "front_left", "top_center", "side_right", "side_left", "back_center", "top_back_left", "top_front_right", "top_front_center", "top_front_left", "unused1", "top_back_right", "top_back_center", "unused2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['front_right_of_center']['start'] = self._io.pos()
            self.front_right_of_center = self._io.read_bits_int(1) != 0
            self._debug['front_right_of_center']['end'] = self._io.pos()
            self._debug['front_left_of_center']['start'] = self._io.pos()
            self.front_left_of_center = self._io.read_bits_int(1) != 0
            self._debug['front_left_of_center']['end'] = self._io.pos()
            self._debug['back_right']['start'] = self._io.pos()
            self.back_right = self._io.read_bits_int(1) != 0
            self._debug['back_right']['end'] = self._io.pos()
            self._debug['back_left']['start'] = self._io.pos()
            self.back_left = self._io.read_bits_int(1) != 0
            self._debug['back_left']['end'] = self._io.pos()
            self._debug['low_frequency']['start'] = self._io.pos()
            self.low_frequency = self._io.read_bits_int(1) != 0
            self._debug['low_frequency']['end'] = self._io.pos()
            self._debug['front_center']['start'] = self._io.pos()
            self.front_center = self._io.read_bits_int(1) != 0
            self._debug['front_center']['end'] = self._io.pos()
            self._debug['front_right']['start'] = self._io.pos()
            self.front_right = self._io.read_bits_int(1) != 0
            self._debug['front_right']['end'] = self._io.pos()
            self._debug['front_left']['start'] = self._io.pos()
            self.front_left = self._io.read_bits_int(1) != 0
            self._debug['front_left']['end'] = self._io.pos()
            self._debug['top_center']['start'] = self._io.pos()
            self.top_center = self._io.read_bits_int(1) != 0
            self._debug['top_center']['end'] = self._io.pos()
            self._debug['side_right']['start'] = self._io.pos()
            self.side_right = self._io.read_bits_int(1) != 0
            self._debug['side_right']['end'] = self._io.pos()
            self._debug['side_left']['start'] = self._io.pos()
            self.side_left = self._io.read_bits_int(1) != 0
            self._debug['side_left']['end'] = self._io.pos()
            self._debug['back_center']['start'] = self._io.pos()
            self.back_center = self._io.read_bits_int(1) != 0
            self._debug['back_center']['end'] = self._io.pos()
            self._debug['top_back_left']['start'] = self._io.pos()
            self.top_back_left = self._io.read_bits_int(1) != 0
            self._debug['top_back_left']['end'] = self._io.pos()
            self._debug['top_front_right']['start'] = self._io.pos()
            self.top_front_right = self._io.read_bits_int(1) != 0
            self._debug['top_front_right']['end'] = self._io.pos()
            self._debug['top_front_center']['start'] = self._io.pos()
            self.top_front_center = self._io.read_bits_int(1) != 0
            self._debug['top_front_center']['end'] = self._io.pos()
            self._debug['top_front_left']['start'] = self._io.pos()
            self.top_front_left = self._io.read_bits_int(1) != 0
            self._debug['top_front_left']['end'] = self._io.pos()
            self._debug['unused1']['start'] = self._io.pos()
            self.unused1 = self._io.read_bits_int(6)
            self._debug['unused1']['end'] = self._io.pos()
            self._debug['top_back_right']['start'] = self._io.pos()
            self.top_back_right = self._io.read_bits_int(1) != 0
            self._debug['top_back_right']['end'] = self._io.pos()
            self._debug['top_back_center']['start'] = self._io.pos()
            self.top_back_center = self._io.read_bits_int(1) != 0
            self._debug['top_back_center']['end'] = self._io.pos()
            self._debug['unused2']['start'] = self._io.pos()
            self.unused2 = self._io.read_bits_int(8)
            self._debug['unused2']['end'] = self._io.pos()


    class ChunkType(KaitaiStruct):
        SEQ_FIELDS = ["chunk_id", "len", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['chunk_id']['start'] = self._io.pos()
            self.chunk_id = self._io.read_u4be()
            self._debug['chunk_id']['end'] = self._io.pos()
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u4le()
            self._debug['len']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            _on = self.chunk_id
            if _on == 1684108385:
                self._raw_data = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.DataChunkType(io, self, self._root)
                self.data._read()
            elif _on == 1668637984:
                self._raw_data = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.CueChunkType(io, self, self._root)
                self.data._read()
            elif _on == 1650817140:
                self._raw_data = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.BextChunkType(io, self, self._root)
                self.data._read()
            elif _on == 1718449184:
                self._raw_data = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_data))
                self.data = self._root.FormatChunkType(io, self, self._root)
                self.data._read()
            else:
                self.data = self._io.read_bytes(self.len)
            self._debug['data']['end'] = self._io.pos()


    class BextChunkType(KaitaiStruct):
        SEQ_FIELDS = ["description", "originator", "originator_reference", "origination_date", "origination_time", "time_reference_low", "time_reference_high", "version", "umid", "loudness_value", "loudness_range", "max_true_peak_level", "max_momentary_loudness", "max_short_term_loudness"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['description']['start'] = self._io.pos()
            self.description = (self._io.read_bytes(256)).decode(u"ASCII")
            self._debug['description']['end'] = self._io.pos()
            self._debug['originator']['start'] = self._io.pos()
            self.originator = (self._io.read_bytes(32)).decode(u"ASCII")
            self._debug['originator']['end'] = self._io.pos()
            self._debug['originator_reference']['start'] = self._io.pos()
            self.originator_reference = (self._io.read_bytes(32)).decode(u"ASCII")
            self._debug['originator_reference']['end'] = self._io.pos()
            self._debug['origination_date']['start'] = self._io.pos()
            self.origination_date = (self._io.read_bytes(10)).decode(u"ASCII")
            self._debug['origination_date']['end'] = self._io.pos()
            self._debug['origination_time']['start'] = self._io.pos()
            self.origination_time = (self._io.read_bytes(8)).decode(u"ASCII")
            self._debug['origination_time']['end'] = self._io.pos()
            self._debug['time_reference_low']['start'] = self._io.pos()
            self.time_reference_low = self._io.read_u4le()
            self._debug['time_reference_low']['end'] = self._io.pos()
            self._debug['time_reference_high']['start'] = self._io.pos()
            self.time_reference_high = self._io.read_u4le()
            self._debug['time_reference_high']['end'] = self._io.pos()
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2le()
            self._debug['version']['end'] = self._io.pos()
            self._debug['umid']['start'] = self._io.pos()
            self.umid = self._io.read_bytes(64)
            self._debug['umid']['end'] = self._io.pos()
            self._debug['loudness_value']['start'] = self._io.pos()
            self.loudness_value = self._io.read_u2le()
            self._debug['loudness_value']['end'] = self._io.pos()
            self._debug['loudness_range']['start'] = self._io.pos()
            self.loudness_range = self._io.read_u2le()
            self._debug['loudness_range']['end'] = self._io.pos()
            self._debug['max_true_peak_level']['start'] = self._io.pos()
            self.max_true_peak_level = self._io.read_u2le()
            self._debug['max_true_peak_level']['end'] = self._io.pos()
            self._debug['max_momentary_loudness']['start'] = self._io.pos()
            self.max_momentary_loudness = self._io.read_u2le()
            self._debug['max_momentary_loudness']['end'] = self._io.pos()
            self._debug['max_short_term_loudness']['start'] = self._io.pos()
            self.max_short_term_loudness = self._io.read_u2le()
            self._debug['max_short_term_loudness']['end'] = self._io.pos()


    @property
    def format_chunk(self):
        if hasattr(self, '_m_format_chunk'):
            return self._m_format_chunk if hasattr(self, '_m_format_chunk') else None

        self._m_format_chunk = self.chunks.chunk[0].data
        return self._m_format_chunk if hasattr(self, '_m_format_chunk') else None


