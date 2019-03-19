# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MifareClassic(KaitaiStruct):
    """You can get a dump for testing by the link: https://github.com/zhovner/mfdread/raw/master/dump.mfd
    
    .. seealso::
       Source - https://github.com/nfc-tools/libnfc
       https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf
    """
    SEQ_FIELDS = ["sectors"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['sectors']['start'] = self._io.pos()
        self._raw_sectors = []
        self.sectors = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['sectors']:
                self._debug['sectors']['arr'] = []
            self._debug['sectors']['arr'].append({'start': self._io.pos()})
            self._raw_sectors.append(self._io.read_bytes((((4 if i >= 32 else 1) * 4) * 16)))
            io = KaitaiStream(BytesIO(self._raw_sectors[-1]))
            _t_sectors = self._root.Sector(i == 0, io, self, self._root)
            _t_sectors._read()
            self.sectors.append(_t_sectors)
            self._debug['sectors']['arr'][len(self.sectors) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['sectors']['end'] = self._io.pos()

    class Key(KaitaiStruct):
        SEQ_FIELDS = ["key"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['key']['start'] = self._io.pos()
            self.key = self._io.read_bytes(6)
            self._debug['key']['end'] = self._io.pos()


    class Sector(KaitaiStruct):
        SEQ_FIELDS = ["manufacturer", "data_filler", "trailer"]
        def __init__(self, has_manufacturer, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.has_manufacturer = has_manufacturer
            self._debug = collections.defaultdict(dict)

        def _read(self):
            if self.has_manufacturer:
                self._debug['manufacturer']['start'] = self._io.pos()
                self.manufacturer = self._root.Manufacturer(self._io, self, self._root)
                self.manufacturer._read()
                self._debug['manufacturer']['end'] = self._io.pos()

            self._debug['data_filler']['start'] = self._io.pos()
            self._raw_data_filler = self._io.read_bytes(((self._io.size() - self._io.pos()) - 16))
            io = KaitaiStream(BytesIO(self._raw_data_filler))
            self.data_filler = self._root.Sector.Filler(io, self, self._root)
            self.data_filler._read()
            self._debug['data_filler']['end'] = self._io.pos()
            self._debug['trailer']['start'] = self._io.pos()
            self.trailer = self._root.Trailer(self._io, self, self._root)
            self.trailer._read()
            self._debug['trailer']['end'] = self._io.pos()

        class Values(KaitaiStruct):
            SEQ_FIELDS = ["values"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['values']['start'] = self._io.pos()
                self.values = []
                i = 0
                while not self._io.is_eof():
                    if not 'arr' in self._debug['values']:
                        self._debug['values']['arr'] = []
                    self._debug['values']['arr'].append({'start': self._io.pos()})
                    _t_values = self._root.Sector.Values.ValueBlock(self._io, self, self._root)
                    _t_values._read()
                    self.values.append(_t_values)
                    self._debug['values']['arr'][len(self.values) - 1]['end'] = self._io.pos()
                    i += 1

                self._debug['values']['end'] = self._io.pos()

            class ValueBlock(KaitaiStruct):
                SEQ_FIELDS = ["valuez", "addrz"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['valuez']['start'] = self._io.pos()
                    self.valuez = [None] * (3)
                    for i in range(3):
                        if not 'arr' in self._debug['valuez']:
                            self._debug['valuez']['arr'] = []
                        self._debug['valuez']['arr'].append({'start': self._io.pos()})
                        self.valuez[i] = self._io.read_u4le()
                        self._debug['valuez']['arr'][i]['end'] = self._io.pos()

                    self._debug['valuez']['end'] = self._io.pos()
                    self._debug['addrz']['start'] = self._io.pos()
                    self.addrz = [None] * (4)
                    for i in range(4):
                        if not 'arr' in self._debug['addrz']:
                            self._debug['addrz']['arr'] = []
                        self._debug['addrz']['arr'].append({'start': self._io.pos()})
                        self.addrz[i] = self._io.read_u1()
                        self._debug['addrz']['arr'][i]['end'] = self._io.pos()

                    self._debug['addrz']['end'] = self._io.pos()

                @property
                def addr(self):
                    if hasattr(self, '_m_addr'):
                        return self._m_addr if hasattr(self, '_m_addr') else None

                    if self.valid:
                        self._m_addr = self.addrz[0]

                    return self._m_addr if hasattr(self, '_m_addr') else None

                @property
                def addr_valid(self):
                    if hasattr(self, '_m_addr_valid'):
                        return self._m_addr_valid if hasattr(self, '_m_addr_valid') else None

                    self._m_addr_valid =  ((self.addrz[0] == ~(self.addrz[1])) and (self.addrz[0] == self.addrz[2]) and (self.addrz[1] == self.addrz[3])) 
                    return self._m_addr_valid if hasattr(self, '_m_addr_valid') else None

                @property
                def valid(self):
                    if hasattr(self, '_m_valid'):
                        return self._m_valid if hasattr(self, '_m_valid') else None

                    self._m_valid =  ((self.value_valid) and (self.addr_valid)) 
                    return self._m_valid if hasattr(self, '_m_valid') else None

                @property
                def value_valid(self):
                    if hasattr(self, '_m_value_valid'):
                        return self._m_value_valid if hasattr(self, '_m_value_valid') else None

                    self._m_value_valid =  ((self.valuez[0] == ~(self.valuez[1])) and (self.valuez[0] == self.valuez[2])) 
                    return self._m_value_valid if hasattr(self, '_m_value_valid') else None

                @property
                def value(self):
                    if hasattr(self, '_m_value'):
                        return self._m_value if hasattr(self, '_m_value') else None

                    if self.valid:
                        self._m_value = self.valuez[0]

                    return self._m_value if hasattr(self, '_m_value') else None



        class Filler(KaitaiStruct):
            """only to create _io."""
            SEQ_FIELDS = ["data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['data']['start'] = self._io.pos()
                self.data = self._io.read_bytes(self._io.size())
                self._debug['data']['end'] = self._io.pos()


        @property
        def block_size(self):
            if hasattr(self, '_m_block_size'):
                return self._m_block_size if hasattr(self, '_m_block_size') else None

            self._m_block_size = 16
            return self._m_block_size if hasattr(self, '_m_block_size') else None

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            self._m_data = self.data_filler.data
            return self._m_data if hasattr(self, '_m_data') else None

        @property
        def blocks(self):
            if hasattr(self, '_m_blocks'):
                return self._m_blocks if hasattr(self, '_m_blocks') else None

            io = self.data_filler._io
            _pos = io.pos()
            io.seek(0)
            self._debug['_m_blocks']['start'] = io.pos()
            self._m_blocks = []
            i = 0
            while not io.is_eof():
                if not 'arr' in self._debug['_m_blocks']:
                    self._debug['_m_blocks']['arr'] = []
                self._debug['_m_blocks']['arr'].append({'start': io.pos()})
                self._m_blocks.append(io.read_bytes(self.block_size))
                self._debug['_m_blocks']['arr'][len(self._m_blocks) - 1]['end'] = io.pos()
                i += 1

            self._debug['_m_blocks']['end'] = io.pos()
            io.seek(_pos)
            return self._m_blocks if hasattr(self, '_m_blocks') else None

        @property
        def values(self):
            if hasattr(self, '_m_values'):
                return self._m_values if hasattr(self, '_m_values') else None

            io = self.data_filler._io
            _pos = io.pos()
            io.seek(0)
            self._debug['_m_values']['start'] = io.pos()
            self._m_values = self._root.Sector.Values(io, self, self._root)
            self._m_values._read()
            self._debug['_m_values']['end'] = io.pos()
            io.seek(_pos)
            return self._m_values if hasattr(self, '_m_values') else None


    class Manufacturer(KaitaiStruct):
        SEQ_FIELDS = ["nuid", "bcc", "sak", "atqa", "manufacturer"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['nuid']['start'] = self._io.pos()
            self.nuid = self._io.read_u4le()
            self._debug['nuid']['end'] = self._io.pos()
            self._debug['bcc']['start'] = self._io.pos()
            self.bcc = self._io.read_u1()
            self._debug['bcc']['end'] = self._io.pos()
            self._debug['sak']['start'] = self._io.pos()
            self.sak = self._io.read_u1()
            self._debug['sak']['end'] = self._io.pos()
            self._debug['atqa']['start'] = self._io.pos()
            self.atqa = self._io.read_u2le()
            self._debug['atqa']['end'] = self._io.pos()
            self._debug['manufacturer']['start'] = self._io.pos()
            self.manufacturer = self._io.read_bytes(8)
            self._debug['manufacturer']['end'] = self._io.pos()


    class Trailer(KaitaiStruct):
        SEQ_FIELDS = ["key_a", "access_bits", "user_byte", "key_b"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['key_a']['start'] = self._io.pos()
            self.key_a = self._root.Key(self._io, self, self._root)
            self.key_a._read()
            self._debug['key_a']['end'] = self._io.pos()
            self._debug['access_bits']['start'] = self._io.pos()
            self._raw_access_bits = self._io.read_bytes(3)
            io = KaitaiStream(BytesIO(self._raw_access_bits))
            self.access_bits = self._root.Trailer.AccessConditions(io, self, self._root)
            self.access_bits._read()
            self._debug['access_bits']['end'] = self._io.pos()
            self._debug['user_byte']['start'] = self._io.pos()
            self.user_byte = self._io.read_u1()
            self._debug['user_byte']['end'] = self._io.pos()
            self._debug['key_b']['start'] = self._io.pos()
            self.key_b = self._root.Key(self._io, self, self._root)
            self.key_b._read()
            self._debug['key_b']['end'] = self._io.pos()

        class AccessConditions(KaitaiStruct):
            SEQ_FIELDS = ["raw_chunks"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['raw_chunks']['start'] = self._io.pos()
                self.raw_chunks = [None] * (self._parent.ac_count_of_chunks)
                for i in range(self._parent.ac_count_of_chunks):
                    if not 'arr' in self._debug['raw_chunks']:
                        self._debug['raw_chunks']['arr'] = []
                    self._debug['raw_chunks']['arr'].append({'start': self._io.pos()})
                    self.raw_chunks[i] = self._io.read_bits_int(4)
                    self._debug['raw_chunks']['arr'][i]['end'] = self._io.pos()

                self._debug['raw_chunks']['end'] = self._io.pos()

            class TrailerAc(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, ac, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.ac = ac
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                @property
                def can_read_key_b(self):
                    """key A is required."""
                    if hasattr(self, '_m_can_read_key_b'):
                        return self._m_can_read_key_b if hasattr(self, '_m_can_read_key_b') else None

                    self._m_can_read_key_b = self.ac.inv_shift_val <= 2
                    return self._m_can_read_key_b if hasattr(self, '_m_can_read_key_b') else None

                @property
                def can_write_keys(self):
                    if hasattr(self, '_m_can_write_keys'):
                        return self._m_can_write_keys if hasattr(self, '_m_can_write_keys') else None

                    self._m_can_write_keys =  ((((self.ac.inv_shift_val + 1) % 3) != 0) and (self.ac.inv_shift_val < 6)) 
                    return self._m_can_write_keys if hasattr(self, '_m_can_write_keys') else None

                @property
                def can_write_access_bits(self):
                    if hasattr(self, '_m_can_write_access_bits'):
                        return self._m_can_write_access_bits if hasattr(self, '_m_can_write_access_bits') else None

                    self._m_can_write_access_bits = self.ac.bits[2].b
                    return self._m_can_write_access_bits if hasattr(self, '_m_can_write_access_bits') else None

                @property
                def key_b_controls_write(self):
                    if hasattr(self, '_m_key_b_controls_write'):
                        return self._m_key_b_controls_write if hasattr(self, '_m_key_b_controls_write') else None

                    self._m_key_b_controls_write = not (self.can_read_key_b)
                    return self._m_key_b_controls_write if hasattr(self, '_m_key_b_controls_write') else None


            class ChunkBitRemap(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, bit_no, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.bit_no = bit_no
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                @property
                def shift_value(self):
                    if hasattr(self, '_m_shift_value'):
                        return self._m_shift_value if hasattr(self, '_m_shift_value') else None

                    self._m_shift_value = (-1 if self.bit_no == 1 else 1)
                    return self._m_shift_value if hasattr(self, '_m_shift_value') else None

                @property
                def chunk_no(self):
                    if hasattr(self, '_m_chunk_no'):
                        return self._m_chunk_no if hasattr(self, '_m_chunk_no') else None

                    self._m_chunk_no = (((self.inv_chunk_no + self.shift_value) + self._parent._parent.ac_count_of_chunks) % self._parent._parent.ac_count_of_chunks)
                    return self._m_chunk_no if hasattr(self, '_m_chunk_no') else None

                @property
                def inv_chunk_no(self):
                    if hasattr(self, '_m_inv_chunk_no'):
                        return self._m_inv_chunk_no if hasattr(self, '_m_inv_chunk_no') else None

                    self._m_inv_chunk_no = (self.bit_no + self.shift_value)
                    return self._m_inv_chunk_no if hasattr(self, '_m_inv_chunk_no') else None


            class DataAc(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, ac, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.ac = ac
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                @property
                def read_key_a_required(self):
                    if hasattr(self, '_m_read_key_a_required'):
                        return self._m_read_key_a_required if hasattr(self, '_m_read_key_a_required') else None

                    self._m_read_key_a_required = self.ac.val <= 4
                    return self._m_read_key_a_required if hasattr(self, '_m_read_key_a_required') else None

                @property
                def write_key_b_required(self):
                    if hasattr(self, '_m_write_key_b_required'):
                        return self._m_write_key_b_required if hasattr(self, '_m_write_key_b_required') else None

                    self._m_write_key_b_required =  (( ((not (self.read_key_a_required)) or (self.read_key_b_required)) ) and (not (self.ac.bits[0].b))) 
                    return self._m_write_key_b_required if hasattr(self, '_m_write_key_b_required') else None

                @property
                def write_key_a_required(self):
                    if hasattr(self, '_m_write_key_a_required'):
                        return self._m_write_key_a_required if hasattr(self, '_m_write_key_a_required') else None

                    self._m_write_key_a_required = self.ac.val == 0
                    return self._m_write_key_a_required if hasattr(self, '_m_write_key_a_required') else None

                @property
                def read_key_b_required(self):
                    if hasattr(self, '_m_read_key_b_required'):
                        return self._m_read_key_b_required if hasattr(self, '_m_read_key_b_required') else None

                    self._m_read_key_b_required = self.ac.val <= 6
                    return self._m_read_key_b_required if hasattr(self, '_m_read_key_b_required') else None

                @property
                def decrement_available(self):
                    if hasattr(self, '_m_decrement_available'):
                        return self._m_decrement_available if hasattr(self, '_m_decrement_available') else None

                    self._m_decrement_available =  (( ((self.ac.bits[1].b) or (not (self.ac.bits[0].b))) ) and (not (self.ac.bits[2].b))) 
                    return self._m_decrement_available if hasattr(self, '_m_decrement_available') else None

                @property
                def increment_available(self):
                    if hasattr(self, '_m_increment_available'):
                        return self._m_increment_available if hasattr(self, '_m_increment_available') else None

                    self._m_increment_available =  (( ((not (self.ac.bits[0].b)) and (not (self.read_key_a_required)) and (not (self.read_key_b_required))) ) or ( ((not (self.ac.bits[0].b)) and (self.read_key_a_required) and (self.read_key_b_required)) )) 
                    return self._m_increment_available if hasattr(self, '_m_increment_available') else None


            class Ac(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, index, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.index = index
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                class AcBit(KaitaiStruct):
                    SEQ_FIELDS = []
                    def __init__(self, i, chunk, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self.i = i
                        self.chunk = chunk
                        self._debug = collections.defaultdict(dict)

                    def _read(self):
                        pass

                    @property
                    def n(self):
                        if hasattr(self, '_m_n'):
                            return self._m_n if hasattr(self, '_m_n') else None

                        self._m_n = ((self.chunk >> self.i) & 1)
                        return self._m_n if hasattr(self, '_m_n') else None

                    @property
                    def b(self):
                        if hasattr(self, '_m_b'):
                            return self._m_b if hasattr(self, '_m_b') else None

                        self._m_b = self.n == 1
                        return self._m_b if hasattr(self, '_m_b') else None


                @property
                def bits(self):
                    if hasattr(self, '_m_bits'):
                        return self._m_bits if hasattr(self, '_m_bits') else None

                    _pos = self._io.pos()
                    self._io.seek(0)
                    self._debug['_m_bits']['start'] = self._io.pos()
                    self._m_bits = [None] * (self._parent._parent.ac_bits)
                    for i in range(self._parent._parent.ac_bits):
                        if not 'arr' in self._debug['_m_bits']:
                            self._debug['_m_bits']['arr'] = []
                        self._debug['_m_bits']['arr'].append({'start': self._io.pos()})
                        _t__m_bits = self._root.Trailer.AccessConditions.Ac.AcBit(self.index, self._parent.chunks[i].chunk, self._io, self, self._root)
                        _t__m_bits._read()
                        self._m_bits[i] = _t__m_bits
                        self._debug['_m_bits']['arr'][i]['end'] = self._io.pos()

                    self._debug['_m_bits']['end'] = self._io.pos()
                    self._io.seek(_pos)
                    return self._m_bits if hasattr(self, '_m_bits') else None

                @property
                def val(self):
                    """c3 c2 c1."""
                    if hasattr(self, '_m_val'):
                        return self._m_val if hasattr(self, '_m_val') else None

                    self._m_val = (((self.bits[2].n << 2) | (self.bits[1].n << 1)) | self.bits[0].n)
                    return self._m_val if hasattr(self, '_m_val') else None

                @property
                def inv_shift_val(self):
                    if hasattr(self, '_m_inv_shift_val'):
                        return self._m_inv_shift_val if hasattr(self, '_m_inv_shift_val') else None

                    self._m_inv_shift_val = (((self.bits[0].n << 2) | (self.bits[1].n << 1)) | self.bits[2].n)
                    return self._m_inv_shift_val if hasattr(self, '_m_inv_shift_val') else None


            class ValidChunk(KaitaiStruct):
                SEQ_FIELDS = []
                def __init__(self, inv_chunk, chunk, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.inv_chunk = inv_chunk
                    self.chunk = chunk
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    pass

                @property
                def valid(self):
                    if hasattr(self, '_m_valid'):
                        return self._m_valid if hasattr(self, '_m_valid') else None

                    self._m_valid = (self.inv_chunk ^ self.chunk) == 15
                    return self._m_valid if hasattr(self, '_m_valid') else None


            @property
            def data_acs(self):
                if hasattr(self, '_m_data_acs'):
                    return self._m_data_acs if hasattr(self, '_m_data_acs') else None

                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_data_acs']['start'] = self._io.pos()
                self._m_data_acs = [None] * ((self._parent.acs_in_sector - 1))
                for i in range((self._parent.acs_in_sector - 1)):
                    if not 'arr' in self._debug['_m_data_acs']:
                        self._debug['_m_data_acs']['arr'] = []
                    self._debug['_m_data_acs']['arr'].append({'start': self._io.pos()})
                    _t__m_data_acs = self._root.Trailer.AccessConditions.DataAc(self.acs_raw[i], self._io, self, self._root)
                    _t__m_data_acs._read()
                    self._m_data_acs[i] = _t__m_data_acs
                    self._debug['_m_data_acs']['arr'][i]['end'] = self._io.pos()

                self._debug['_m_data_acs']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_data_acs if hasattr(self, '_m_data_acs') else None

            @property
            def remaps(self):
                if hasattr(self, '_m_remaps'):
                    return self._m_remaps if hasattr(self, '_m_remaps') else None

                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_remaps']['start'] = self._io.pos()
                self._m_remaps = [None] * (self._parent.ac_bits)
                for i in range(self._parent.ac_bits):
                    if not 'arr' in self._debug['_m_remaps']:
                        self._debug['_m_remaps']['arr'] = []
                    self._debug['_m_remaps']['arr'].append({'start': self._io.pos()})
                    _t__m_remaps = self._root.Trailer.AccessConditions.ChunkBitRemap(i, self._io, self, self._root)
                    _t__m_remaps._read()
                    self._m_remaps[i] = _t__m_remaps
                    self._debug['_m_remaps']['arr'][i]['end'] = self._io.pos()

                self._debug['_m_remaps']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_remaps if hasattr(self, '_m_remaps') else None

            @property
            def acs_raw(self):
                if hasattr(self, '_m_acs_raw'):
                    return self._m_acs_raw if hasattr(self, '_m_acs_raw') else None

                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_acs_raw']['start'] = self._io.pos()
                self._m_acs_raw = [None] * (self._parent.acs_in_sector)
                for i in range(self._parent.acs_in_sector):
                    if not 'arr' in self._debug['_m_acs_raw']:
                        self._debug['_m_acs_raw']['arr'] = []
                    self._debug['_m_acs_raw']['arr'].append({'start': self._io.pos()})
                    _t__m_acs_raw = self._root.Trailer.AccessConditions.Ac(i, self._io, self, self._root)
                    _t__m_acs_raw._read()
                    self._m_acs_raw[i] = _t__m_acs_raw
                    self._debug['_m_acs_raw']['arr'][i]['end'] = self._io.pos()

                self._debug['_m_acs_raw']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_acs_raw if hasattr(self, '_m_acs_raw') else None

            @property
            def trailer_ac(self):
                if hasattr(self, '_m_trailer_ac'):
                    return self._m_trailer_ac if hasattr(self, '_m_trailer_ac') else None

                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_trailer_ac']['start'] = self._io.pos()
                self._m_trailer_ac = self._root.Trailer.AccessConditions.TrailerAc(self.acs_raw[(self._parent.acs_in_sector - 1)], self._io, self, self._root)
                self._m_trailer_ac._read()
                self._debug['_m_trailer_ac']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_trailer_ac if hasattr(self, '_m_trailer_ac') else None

            @property
            def chunks(self):
                if hasattr(self, '_m_chunks'):
                    return self._m_chunks if hasattr(self, '_m_chunks') else None

                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_chunks']['start'] = self._io.pos()
                self._m_chunks = [None] * (self._parent.ac_bits)
                for i in range(self._parent.ac_bits):
                    if not 'arr' in self._debug['_m_chunks']:
                        self._debug['_m_chunks']['arr'] = []
                    self._debug['_m_chunks']['arr'].append({'start': self._io.pos()})
                    _t__m_chunks = self._root.Trailer.AccessConditions.ValidChunk(self.raw_chunks[self.remaps[i].inv_chunk_no], self.raw_chunks[self.remaps[i].chunk_no], self._io, self, self._root)
                    _t__m_chunks._read()
                    self._m_chunks[i] = _t__m_chunks
                    self._debug['_m_chunks']['arr'][i]['end'] = self._io.pos()

                self._debug['_m_chunks']['end'] = self._io.pos()
                self._io.seek(_pos)
                return self._m_chunks if hasattr(self, '_m_chunks') else None


        @property
        def ac_bits(self):
            if hasattr(self, '_m_ac_bits'):
                return self._m_ac_bits if hasattr(self, '_m_ac_bits') else None

            self._m_ac_bits = 3
            return self._m_ac_bits if hasattr(self, '_m_ac_bits') else None

        @property
        def acs_in_sector(self):
            if hasattr(self, '_m_acs_in_sector'):
                return self._m_acs_in_sector if hasattr(self, '_m_acs_in_sector') else None

            self._m_acs_in_sector = 4
            return self._m_acs_in_sector if hasattr(self, '_m_acs_in_sector') else None

        @property
        def ac_count_of_chunks(self):
            if hasattr(self, '_m_ac_count_of_chunks'):
                return self._m_ac_count_of_chunks if hasattr(self, '_m_ac_count_of_chunks') else None

            self._m_ac_count_of_chunks = (self.ac_bits * 2)
            return self._m_ac_count_of_chunks if hasattr(self, '_m_ac_count_of_chunks') else None



