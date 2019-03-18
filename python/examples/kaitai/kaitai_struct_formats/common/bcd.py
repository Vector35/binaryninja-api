from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Bcd(KaitaiStruct):
    """BCD (Binary Coded Decimals) is a common way to encode integer
    numbers in a way that makes human-readable output somewhat
    simpler. In this encoding scheme, every decimal digit is encoded as
    either a single byte (8 bits), or a nibble (half of a byte, 4
    bits). This obviously wastes a lot of bits, but it makes translation
    into human-readable string much easier than traditional
    binary-to-decimal conversion process, which includes lots of
    divisions by 10.
    
    For example, encoding integer 31337 in 8-digit, 8 bits per digit,
    big endian order of digits BCD format yields
    
    ```
    00 00 00 03 01 03 03 07
    ```
    
    Encoding the same integer as 8-digit, 4 bits per digit, little
    endian order BCD format would yield:
    
    ```
    73 31 30 00
    ```
    
    Using this type of encoding in Kaitai Struct is pretty
    straightforward: one calls for this type, specifying desired
    encoding parameters, and gets result using either `as_int` or
    `as_str` attributes.
    """
    SEQ_FIELDS = ["digits"]
    def __init__(self, num_digits, bits_per_digit, is_le, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.num_digits = num_digits
        self.bits_per_digit = bits_per_digit
        self.is_le = is_le
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['digits']['start'] = self._io.pos()
        self.digits = [None] * (self.num_digits)
        for i in range(self.num_digits):
            if not 'arr' in self._debug['digits']:
                self._debug['digits']['arr'] = []
            self._debug['digits']['arr'].append({'start': self._io.pos()})
            _on = self.bits_per_digit
            if _on == 4:
                if not 'arr' in self._debug['digits']:
                    self._debug['digits']['arr'] = []
                self._debug['digits']['arr'].append({'start': self._io.pos()})
                self.digits[i] = self._io.read_bits_int(4)
                self._debug['digits']['arr'][i]['end'] = self._io.pos()
            elif _on == 8:
                if not 'arr' in self._debug['digits']:
                    self._debug['digits']['arr'] = []
                self._debug['digits']['arr'].append({'start': self._io.pos()})
                self.digits[i] = self._io.read_u1()
                self._debug['digits']['arr'][i]['end'] = self._io.pos()
            self._debug['digits']['arr'][i]['end'] = self._io.pos()

        self._debug['digits']['end'] = self._io.pos()

    @property
    def as_int(self):
        """Value of this BCD number as integer. Endianness would be selected based on `is_le` parameter given."""
        if hasattr(self, '_m_as_int'):
            return self._m_as_int if hasattr(self, '_m_as_int') else None

        self._m_as_int = (self.as_int_le if self.is_le else self.as_int_be)
        return self._m_as_int if hasattr(self, '_m_as_int') else None

    @property
    def as_int_le(self):
        """Value of this BCD number as integer (treating digit order as little-endian)."""
        if hasattr(self, '_m_as_int_le'):
            return self._m_as_int_le if hasattr(self, '_m_as_int_le') else None

        self._m_as_int_le = (self.digits[0] + (0 if self.num_digits < 2 else ((self.digits[1] * 10) + (0 if self.num_digits < 3 else ((self.digits[2] * 100) + (0 if self.num_digits < 4 else ((self.digits[3] * 1000) + (0 if self.num_digits < 5 else ((self.digits[4] * 10000) + (0 if self.num_digits < 6 else ((self.digits[5] * 100000) + (0 if self.num_digits < 7 else ((self.digits[6] * 1000000) + (0 if self.num_digits < 8 else (self.digits[7] * 10000000)))))))))))))))
        return self._m_as_int_le if hasattr(self, '_m_as_int_le') else None

    @property
    def last_idx(self):
        """Index of last digit (0-based)."""
        if hasattr(self, '_m_last_idx'):
            return self._m_last_idx if hasattr(self, '_m_last_idx') else None

        self._m_last_idx = (self.num_digits - 1)
        return self._m_last_idx if hasattr(self, '_m_last_idx') else None

    @property
    def as_int_be(self):
        """Value of this BCD number as integer (treating digit order as big-endian)."""
        if hasattr(self, '_m_as_int_be'):
            return self._m_as_int_be if hasattr(self, '_m_as_int_be') else None

        self._m_as_int_be = (self.digits[self.last_idx] + (0 if self.num_digits < 2 else ((self.digits[(self.last_idx - 1)] * 10) + (0 if self.num_digits < 3 else ((self.digits[(self.last_idx - 2)] * 100) + (0 if self.num_digits < 4 else ((self.digits[(self.last_idx - 3)] * 1000) + (0 if self.num_digits < 5 else ((self.digits[(self.last_idx - 4)] * 10000) + (0 if self.num_digits < 6 else ((self.digits[(self.last_idx - 5)] * 100000) + (0 if self.num_digits < 7 else ((self.digits[(self.last_idx - 6)] * 1000000) + (0 if self.num_digits < 8 else (self.digits[(self.last_idx - 7)] * 10000000)))))))))))))))
        return self._m_as_int_be if hasattr(self, '_m_as_int_be') else None


