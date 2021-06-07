# Copyright (c) 2015-2021 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# from binaryninja import *
from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag
from binaryninja.log import log_error

import struct
import traceback


def crc16(data):
    crc = 0xffff
    for ch in data:
        crc ^= ord(ch)
        for bit in range(0, 8):
            if (crc & 1) == 1:
                crc = (crc >> 1) ^ 0xa001
            else:
                crc >>= 1
    return crc


class DSView(BinaryView):
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    @staticmethod
    def is_valid_for_data(data):
        hdr = data.read(0, 0x160)
        if len(hdr) < 0x160:
            return False
        if struct.unpack("<H", hdr[0x15e:0x160])[0] != crc16(hdr[0:0x15e]):
            return False
        if struct.unpack("<H", hdr[0x15c:0x15e])[0] != crc16(hdr[0xc0:0x15c]):
            return False
        return True

    def init_common(self):
        self.platform = Architecture["armv7"].standalone_platform  # type: ignore
        self.hdr = self.raw.read(0, 0x160)

    def init_arm9(self):
        try:
            self.init_common()
            self.arm9_offset = struct.unpack("<L", self.hdr[0x20:0x24])[0]
            self.arm_entry_addr = struct.unpack("<L", self.hdr[0x24:0x28])[0]
            self.arm9_load_addr = struct.unpack("<L", self.hdr[0x28:0x2C])[0]
            self.arm9_size = struct.unpack("<L", self.hdr[0x2C:0x30])[0]
            self.add_auto_segment(self.arm9_load_addr, self.arm9_size, self.arm9_offset, self.arm9_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_entry_point(Architecture['armv7'].standalone_platform, self.arm_entry_addr)  # type: ignore
            return True
        except:
            log_error(traceback.format_exc())
            return False

    def init_arm7(self):
        try:
            self.init_common()
            self.arm7_offset = struct.unpack("<L", self.hdr[0x30:0x34])[0]
            self.arm_entry_addr = struct.unpack("<L", self.hdr[0x34:0x38])[0]
            self.arm7_load_addr = struct.unpack("<L", self.hdr[0x38:0x3C])[0]
            self.arm7_size = struct.unpack("<L", self.hdr[0x3C:0x40])[0]
            self.add_auto_segment(self.arm7_load_addr, self.arm7_size, self.arm7_offset, self.arm7_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_entry_point(Architecture['armv7'].standalone_platform, self.arm_entry_addr)  # type: ignore
            return True
        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.arm_entry_addr


class DSARM9View(DSView):
    name = "DSARM9"
    long_name = "DS ARM9 ROM"

    def init(self):
        return self.init_arm9()


class DSARM7View(DSView):
    name = "DSARM7"
    long_name = "DS ARM7 ROM"

    def init(self):
        return self.init_arm7()


DSARM9View.register()
DSARM7View.register()
