from binaryninja import *
import struct
import traceback
import os

def crc16(data):
    crc = 0xffff
    for ch in data:
        crc ^= ord(ch)
        for bit in xrange(0, 8):
            if (crc & 1) == 1:
                crc = (crc >> 1) ^ 0xa001
            else:
                crc >>= 1
    return crc

class DSView(BinaryView):
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 0x160)
        if len(hdr) < 0x160:
            return False
        if struct.unpack("<H", hdr[0x15e:0x160])[0] != crc16(hdr[0:0x15e]):
            return False
        if struct.unpack("<H", hdr[0x15c:0x15e])[0] != crc16(hdr[0xc0:0x15c]):
            return False
        return True

    def init_common(self):
        self.platform = Architecture["armv7"].standalone_platform
        self.hdr = self.raw.read(0, 0x160)

    def init_arm9(self):
        try:
            self.init_common()
            self.arm9_offset = struct.unpack("<L", self.hdr[0x20:0x24])[0]
            self.arm_entry_addr = struct.unpack("<L", self.hdr[0x24:0x28])[0]
            self.arm9_load_addr = struct.unpack("<L", self.hdr[0x28:0x2C])[0]
            self.arm9_size = struct.unpack("<L", self.hdr[0x2C:0x30])[0]
            self.add_auto_segment(self.arm9_load_addr, self.arm9_size, self.arm9_offset, self.arm9_size,
                SegmentReadable | SegmentExecutable)
            self.add_entry_point(Architecture['armv7'].standalone_platform, self.arm_entry_addr)
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
                SegmentReadable | SegmentExecutable)
            self.add_entry_point(Architecture['armv7'].standalone_platform, self.arm_entry_addr)
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
