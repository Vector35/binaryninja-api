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
#
#
# Simple NSF file loader, primarily for analyzing:
# https://scarybeastsecurity.blogspot.com/2016/11/0day-exploit-compromising-linux-desktop.html
#

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.log import log_error, log_info
from binaryninja.types import Symbol
from binaryninja.enums import SymbolType, SegmentFlag

import struct
import traceback


class NSFView(BinaryView):
	name = "NSF"
	long_name = "Nintendo Sound Format"

	def __init__(self, data):
		BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
		self.platform = Architecture["6502"].standalone_platform  # type: ignore

	@staticmethod
	def is_valid_for_data(data):
		hdr = data.read(0, 128)
		if len(hdr) < 128:
			return False
		if hdr[0:5] != "NESM\x1a":
			return False
		song_count = struct.unpack("B", hdr[6])[0]
		if song_count < 1:
			log_info("Appears to be an NSF, but no songs.")
			return False
		return True

	def init(self):
		try:
			hdr = self.parent_view.read(0, 128)
			self.version = int(hdr[5])
			self.song_count = int(hdr[6])
			self.starting_song = int(hdr[7])
			self.load_address = struct.unpack("<H", hdr[8:10])[0]
			self.init_address = struct.unpack("<H", hdr[10:12])[0]
			self.play_address = struct.unpack("<H", hdr[12:14])[0]
			self.song_name = int(hdr[15])
			self.artist_name = int(hdr[46])
			self.copyright_name = int(hdr[78])
			self.play_speed_ntsc = struct.unpack("<H", hdr[110:112])[0]
			self.bank_switching = hdr[112:120]
			self.play_speed_pal = struct.unpack("<H", hdr[120:122])[0]
			self.pal_ntsc_bits = int(hdr[122])
			self.pal = True if (self.pal_ntsc_bits & 1) == 1 else False
			self.ntsc = not self.pal
			if self.pal_ntsc_bits & 2 == 2:
				self.pal = True
				self.ntsc = True
			self.extra_sound_bits = int(hdr[123])

			if self.bank_switching == "\0" * 8:
				# no bank switching
				self.load_address & 0xFFF
				self.rom_offset = 128

			else:
				# bank switching not implemented
				log_info("Bank switching not implemented in this loader.")

			# Add mapping for RAM and hardware registers, not backed by file contents
			self.add_auto_segment(0, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

			# Add ROM mappings
			self.add_auto_segment(0x8000, 0x4000, self.rom_offset, 0x4000,
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.play_address, "_play"))
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.init_address, "_init"))
			self.add_entry_point(self.init_address)
			self.add_function(self.play_address)

			# Hardware registers
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2000, "PPUCTRL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2001, "PPUMASK"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2002, "PPUSTATUS"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2003, "OAMADDR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2004, "OAMDATA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2005, "PPUSCROLL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2006, "PPUADDR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2007, "PPUDATA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4000, "SQ1_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4001, "SQ1_SWEEP"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4002, "SQ1_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4003, "SQ1_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4004, "SQ2_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4005, "SQ2_SWEEP"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4006, "SQ2_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4007, "SQ2_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4008, "TRI_LINEAR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400a, "TRI_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400b, "TRI_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400c, "NOISE_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400e, "NOISE_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400f, "NOISE_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4010, "DMC_FREQ"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4011, "DMC_RAW"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4012, "DMC_START"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4013, "DMC_LEN"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4014, "OAMDMA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4015, "SND_CHN"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4016, "JOY1"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4017, "JOY2"))

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return struct.unpack("<H", self.perform_read(0x0a, 2))[0]


NSFView.register()
