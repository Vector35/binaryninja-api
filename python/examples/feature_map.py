#!/usr/bin/env python

# headlessly draw the feature map of a given binary

import os, sys, binaryninja
from binaryninja.enums import SymbolType, StringType

WIDTH, HEIGHT = 100, 800

FeatureMapBaseColor = (16, 16, 16)
FeatureMapNavLineColor = (16, 16, 16)
FeatureMapNavHighlightColor = (237, 223, 179)
FeatureMapDataVariableColor = (144, 144, 144)
FeatureMapAsciiStringColor = (162, 217, 175)
FeatureMapUnicodeStringColor = (222, 143, 151)
FeatureMapFunctionColor = (128, 198, 233)
FeatureMapImportColor = (237, 189, 129)
FeatureMapExternColor = (237, 189, 129)
FeatureMapLibraryColor = (237, 189, 129)

bv = binaryninja.open_view(sys.argv[1], update_analysis=True)

imgdata = [FeatureMapBaseColor]*(WIDTH*HEIGHT)

data_len = sum([s.end - s.start for s in bv.segments])
image_len = WIDTH*HEIGHT
factor = image_len / data_len

def addr_to_fmap_offset(addr):
	for (i,seg) in enumerate(bv.segments):
		#print(f'segment {i}: [{seg.start:08X}, {seg.end:08X})')
		if addr >= seg.start and addr < seg.end:
			a = sum([s.end - s.start for s in bv.segments[0:i]]) + (addr - seg.start)
			return int(factor * a)
	assert False, f'address {addr:08X} was not in any segment'

for seg in bv.segments:
	print(f'segment [{seg.start:08X}, {seg.end:08X}) -draw-> ' + \
		f'[{addr_to_fmap_offset(seg.start):08X}, {addr_to_fmap_offset(seg.end-1):08X}]')

def highlight(a0, a1, color):
	for i in range(addr_to_fmap_offset(a0), addr_to_fmap_offset(a1)):
		imgdata[i] = color

# data variables
for (addr, var) in bv.data_vars.items():
	sym = bv.get_symbol_at(addr)
	if sym and sym.type in [SymbolType.ImportAddressSymbol, SymbolType.ImportedFunctionSymbol, SymbolType.ImportedDataSymbol]:
		color = FeatureMapImportColor
	elif sym and sym.type in [SymbolType.ExternalSymbol]:
		color = FeatureMapExternColor
	else:
		color = FeatureMapDataVariableColor
	highlight(addr, addr + len(var), color)

# strings
for s in bv.strings:
	color = FeatureMapAsciiStringColor if s.type == StringType.AsciiString else FeatureMapUnicodeStringColor
	highlight(s.start, s.start + len(s), color)

# functions
for f in bv.functions:
	sym = f.symbol
	if sym and sym.type == SymbolType.ImportedFunctionSymbol:
		color = FeatureMapImportColor
	elif sym and sym.type == SymbolType.LibraryFunctionSymbol:
		color = FeatureMapLibraryColor
	else:
		color = FeatureMapFunctionColor

	for bb in f.basic_blocks:
		highlight(bb.start, bb.end, color)

# export image
import struct
from PIL import Image
data = b''.join([struct.pack('BBB', *rgb) for rgb in imgdata])
Image.frombytes('RGB', (WIDTH,HEIGHT), data).save('feature-map.png')
