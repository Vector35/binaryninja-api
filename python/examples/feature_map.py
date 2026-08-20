#!/usr/bin/env python

# headlessly draw the feature map of a given binary

import argparse
import struct

import binaryninja
from binaryninja.enums import SymbolType, StringType
from PIL import Image

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

def main() -> int:
	parser = argparse.ArgumentParser(description="Render Binary Ninja's feature-map data for a binary")
	parser.add_argument("path", help="binary to analyze")
	parser.add_argument("-o", "--output", default="feature-map.png", help="output PNG path")
	args = parser.parse_args()

	with binaryninja.load(args.path, update_analysis=True) as view:
		segments = list(view.segments)
		data_length = sum(segment.end - segment.start for segment in segments)
		if data_length == 0:
			parser.error("the input has no mapped segments")
		factor = (WIDTH * HEIGHT) / data_length
		image_data = [FeatureMapBaseColor] * (WIDTH * HEIGHT)

		def address_to_offset(address):
			mapped_before = 0
			for segment in segments:
				if segment.start <= address < segment.end:
					return min(int(factor * (mapped_before + address - segment.start)), len(image_data) - 1)
				mapped_before += segment.end - segment.start
			raise ValueError(f"address {address:#x} is not in a mapped segment")

		def highlight(start, end, color):
			for offset in range(address_to_offset(start), address_to_offset(end - 1) + 1):
				image_data[offset] = color

		for segment in segments:
			print(
				f"segment [{segment.start:08X}, {segment.end:08X}) -draw-> "
				f"[{address_to_offset(segment.start):08X}, {address_to_offset(segment.end - 1):08X}]"
			)

		for address, variable in view.data_vars.items():
			symbol = view.get_symbol_at(address)
			if symbol and symbol.type in {
				SymbolType.ImportAddressSymbol,
				SymbolType.ImportedFunctionSymbol,
				SymbolType.ImportedDataSymbol,
			}:
				color = FeatureMapImportColor
			elif symbol and symbol.type == SymbolType.ExternalSymbol:
				color = FeatureMapExternColor
			else:
				color = FeatureMapDataVariableColor
			highlight(address, address + len(variable), color)

		for string in view.strings:
			color = FeatureMapAsciiStringColor if string.type == StringType.AsciiString else FeatureMapUnicodeStringColor
			highlight(string.start, string.start + len(string), color)

		for function in view.functions:
			symbol = function.symbol
			if symbol and symbol.type == SymbolType.ImportedFunctionSymbol:
				color = FeatureMapImportColor
			elif symbol and symbol.type == SymbolType.LibraryFunctionSymbol:
				color = FeatureMapLibraryColor
			else:
				color = FeatureMapFunctionColor
			for block in function.basic_blocks:
				highlight(block.start, block.end, color)

	data = b"".join(struct.pack("BBB", *rgb) for rgb in image_data)
	Image.frombytes("RGB", (WIDTH, HEIGHT), data).save(args.output)
	print(f"wrote {args.output}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
