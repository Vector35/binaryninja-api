from binaryninja.datarender import DataRenderer
from binaryninja.function import DisassemblyTextLine
from binaryninja.enums import TypeClass, HighlightStandardColor
from binaryninja.binaryview import BinaryView
from binaryninja.architecture import InstructionTextToken
from binaryninja.types import Type
from typing import List

import sys
from PySide6.QtGui import QKeySequence
from binaryninjaui import UIActionHandler, UIAction, UIActionContext

class CodeDataRenderer(DataRenderer):
	def __init__(self):
		DataRenderer.__init__(self)
	def perform_is_valid_for_data(self, _, bv: BinaryView, addr: int, type: Type, context: List[str]) -> bool:
		sym = bv.get_symbol_at(addr)
		return sym is not None and sym.name.startswith("CODE_") and type.type_class == TypeClass.ArrayTypeClass
	def perform_get_lines_for_data(self, _, bv: BinaryView, addr: int, type: Type, prefix: List[InstructionTextToken], width: int, context: List[str]) -> List[DisassemblyTextLine]:
		end = addr + len(type)
		result: List[DisassemblyTextLine] = []
		for tokens, size in bv.disassembly_tokens(addr, bv.arch):
			if addr + size > end:
				break
			result.append(DisassemblyTextLine([*tokens], addr, color=HighlightStandardColor.RedHighlightColor))
			addr += size
		return result
	def __del__(self):
		pass

def make_code(bv: BinaryView, start: int, end: int) -> None:
	if bv.get_basic_blocks_at(start):
		return
	if end - start <= 1:
		# find the next basic block, data variable, or segment/section end
		data_var = bv.get_next_data_var_after(start)
		if data_var is not None:
			end = data_var.address
		else:
			end = bv.end
		end = min(bv.get_next_basic_block_start_after(start), end)
		seg = bv.get_segment_at(start)
		if seg is not None:
			end = min(seg.end, end)
		section_ends = [s.end for s in bv.get_sections_at(start)]
		end = min(*section_ends, end)
	bv.define_user_data_var(start, Type.array(Type.int(1, False), end-start), f"CODE_{start:08x}")

def make_code_helper(ctx: UIActionContext):
	make_code(ctx.binaryView, ctx.address, ctx.address + ctx.length)

CodeDataRenderer().register_type_specific()
UIAction.registerAction("Make Code", QKeySequence("C"))
UIActionHandler.globalActions().bindAction("Make Code", UIAction(make_code_helper))
