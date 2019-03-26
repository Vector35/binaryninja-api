# Copyright (c) 2019 Vector 35 Inc
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

from binaryninja.function import DisassemblyTextRenderer, DisassemblyTextLine
from binaryninja.lineardisassembly import LinearDisassemblyLine
from binaryninja.enums import LinearDisassemblyLineType, DisassemblyOption
from binaryninjaui import TokenizedTextView, TokenizedTextViewHistoryEntry, ViewType


class LinearMLILView(TokenizedTextView):
	def __init__(self, parent, data):
		super(LinearMLILView, self).__init__(parent, data)
		self.data = data
		self.function = data.entry_function
		if self.function is not None:
			self.setFunction(self.function)
			self.updateLines()

	def generateLines(self):
		if self.function is None:
			return []

		il = self.function.mlil

		# Set up IL display options
		renderer = DisassemblyTextRenderer(il)
		renderer.settings.set_option(DisassemblyOption.ShowAddress)
		renderer.settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)

		# Sort basic blocks by IL instruction index
		blocks = il.basic_blocks
		blocks.sort(key = lambda block: block.start)

		# Function header
		result = []
		result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderStartLineType,
			self.function, None, 0, DisassemblyTextLine([], self.function.start)))
		result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderLineType,
			self.function, None, 0, DisassemblyTextLine(self.function.type_tokens, self.function.start)))
		result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderEndLineType,
			self.function, None, 0, DisassemblyTextLine([], self.function.start)))

		# Display IL instructions in order
		lastAddr = self.function.start
		lastBlock = None
		lineIndex = 0
		for block in il:
			if lastBlock is not None:
				# Blank line between basic blocks
				result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
					self.function, block, 0, DisassemblyTextLine([], lastAddr)))
			for i in block:
				lines, length = renderer.get_disassembly_text(i.instr_index)
				lastAddr = i.address
				lineIndex = 0
				for line in lines:
					result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
						self.function, block, lineIndex, line))
					lineIndex += 1
			lastBlock = block

		result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionEndLineType,
			self.function, lastBlock, lineIndex, DisassemblyTextLine([], lastAddr)))

		return result

	def updateLines(self):
		self.setUpdatedLines(self.generateLines())

	def navigate(self, addr):
		# Find correct function based on most recent use
		block = self.data.get_recent_basic_block_at(addr)
		if block is None:
			# If function isn't done analyzing yet, it may have a function start but no basic blocks
			func = self.data.get_recent_function_at(addr)
		else:
			func = block.function

		if func is None:
			# No function contains this address, fail navigation in this view
			return False

		self.function = func
		self.setFunction(self.function)
		self.setLines(self.generateLines())
		return True

	def getHistoryEntry(self):
		class LinearMLILHistoryEntry(TokenizedTextViewHistoryEntry):
			def __init__(self, function):
				super(LinearMLILHistoryEntry, self).__init__()
				self.function = function

		result = LinearMLILHistoryEntry(self.function)
		self.populateDefaultHistoryEntry(result)
		return result

	def navigateToHistoryEntry(self, entry):
		if hasattr(entry, 'function'):
			self.function = entry.function
			self.setFunction(self.function)
			self.updateLines()
		super(LinearMLILView, self).navigateToHistoryEntry(entry)


# View type for the new view
class LinearMLILViewType(ViewType):
	def __init__(self):
		super(LinearMLILViewType, self).__init__("Linear MLIL", "Linear MLIL")

	def getPriority(self, data, filename):
		if data.executable:
			# Use low priority so that this view is not picked by default
			return 1
		return 0

	def create(self, data, view_frame):
		return LinearMLILView(view_frame, data)


# Register the view type so that it can be chosen by the user
ViewType.registerViewType(LinearMLILViewType())
