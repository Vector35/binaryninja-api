# Copyright (c) 2015-2017 Vector 35 LLC
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

# This plugin will attempt to resolve simple jump tables (an array of code pointers) and add the destinations
# as indirect branch targets so that the flow graph reflects the jump table's control flow.
from binaryninja.plugin import PluginCommand
from binaryninja.enums import InstructionTextTokenType
import struct


def find_jump_table(bv, addr):
	for block in bv.get_basic_blocks_at(addr):
		func = block.function
		arch = func.arch
		addrsize = arch.address_size

		# Grab the instruction tokens so that we can look for the table's starting address
		tokens, length = arch.get_instruction_text(bv.read(addr, 16), addr)

		# Look for the next jump instruction, which may be the current instruction. Some jump tables will
		# compute the address first then jump to the computed address as a separate instruction.
		jump_addr = addr
		while jump_addr < block.end:
			info = arch.get_instruction_info(bv.read(jump_addr, 16), jump_addr)
			if len(info.branches) != 0:
				break
			jump_addr += info.length
		if jump_addr >= block.end:
			print "Unable to find jump after instruction 0x%x" % addr
			continue
		print "Jump at 0x%x" % jump_addr

		# Collect the branch targets for any tables referenced by the clicked instruction
		branches = []
		for token in tokens:
			if InstructionTextTokenType(token.type) == InstructionTextTokenType.PossibleAddressToken:  # Table addresses will be a "possible address" token
				tbl = token.value
				print "Found possible table at 0x%x" % tbl
				i = 0
				while True:
					# Read the next pointer from the table
					data = bv.read(tbl + (i * addrsize), addrsize)
					if len(data) == addrsize:
						if addrsize == 4:
							ptr = struct.unpack("<I", data)[0]
						else:
							ptr = struct.unpack("<Q", data)[0]

						# If the pointer is within the binary, add it as a destination and continue
						# to the next entry
						if (ptr >= bv.start) and (ptr < bv.end):
							print "Found destination 0x%x" % ptr
							branches.append((arch, ptr))
						else:
							# Once a value that is not a pointer is encountered, the jump table is ended
							break
					else:
						# Reading invalid memory
						break

					i += 1

		# Set the indirect branch targets on the jump instruction to be the list of targets discovered
		func.set_user_indirect_branches(jump_addr, branches)


# Create a plugin command so that the user can right click on an instruction referencing a jump table and
# invoke the command
PluginCommand.register_for_address("Process jump table", "Look for jump table destinations", find_jump_table)
