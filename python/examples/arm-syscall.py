#!/usr/bin/env python
"""
	Thanks to @theqlabs from arm.ninja for the nice writeup and idea for this plugin:
	http://arm.ninja/2016/03/08/intro-to-binary-ninja-api/
"""
import sys, binaryninja, time
if len(sys.argv) > 1:
	target = sys.argv[1]
else:
	raise ValueError("Missing argument to binary.")

bv = binaryninja.BinaryViewType["Mach-O"].open(target)
bv.update_analysis_and_wait()

for func in bv.functions:
	for il in func.low_level_il:
		if il.operation == core.LLIL_SYSCALL:
			print "System call address: %x - %d" % (il.address, func.get_reg_value_at_low_level_il_instruction(il.address, bv.platform.system_call_convention.int_arg_regs[0]).value)
