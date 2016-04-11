from binaryninja import *

def write_breakpoint(view, start, length):
	"""Sample function to show registering a plugin menu item for a range of bytes. Also possible:
		register
		register_for_address
		register_for_function
	"""
	if view.arch.name.startswith("x86"):
		view.write(start, "\xcc" * length)
	elif view.arch.name == "armv7":
		view.write(start, "\x7a\x00\x20\xe1" * (length/4))
	else:
		log_error("No support for breakpoint on %s" % view.arch.name)

PluginCommand.register_for_range("Convert to breakpoint", "Fill region with breakpoint instructions.", write_breakpoint)
