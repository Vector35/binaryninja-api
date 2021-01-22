import binaryninja as bn


# This should return a boolean based on whether the given binary view contains valid debug info for your plugin
def is_valid(bv: bn.BinaryView) -> bool:
  return True


# Given the binary view, do whatever parsing you need to do and populate the provided debug_info object
def parse_info(debug_info: bn.DebugInfo, bv: bn.BinaryView) -> None:
  # TODO : Expand this example

  # At time of writing you can only add functions and types, as so:

  int_type = bn.Type.int(4)
  debug_info.add_type(int_type)

  return_type = None
  debug_info.add_function(bn.DebugFunctionInfo("short_name", "full_name", "raw_name", 0xadd2e55, return_type, [("arg_1", int_type)]))
