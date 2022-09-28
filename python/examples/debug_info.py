#!/usr/bin/env python3

# If you're here, you're likely looking for boilerplate code.  Here it is:
# ```
# import binaryninja as bn
#
# def is_valid(bv: bn.binaryview.BinaryView):
#   return bv.view_type == "Raw"
#
# def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView):
#   debug_info.add_type("name", bn.types.Type.int(4, True))
#
#   debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
#   debug_info.add_data_variable(0x4321, bn.types.Type.int(4, True))  # Names are optional
#
#   # Just provide the information you can; we can't create the function without an address, but we'll
#   # figure out what we can and you can query this info later when you have a better idea of things
#   function_info = bn.debuginfo.DebugFunctionInfo(0xdead1337, "short_name", "full_name", "raw_name", bn.types.Type.int(4, False), [])
#   debug_info.add_function(function_info)
#
# bn.debuginfo.DebugInfoParser.register("debug info parser", is_valid, parse_info)
# ```

# If you're interesting in applying debug info to existing BNDBs or otherwise manipulating debug info more directally, consider:
# ```
# valid_parsers = bn.debuginfo.DebugInfoParser.get_parsers_for_view(bv)
# parser = bn.debuginfo.DebugInfoParser[name]
# debug_info = parser.parse_debug_info(bv)
# bv.apply_debug_info(debug_info)
# ```

# The rest of this file serves as a test and example of implementing debug info parsers, and the resultant debug info.
#
# All that is required is to provide functions similar to "is_valid" and "parse_info" below, and call
# `binaryninja.debuginfo.DebugInfoParser.register` with a name for your parser; your parser will be made
# available for all valid binary views, with the ability to parse and apply debug info to existing BNDBs.
#
# For the purposes of this example, the following test program was compiled and the symbol `__elf_interp`
# overwritten to provide some magic for us to key on.  This example should prove sufficient to
# demonstraight the capabilities of a debug info parser; providing function prototypes, local variables,
# data variables, and new types.  It also highlights some limitations of BN at time of writing which
# should be fixed (see github.com/Vector35/binaryninja-api/issues/2399).
# ```
# #include <stdint.h>
# #include <stdbool.h>
#
# struct test_type_1 {
#   int a;
#   char b[4];
#   uint64_t c;
#   bool d;
# } test_var_1;
#
# struct test_type_2 {
#   struct test_type_1 a;
#   struct test_type_1* b;
#   struct test_type_2* c;
# };
#
# int test_var_2 = 0x1232;
# const int test_var_3 = 0x1233;
# static int test_var_4 = 0x1234;
#
# void no_return_type_no_parameters() { }
#
# bool used_parameter(bool value)
# {
#   return !value;
# }
#
# int unused_parameters(bool value_1, int value_2, char* value_3)
# {
#   return 8*16-12/32+7|13;
# }
#
# int used_and_unused_parameters_1(int value_1, int value_2, char* value_3, bool value_4)
# {
#   return value_1 + value_2;
# }
#
# uint8_t used_and_unused_parameters_2(bool value_1, uint8_t value_2, char* value_3, uint8_t value_4, char value_5)
# {
#   return value_2 + value_4;
# }
#
# void local_parameters(bool value_1, uint8_t value_2, char* value_3, uint8_t value_4, char value_5)
# {
#   char local_var_1 = value_1 ? value_3[15] : value_5;
#   uint8_t local_var_2 = value_2 + 25;
# }
#
# int main()
# {
#   int a = 0b01010101;
#   int b = 0b10101010;
#   return ~(a | b | test_var_2);
# }
# ```

import binaryninja as bn
import os

filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_debug_info")

# Some setup code not just for informative printing

print = print
if __name__ != "__main__":
	print = bn.log_error


def pretty_print_add_data_variable(
  debug_info: bn.debuginfo.DebugInfo, address: int, t: bn.types.Type, name: str = None
) -> None:
	print(f"  Adding data variable of type `{t}` at {hex(address)} : {debug_info.add_data_variable(address, t, name)}")


def pretty_print_add_function(
  debug_info: bn.debuginfo.DebugInfo, address: int, short_name: str = None, full_name: str = None, raw_name: str = None,
  return_type=None, parameters=None
) -> None:
	function_info = bn.debuginfo.DebugFunctionInfo(address, short_name, full_name, raw_name, return_type, parameters)
	if parameters is not None:
		print(
		  f"  Adding function `{return_type} {short_name}({', '.join(f'{t} {name}' for name, t in parameters)})` at {hex(address)} : {debug_info.add_function(function_info)}"
		)
	else:
		print(
		  f"  Adding function `{return_type} {short_name}()` at {hex(address)} : {debug_info.add_function(function_info)}"
		)


# The beginning of the actual debug info plugin


def is_valid(bv: bn.binaryview.BinaryView):
	sym = bv.get_symbol_by_raw_name("__elf_interp")
	if sym is None:
		return False
	else:
		var = bv.get_data_var_at(sym.address)
		return b"test_debug_info_parsing" == bv.read(sym.address, var.type.width - 1)


def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView):
	print("Adding types")
	types = []
	for name, t in bv.parse_types_from_string(
	  """
  struct test_type_1 {
    int a;
    char b[4];
    uint64_t c;
    bool d;
  };

  struct test_type_2 {
    struct test_type_1 a;
    struct test_type_1* b;
    struct test_type_2* c;
  };"""
	).types.items():
		print(f"  Adding type \"{name}\" `{t}` : {debug_info.add_type(str(name), t)}")
		types.append(t)

	print("Adding data variables")
	pretty_print_add_data_variable(debug_info, 0x4030, types[0], "test_var_1")
	pretty_print_add_data_variable(debug_info, 0x4010, bn.types.Type.int(4, True), "test_var_2")
	# Names are optional
	pretty_print_add_data_variable(debug_info, 0x4014, bn.types.Type.int(4, True))

	t = bn.types.Type.int(4, True)
	t.const = True
	pretty_print_add_data_variable(debug_info, 0x2004, t, "test_var_3")

	print("Adding functions")
	char_star = bv.parse_type_string("char*")[0]
	pretty_print_add_function(debug_info, 0x1129, "no_return_type_no_parameters", None, None, bn.types.Type.void(), None)
	pretty_print_add_function(
	  debug_info, 0x1134, "used_parameter", None, None, bn.types.Type.bool(), [("value", bn.types.Type.bool())]
	)
	pretty_print_add_function(
	  debug_info, 0x1155, "unused_parameters", None, None, bn.types.Type.int(4, True),
	  [("value_1", bn.types.Type.bool()), ("value_2", bn.types.Type.int(4, True)), ("value_3", char_star)]
	)
	pretty_print_add_function(
	  debug_info, 0x1170, "used_and_unused_parameters_1", None, None, bn.types.Type.int(4, True),
	  [("value_1", bn.types.Type.int(4, True)), ("value_2", bn.types.Type.int(4, True)), ("value_3", char_star),
	   ("value_4", bn.types.Type.bool())]
	)
	pretty_print_add_function(
	  debug_info, 0x1191, "used_and_unused_parameters_2", None, None, bn.types.Type.int(1, False),
	  [("value_1", bn.types.Type.bool()), ("value_2", bn.types.Type.int(1, False)), ("value_3", char_star),
	   ("value_4", bn.types.Type.int(1, False)), ("value_5", bn.types.Type.char())]
	)
	pretty_print_add_function(
	  debug_info, 0x11c0, "local_parameters", None, None, bn.types.Type.void(), [("value_1", bn.types.Type.bool()),
	                                                                             ("value_2", bn.types.Type.int(1, False)),
	                                                                             ("value_3", char_star),
	                                                                             ("value_4", bn.types.Type.int(1, False)),
	                                                                             ("value_5", bn.types.Type.char())]
	)


parser = bn.debuginfo.DebugInfoParser.register("test debug info parser", is_valid, parse_info)
print(f"Registered parser: {parser.name}")

# The above is all that is needed for a DebugInfo plugin
# The below serves to test the correctness of (the Python bindings' implementation of) debug info parsers' functionality.

bn.debuginfo.DebugInfoParser.register("dummy extra debug parser 1", lambda bv: False, lambda di, bv: None)
bn.debuginfo.DebugInfoParser.register(
  "dummy extra debug parser 2", lambda bv: bv.view_type != "Raw", lambda di, bv: None
)

# Test fetching parser list and fetching by name
print(f"Availible parsers: {len(list(bn.debuginfo.DebugInfoParser))}")
for p in bn.debuginfo.DebugInfoParser:
	if p == parser:
		print(f"  {bn.debuginfo.DebugInfoParser[p.name].name} (the one we just registered)")
	else:
		print(f"  {bn.debuginfo.DebugInfoParser[p.name].name}")

# Test calling our `is_valid` callback
bv = bn.open_view(filename, options={"loader.debugInfoInternal": False})
if parser.is_valid_for_view(bv):
	print("Parser is valid")
else:
	print("Parser is NOT valid!")
	quit()

# Test getting list of valid parsers, and DebugInfoParser's repr
print("")
for p in bn.debuginfo.DebugInfoParser.get_parsers_for_view(bv):
	print(f"`{p.name}` is valid for `{bv}`")
print("")

# Test calling our `parse_info` callback
debug_info = parser.parse_debug_info(bv)
# debug_info = bv.debug_info

print("\nEach of the following pairs of prints should be the same\n")

print("All types:")
for name, t in debug_info.types:
	print(f"  \"{name}\": `{t}`")

print("Types from parser:")
for name, t in debug_info.types_from_parser(parser.name):
	print(f"  \"{name}\": `{t}`")

print("")

print("All functions:")
for func in debug_info.functions:
	print(f"  {func}")

print("Functions from parser:")
for func in debug_info.functions_from_parser(parser.name):
	print(f"  {func}")

print("")

print("All data variables:")
for data_var in debug_info.data_variables:
	print(f"  {data_var}")

print("Data variables from parser:")
for data_var in debug_info.data_variables_from_parser(parser.name):
	print(f"  {data_var}")

print("Appling debug info!")
bv.apply_debug_info(debug_info)
bv.update_analysis_and_wait()

# Checking applied debug info
print("")
print("Types:")
for name, t in debug_info.types:
	print(f"  {bv.get_type_by_name(name)}")

print("")

print("Functions:")
for func in debug_info.functions:
	print(f"  {bv.get_function_at(func.address)}")

print("")

print("Data variables:")
for data_var in debug_info.data_variables:
	print(f"  {bv.get_data_var_at(data_var.address)}")
