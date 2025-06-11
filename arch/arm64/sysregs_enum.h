/* GENERATED FILE - DO NOT MODIFY - SUBMIT GITHUB ISSUE IF PROBLEM FOUND */
#pragma once

#include <stddef.h>

#include "binaryninjaapi.h"
#include "disassembler/sysregs_gen.h"
#include "disassembler/sysregs_fmt_gen.h"

using namespace BinaryNinja;
using namespace std;

Ref<Enumeration> get_system_register_enum();
Ref<Type> get_system_register_enum_type(Ref<BinaryView> view);
QualifiedName get_system_register_enum_type_name(Ref<BinaryView> view);
const vector<uint32_t>& get_system_registers();

