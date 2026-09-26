#pragma once

#include "base/strong_typedef.h"
#include "binaryninjaapi.h"

#include "exarmo/aarch64.h"

#include <stdint.h>
#include <string_view>
#include <vector>

// A system register, identified by its op0:op1:CRn:CRm:op2 encoding. MRS and MSR can only name
// encodings with op0 of 2 or 3, which puts every system register at 0x8000 or above, clear of
// Register's numbers.
using SystemRegister = bn::base::StrongTypedef<uint32_t, struct SystemRegisterTag,
    bn::base::strong_typedef::Ordered, bn::base::strong_typedef::Hashable>;

constexpr uint32_t SYSREG_NONE = 0;
// Every named system register is below 0xFFFC, where the fake registers il.h numbers begin.
constexpr uint32_t SYSREG_END = 0xFFFC;

// The system register an MRS or MSR names. Both number it by the same op0:op1:CRn:CRm:op2.
inline SystemRegister ToSystemRegister(exarmo_aarch64_sysreg sysreg)
{
	return SystemRegister(sysreg.encoding);
}

// The architectural name of a system register, or Apple's name for an encoding ARM leaves
// IMPLEMENTATION DEFINED. Empty for any other number. A register with different names for reading
// and writing reports the name MRS uses.
std::string_view SystemRegisterName(SystemRegister reg);

// Every system register that has a name, architectural or vendor.
const std::vector<SystemRegister>& SystemRegisters();

// The system registers as an enumeration a lifted MRS or MSR takes.
BinaryNinja::Ref<BinaryNinja::Enumeration> SystemRegisterEnumeration();
