#include "system_registers.h"

#include "apple_vendor.h"

#include "exarmo/aarch64.h"

#include <algorithm>
#include <string>

using namespace BinaryNinja;
using namespace std;

namespace {
// exarmo_aarch64_sysregs is sorted by encoding. A register with separate read and write names has
// one entry per name, and the MRS name comes first.
const exarmo_aarch64_sysreg_def* ArchitecturalRegister(SystemRegister reg)
{
	if (reg.Value() >= SYSREG_END)
		return nullptr;

	auto found = std::lower_bound(std::begin(exarmo_aarch64_sysregs),
	    std::end(exarmo_aarch64_sysregs), (uint16_t)reg.Value(),
	    [](const exarmo_aarch64_sysreg_def& entry, uint16_t value) {
		    return entry.encoding < value;
	    });

	if (found == std::end(exarmo_aarch64_sysregs) || found->encoding != reg.Value())
		return nullptr;

	return found;
}
}


string_view SystemRegisterName(SystemRegister reg)
{
	if (const exarmo_aarch64_sysreg_def* architectural = ArchitecturalRegister(reg))
		return string_view(architectural->name.data, architectural->name.length);

	return AppleVendorSystemRegisterName(reg.Value());
}


const vector<SystemRegister>& SystemRegisters()
{
	static vector<SystemRegister> registers = [] {
		vector<SystemRegister> all;
		for (const exarmo_aarch64_sysreg_def& def : exarmo_aarch64_sysregs)
		{
			// Skip the second entry of a register with separate read and write names.
			if (all.empty() || all.back() != SystemRegister(def.encoding))
				all.push_back(SystemRegister(def.encoding));
		}

		vector<uint32_t> vendor;
		AppleVendorGetSystemRegisters(vendor);
		for (uint32_t reg : vendor)
			all.push_back(SystemRegister(reg));

		return all;
	}();

	return registers;
}


Ref<Enumeration> SystemRegisterEnumeration()
{
	static Ref<Enumeration> registers = [] {
		EnumerationBuilder builder;
		// Add both names of a register with separate read and write names, so that either one
		// resolves.
		for (const exarmo_aarch64_sysreg_def& def : exarmo_aarch64_sysregs)
			builder.AddMemberWithValue(string(def.name.data, def.name.length), def.encoding);

		vector<uint32_t> vendor;
		AppleVendorGetSystemRegisters(vendor);
		for (uint32_t reg : vendor)
			builder.AddMemberWithValue(string(AppleVendorSystemRegisterName(reg)), reg);

		return builder.Finalize();
	}();

	return registers;
}
