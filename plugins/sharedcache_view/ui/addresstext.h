#pragma once

#include <cstdint>
#include <string>

// Renders an address the way the triage tables' Address columns display it: lowercase hex,
// zero-padded to `width` digits.
inline std::string AddressText(uint64_t address, uint32_t width)
{
	std::string text(width, '0');
	for (size_t i = text.size(); address != 0 && i > 0; address >>= 4)
		text[--i] = "0123456789abcdef"[address & 0xf];
	return text;
}
