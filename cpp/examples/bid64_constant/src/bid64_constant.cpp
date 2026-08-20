// This plugin renders 64-bit binary integer decimal floating point constants directly in the
// decompilation. See the sample binary at `cpp/examples/bid64_constant/sample_binary` for an
// example of a binary that uses this unusual format.

#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>
#include <functional>
#include <vector>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


static string Bid64ToString(bool sign, uint64_t magnitude, int exponent)
{
	if (magnitude == 0)
		exponent = 0;

	string digits = to_string(magnitude);
	int intPartDigits = digits.length() + exponent;

	int displayedExponent = 0;
	if (intPartDigits > 10 || intPartDigits < -4)
	{
		int newExponent = 1 - (int)digits.length();
		displayedExponent = exponent - newExponent;
		intPartDigits = digits.length() + newExponent;
	}

	string fracDigits;
	if (intPartDigits < 0)
		fracDigits = digits;
	else if (intPartDigits <= (int)digits.length())
		fracDigits = digits.substr(intPartDigits);

	int trailingZeros = 0;
	for (size_t i = 0; i < fracDigits.length(); i++)
	{
		if (fracDigits[(fracDigits.length() - 1) - i] != '0')
			break;
		trailingZeros++;
	}

	int nonzeroFracDigits = (int)fracDigits.length() - trailingZeros;
	fracDigits = fracDigits.substr(0, nonzeroFracDigits);

	string result;
	if (sign)
		result = "-";
	if (intPartDigits > 0)
	{
		for (size_t i = 0; i < intPartDigits; i++)
		{
			if (i >= digits.length())
				result += "0";
			else
				result += string(1, digits[i]);
		}
	}
	else
	{
		result += "0";
	}

	if (intPartDigits < 0 && fracDigits.length() > 0)
	{
		result += ".";
		for (size_t i = 0; i < -intPartDigits; i++)
			result += "0";
		result += fracDigits;
	}
	else if (fracDigits.length() > 0)
	{
		result += ".";
		result += fracDigits;
	}

	if (displayedExponent > 0)
		result += "E+" + to_string(displayedExponent);
	else if (displayedExponent < 0)
		result += "E" + to_string(displayedExponent);

	return result;
}


class Bid64ConstantRenderer : public ConstantRenderer
{
public:
	Bid64ConstantRenderer() : ConstantRenderer("bid64_constant")
	{
	}

	bool RenderConstant(const HighLevelILInstruction&, Type* type, int64_t val, HighLevelILTokenEmitter& tokens,
		DisassemblySettings* settings, BNOperatorPrecedence) override
	{
		// Typedefs have the final type, so make sure it is a 64 bit integer. The registered name
		// should be the typedef "BID_UINT64".
		if (!type || type->GetClass() != IntegerTypeClass)
			return false;
		if (type->GetWidth() != 8)
			return false;
		auto name = type->GetRegisteredName();
		if (!name || name->GetName().GetString() != "BID_UINT64")
			return false;

		// Get sign bit and raw exponent
		bool sign = (val & (1LL << 63)) != 0;
		int rawExponent = (int)((val >> 53) & 0x3ff);
		if (rawExponent >= 0x300)
		{
			// Don't try and render NaN or infinity
			return false;
		}

		// Get magnitude and actual exponent
		constexpr uint64_t BIAS = 398;
		int exponent = rawExponent - BIAS;
		uint64_t magnitude = val & ((1LL << 53) - 1);

		tokens.Append(FloatingPointToken, Bid64ToString(sign, magnitude, exponent) + "_bid");
		return true;
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		ConstantRenderer::Register(new Bid64ConstantRenderer());
		return true;
	}
}
