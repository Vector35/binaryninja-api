#include "cstyleformatstringresolutionprovider.h"

#include <cctype>

using namespace BinaryNinja;
using namespace std;

namespace
{
	enum class LengthModifier
	{
		None,
		HH,
		H,
		L,
		LL,
		J,
		Z,
		T,
		CapitalL
	};

	enum FormatFlag : uint8_t
	{
		LeftJustifyFlag = 1 << 0,
		ForceSignFlag = 1 << 1,
		SpaceSignFlag = 1 << 2,
		AlternateFormFlag = 1 << 3,
		ZeroPadFlag = 1 << 4
	};

	bool IsWindowsPlatform(Platform* platform)
	{
		return platform && (platform->GetName().find("windows") != string::npos);
	}

	bool IsApplePlatform(Platform* platform)
	{
		if (!platform)
			return false;
		const string name = platform->GetName();
		return name.starts_with("mac-") || name.starts_with("ios-") || name.starts_with("tvos-")
			|| name.starts_with("watchos-");
	}

	optional<size_t> GetAddressSize(Platform* platform)
	{
		if (!platform)
			return nullopt;
		auto arch = platform->GetArchitecture();
		if (!arch)
			return nullopt;
		return arch->GetAddressSize();
	}

	optional<size_t> GetPlatformTypeWidth(const string& name, Platform* platform)
	{
		auto addressSize = GetAddressSize(platform);
		if (!addressSize.has_value())
			return nullopt;

		if ((name == "long") || (name == "unsigned long"))
			return IsWindowsPlatform(platform) ? 4 : *addressSize;
		if ((name == "ssize_t") || (name == "size_t") || (name == "ptrdiff_t")
			|| (name == "unsigned ptrdiff_t"))
		{
			return *addressSize;
		}
		if (name == "wchar_t")
			return IsWindowsPlatform(platform) ? 2 : 4;
		if (name == "long double")
		{
			if (IsWindowsPlatform(platform) || IsApplePlatform(platform))
				return 8;
			return *addressSize == 4 ? 12 : 16;
		}
		return nullopt;
	}

	Confidence<Ref<Type>> IntegerArgument(
		size_t width, bool isSigned, uint8_t confidence = BN_FULL_CONFIDENCE,
		uint8_t signednessConfidence = BN_FULL_CONFIDENCE)
	{
		return Confidence<Ref<Type>>(
			Type::IntegerType(width, Confidence<bool>(isSigned, signednessConfidence)), confidence);
	}

	Confidence<Ref<Type>> PlatformIntegerArgument(
		Platform* platform, const string& name, bool isSigned, uint8_t confidence = BN_FULL_CONFIDENCE,
		uint8_t signednessConfidence = BN_FULL_CONFIDENCE)
	{
		auto width = GetPlatformTypeWidth(name, platform);
		if (!width.has_value())
			return nullptr;
		return Confidence<Ref<Type>>(
			Type::IntegerType(*width, Confidence<bool>(isSigned, signednessConfidence)), confidence);
	}

	Confidence<Ref<Type>> FloatArgument(size_t width, uint8_t confidence = BN_FULL_CONFIDENCE)
	{
		return Confidence<Ref<Type>>(Type::FloatType(width), confidence);
	}

	Confidence<Ref<Type>> PointerArgument(
		Platform* platform, const Confidence<Ref<Type>>& child,
		uint8_t confidence = BN_FULL_CONFIDENCE)
	{
		auto width = GetAddressSize(platform);
		if (!width.has_value() || !child.GetValue())
			return nullptr;
		return Confidence<Ref<Type>>(Type::PointerType(*width, child), confidence);
	}

	Confidence<Ref<Type>> SignedIntegerArgument(LengthModifier length, Platform* platform)
	{
		switch (length)
		{
		case LengthModifier::None:
		case LengthModifier::HH:
		case LengthModifier::H:
			// Signed char and signed short always promote to int.
			return IntegerArgument(4, true);
		case LengthModifier::L:
			return PlatformIntegerArgument(platform, "long", true);
		case LengthModifier::LL:
		case LengthModifier::J:
			return IntegerArgument(8, true);
		case LengthModifier::Z:
			return PlatformIntegerArgument(platform, "ssize_t", true);
		case LengthModifier::T:
			return PlatformIntegerArgument(platform, "ptrdiff_t", true);
		default:
			return nullptr;
		}
	}

	Confidence<Ref<Type>> UnsignedIntegerArgument(LengthModifier length, Platform* platform)
	{
		switch (length)
		{
		case LengthModifier::None:
			return IntegerArgument(4, false);
		case LengthModifier::HH:
		case LengthModifier::H:
			// The promotion is int when it can represent every value, and unsigned int otherwise.
			return IntegerArgument(4, true, BN_HEURISTIC_CONFIDENCE, 0);
		case LengthModifier::L:
			return PlatformIntegerArgument(platform, "unsigned long", false);
		case LengthModifier::LL:
		case LengthModifier::J:
			return IntegerArgument(8, false);
		case LengthModifier::Z:
			return PlatformIntegerArgument(platform, "size_t", false);
		case LengthModifier::T:
			return PlatformIntegerArgument(platform, "unsigned ptrdiff_t", false);
		default:
			return nullptr;
		}
	}

	Confidence<Ref<Type>> CountPointerArgument(LengthModifier length, Platform* platform)
	{
		Confidence<Ref<Type>> child;
		switch (length)
		{
		case LengthModifier::None:
			child = IntegerArgument(4, true);
			break;
		case LengthModifier::HH:
			child = IntegerArgument(1, true);
			break;
		case LengthModifier::H:
			child = IntegerArgument(2, true);
			break;
		case LengthModifier::L:
			child = PlatformIntegerArgument(platform, "long", true);
			break;
		case LengthModifier::LL:
		case LengthModifier::J:
			child = IntegerArgument(8, true);
			break;
		case LengthModifier::Z:
			child = PlatformIntegerArgument(platform, "ssize_t", true);
			break;
		case LengthModifier::T:
			child = PlatformIntegerArgument(platform, "ptrdiff_t", true);
			break;
		default:
			return nullptr;
		}
		return PointerArgument(platform, child);
	}

	Confidence<Ref<Type>> LongDoubleArgument(Platform* platform)
	{
		auto width = GetPlatformTypeWidth("long double", platform);
		if (!width.has_value())
			return nullptr;
		return FloatArgument(*width);
	}

	bool AppendArgument(
		vector<Confidence<Ref<Type>>>& result, const Confidence<Ref<Type>>& argument)
	{
		if (!argument.GetValue())
			return false;
		result.push_back(argument);
		return true;
	}

	bool ValidateFlags(char conversion, uint8_t flags)
	{
		const uint8_t signFlags = ForceSignFlag | SpaceSignFlag;
		switch (conversion)
		{
		case 'd':
		case 'i':
			return (flags & AlternateFormFlag) == 0;
		case 'o':
		case 'x':
		case 'X':
			return (flags & signFlags) == 0;
		case 'u':
			return (flags & (signFlags | AlternateFormFlag)) == 0;
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
			return true;
		case 'c':
		case 's':
		case 'p':
			return (flags & ~LeftJustifyFlag) == 0;
		case 'n':
		case '%':
			return flags == 0;
		default:
			return false;
		}
	}

	bool ValidateLength(char conversion, LengthModifier length)
	{
		switch (conversion)
		{
		case 'd':
		case 'i':
		case 'o':
		case 'u':
		case 'x':
		case 'X':
		case 'n':
			return length != LengthModifier::CapitalL;
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
			return (length == LengthModifier::None) || (length == LengthModifier::L)
				|| (length == LengthModifier::CapitalL);
		case 'c':
		case 's':
			return (length == LengthModifier::None) || (length == LengthModifier::L);
		case 'p':
		case '%':
			return length == LengthModifier::None;
		default:
			return false;
		}
	}

	bool ValidateWidthAndPrecision(char conversion, bool widthSpecified, bool precisionSpecified)
	{
		if ((conversion == 'n') || (conversion == '%'))
			return !widthSpecified && !precisionSpecified;
		if ((conversion == 'c') || (conversion == 'p'))
			return !precisionSpecified;
		return true;
	}

	optional<vector<Confidence<Ref<Type>>>> ResolveCStyleFormatString(
		const string& format, Platform* platform)
	{
		vector<Confidence<Ref<Type>>> result;
		for (size_t i = 0; i < format.size(); i++)
		{
			if (format[i] != '%')
				continue;

			i++;
			if (i == format.size())
				return nullopt;

			uint8_t flags = 0;
			bool parsingFlags = true;
			while (parsingFlags && (i < format.size()))
			{
				switch (format[i])
				{
				case '-': flags |= LeftJustifyFlag; break;
				case '+': flags |= ForceSignFlag; break;
				case ' ': flags |= SpaceSignFlag; break;
				case '#': flags |= AlternateFormFlag; break;
				case '0': flags |= ZeroPadFlag; break;
				default: parsingFlags = false; continue;
				}
				i++;
			}

			bool widthSpecified = false;
			bool widthArgument = false;
			if ((i < format.size()) && (format[i] == '*'))
			{
				widthSpecified = true;
				widthArgument = true;
				i++;
			}
			else
			{
				size_t widthStart = i;
				while ((i < format.size()) && isdigit(static_cast<unsigned char>(format[i])))
					i++;
				widthSpecified = i != widthStart;
			}

			bool precisionSpecified = false;
			bool precisionArgument = false;
			if ((i < format.size()) && (format[i] == '.'))
			{
				precisionSpecified = true;
				i++;
				if ((i < format.size()) && (format[i] == '*'))
				{
					precisionArgument = true;
					i++;
				}
				else
				{
					while ((i < format.size()) && isdigit(static_cast<unsigned char>(format[i])))
						i++;
				}
			}

			LengthModifier length = LengthModifier::None;
			if ((i + 1 < format.size()) && (format[i] == 'h') && (format[i + 1] == 'h'))
			{
				length = LengthModifier::HH;
				i += 2;
			}
			else if ((i + 1 < format.size()) && (format[i] == 'l') && (format[i + 1] == 'l'))
			{
				length = LengthModifier::LL;
				i += 2;
			}
			else if (i < format.size())
			{
				switch (format[i])
				{
				case 'h': length = LengthModifier::H; i++; break;
				case 'l': length = LengthModifier::L; i++; break;
				case 'j': length = LengthModifier::J; i++; break;
				case 'z': length = LengthModifier::Z; i++; break;
				case 't': length = LengthModifier::T; i++; break;
				case 'L': length = LengthModifier::CapitalL; i++; break;
				default: break;
				}
			}

			if (i == format.size())
				return nullopt;
			char conversion = format[i];
			if (!ValidateFlags(conversion, flags) || !ValidateLength(conversion, length)
				|| !ValidateWidthAndPrecision(conversion, widthSpecified, precisionSpecified))
			{
				return nullopt;
			}

			if (widthArgument)
				result.push_back(IntegerArgument(4, true));
			if (precisionArgument)
				result.push_back(IntegerArgument(4, true));

			switch (conversion)
			{
			case 'd':
			case 'i':
				if (!AppendArgument(result, SignedIntegerArgument(length, platform)))
					return nullopt;
				break;
			case 'o':
			case 'u':
			case 'x':
			case 'X':
				if (!AppendArgument(result, UnsignedIntegerArgument(length, platform)))
					return nullopt;
				break;
			case 'f':
			case 'F':
			case 'e':
			case 'E':
			case 'g':
			case 'G':
			case 'a':
			case 'A':
				if (!AppendArgument(result, length == LengthModifier::CapitalL
					? LongDoubleArgument(platform) : FloatArgument(8)))
				{
					return nullopt;
				}
				break;
			case 'c':
				if (length == LengthModifier::L)
				{
					if (!AppendArgument(
						result, IntegerArgument(4, true, BN_HEURISTIC_CONFIDENCE, 0)))
					{
						return nullopt;
					}
				}
				else
				{
					if (!AppendArgument(result, IntegerArgument(4, true)))
						return nullopt;
				}
				break;
			case 's':
				if (length == LengthModifier::L)
				{
					auto width = GetPlatformTypeWidth("wchar_t", platform);
					if (!width.has_value() || !AppendArgument(result, PointerArgument(platform,
						Confidence<Ref<Type>>(
							Type::WideCharType(*width, "wchar_t"), BN_FULL_CONFIDENCE))))
					{
						return nullopt;
					}
				}
				else
				{
					if (!AppendArgument(result, PointerArgument(platform, Confidence<Ref<Type>>(
						Type::IntegerType(1, Confidence<bool>(true, 0), "char"), BN_FULL_CONFIDENCE))))
					{
						return nullopt;
					}
				}
				break;
			case 'p':
				if (!AppendArgument(result, PointerArgument(platform,
					Confidence<Ref<Type>>(Type::VoidType(), BN_FULL_CONFIDENCE))))
				{
					return nullopt;
				}
				break;
			case 'n':
				if (!AppendArgument(result, CountPointerArgument(length, platform)))
					return nullopt;
				break;
			case '%':
				break;
			default:
				return nullopt;
			}
		}
		return result;
	}
}


CStyleFormatStringResolutionProvider::CStyleFormatStringResolutionProvider() :
	FormatStringResolutionProvider("CStyleFormatString")
{}


optional<vector<Confidence<Ref<Type>>>> CStyleFormatStringResolutionProvider::IsValid(
	const string& format, Platform* platform)
{
	return ResolveCStyleFormatString(format, platform);
}


void BinaryNinja::RegisterCStyleFormatStringResolutionProvider()
{
	static bool registered = []() {
		if (!FormatStringResolutionProvider::GetByName("CStyleFormatString"))
		{
			Ref<CStyleFormatStringResolutionProvider> provider = new CStyleFormatStringResolutionProvider();
			FormatStringResolutionProvider::Register(provider);
		}
		return true;
	}();
	(void)registered;
}
