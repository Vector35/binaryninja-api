#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>
#include <functional>
#include <vector>
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


static Ref<CustomStringType> g_encodedStringType;


class EncodedStringRecognizer : public StringRecognizer
{
	typedef function<uint8_t(uint8_t, uint8_t)> Decoder;
	map<string, Decoder> m_decoders;

public:
	EncodedStringRecognizer() : StringRecognizer("encoded_strings")
	{
		// Initialize decoders
		m_decoders["xor_encoded"] = [](uint8_t encoded, uint8_t key) -> uint8_t {
			return encoded ^ key;
		};
		m_decoders["sub_encoded"] = [](uint8_t encoded, uint8_t key) -> uint8_t {
			return encoded - key;
		};
		m_decoders["add_encoded"] = [](uint8_t encoded, uint8_t key) -> uint8_t {
			return encoded + key;
		};
	}

	bool IsValidForType(HighLevelILFunction*, Type* type) override
	{
		if (!type || type->GetClass() != PointerTypeClass)
			return false;

		auto target = type->GetChildType();
		if (!target.GetValue())
			return false;

		// Check if any decoder attribute exists
		for (const auto& decoder : m_decoders)
		{
			if (target->GetAttribute(decoder.first).has_value())
				return true;
		}

		return false;
	}

	optional<DerivedString> RecognizeConstantPointer(
		const HighLevelILInstruction& instr, Type* type, int64_t val) override
	{
		if (!type || type->GetClass() != PointerTypeClass)
			return std::nullopt;

		auto target = type->GetChildType();
		if (!target)
			return std::nullopt;

		// Find the decoder and values
		vector<uint8_t> values;
		Decoder chosenDecoder;

		for (const auto& [name, decoder] : m_decoders)
		{
			if (auto attr = target->GetAttribute(name); attr.has_value())
			{
				// Parse hex string
				if (attr->length() % 2 != 0)
					return std::nullopt;

				for (size_t i = 0; i < attr->length(); i += 2)
				{
					string byteStr = attr->substr(i, 2);
					try
					{
						values.push_back((uint8_t)stoul(byteStr, nullptr, 16));
					}
					catch (...)
					{
						return std::nullopt;
					}
				}

				chosenDecoder = decoder;
				break;
			}
		}

		if (values.empty() || !chosenDecoder)
			return std::nullopt;

		bool encodedNull = target->GetAttribute("encoded_null").has_value();

		// Decode the string
		vector<uint8_t> resultBytes;
		size_t i = 0;
		Ref<BinaryView> view = instr.function->GetFunction()->GetView();

		while (true)
		{
			uint8_t byte;
			if (view->Read(&byte, val + i, 1) != 1)
				return std::nullopt;

			// Check for unencoded null terminator
			if (!encodedNull && byte == 0)
				break;

			// Decode the byte
			byte = chosenDecoder(byte, values[i % values.size()]);

			// Check for encoded null terminator
			if (byte == 0)
				break;

			resultBytes.push_back(byte);
			i++;
		}

		// Create the derived string
		DerivedStringLocation loc(DataBackedStringLocation, val, i);
		return DerivedString(string((char*)resultBytes.data(), resultBytes.size()), loc, g_encodedStringType);
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
		g_encodedStringType = CustomStringType::Register("Encoded", "", "_enc");
		StringRecognizer::Register(new EncodedStringRecognizer());
		return true;
	}
}
